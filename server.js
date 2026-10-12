import express from 'express';
import multer from 'multer';
import sharp from 'sharp';
sharp.cache(false);sharp.concurrency(1);
import {createServer} from 'node:http';
import {scryptSync} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {WebSocketServer,WebSocket} from 'ws';
import {OWNER_ID,FILE_LIMIT,PHOTO_LIMIT,STORAGE_LIMIT,ApiError,fail,hash,newToken,equal,username,email,password,message,makeLimiter,createStore} from './core.js';

export function createWireChat(config,{store}={}){
  config.ownerUsername=username(config.ownerUsername||'Rohan');
  if(!config.ownerPassword)throw new Error('OWNER_PASSWORD is required.');
  config.ownerEmail=email(config.ownerEmail||'owner@wirechat.invalid');
  const sb=store||createStore({url:config.supabaseUrl,key:config.serviceKey});
  const db=(name,options={})=>sb('/rest/v1/'+name,options);
  const rpc=(name,body)=>db('rpc/'+name,{method:'POST',body});
  const app=express(),server=createServer(app),limit=makeLimiter(),sockets=new Map();
  const wss=new WebSocketServer({noServer:true,maxPayload:8192,perMessageDeflate:false});
  app.disable('x-powered-by');app.set('trust proxy',config.trustProxy??false);
  const auth=async token=>{
    if(typeof token!=='string'||! /^[A-Za-z0-9_-]{43}$/.test(token))fail(401,'Please sign in again.');
    const rows=await db('wc_sessions',{params:{token_hash:'eq.'+hash(token),expires_at:'gt.'+new Date().toISOString(),select:'user_id,wc_profiles!inner(id,email,preferences,username,display_name,avatar_version,bio,badge,banned,created_at)',limit:1}});
    if(!rows.length)fail(401,'Your session expired. Please sign in again.');
    const p=rows[0].wc_profiles;if(p.banned)fail(403,'Account banned.');
    return {...p,is_owner:p.id===OWNER_ID,token};
  };
  const authenticate=async(req,res,next)=>{try{req.user=await auth(req.headers.authorization?.replace(/^Bearer /,''));next();}catch(e){next(e);}};
  const owner=(req,res,next)=>req.user.is_owner?next():next(new ApiError(403,'Owner access required.'));
  const peer=async name=>{
    username(name);const rows=await db('wc_profiles',{params:{username_key:'eq.'+name.toLowerCase(),select:'id,username,display_name,avatar_version,email,bio,badge,banned,created_at',limit:1}});
    if(!rows.length)fail(404,'User not found');return rows[0];
  };
  const emit=(uid,event)=>{for(const ws of sockets.get(uid)||[]){if(ws.readyState===WebSocket.OPEN){if(ws.bufferedAmount>1024*1024){ws.close(1013,'Reconnect');continue;}ws.send(JSON.stringify(event));}}};
  const online=()=>[...sockets.values()].map(set=>set.values().next().value?.username).filter(Boolean);
  const broadcastPresence=()=>{const event={type:'online_users',users:online()};for(const uid of sockets.keys())emit(uid,event);};
  const disconnect=(uid,event)=>{emit(uid,event);for(const ws of sockets.get(uid)||[])ws.close(4001);sockets.delete(uid);broadcastPresence();};
  const session=async p=>{
    const token=newToken();
    await db('wc_sessions',{method:'DELETE',params:{expires_at:'lt.'+new Date().toISOString()}});
    // Bound outstanding sessions per account; newest login still works normally.
    const old=await db('wc_sessions',{params:{user_id:'eq.'+p.id,select:'token_hash',order:'created_at.desc',offset:9}});
    for(const r of old)await db('wc_sessions',{method:'DELETE',params:{token_hash:'eq.'+r.token_hash}});
    await db('wc_sessions',{method:'POST',body:{token_hash:hash(token),user_id:p.id,expires_at:new Date(Date.now()+7*86400000).toISOString()}});
    return {access_token:token,username:p.username,is_owner:p.id===OWNER_ID};
  };
  app.use((req,res,next)=>{
    res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});
    const origin=req.headers.origin;
    if(origin&&!config.origins.includes(origin))return next(new ApiError(403,'Origin not allowed.'));
    if(origin)res.set({'Access-Control-Allow-Origin':origin,Vary:'Origin','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Allow-Methods':'GET, POST, PUT, DELETE, OPTIONS'});
    if(req.method==='OPTIONS')return res.sendStatus(204);
    try{limit('ip:'+req.ip,240);next();}catch(e){next(e);}
  });
  app.use(express.json({limit:'16kb',strict:true}));
  app.get('/health',(req,res)=>res.json({status:'ok'}));
  app.get('/config',(req,res)=>res.json({file_sharing_enabled:false,photo_limit:PHOTO_LIMIT,storage_limit:STORAGE_LIMIT}));
  app.post('/register',async(req,res)=>{
    limit('register:'+req.ip,5,3600000);const d=req.body||{};
    const name=username(d.username?.trim()),mail=email(d.email),pass=password(d.password);
    if(name.toLowerCase()===config.ownerUsername.toLowerCase())fail(409,'Username unavailable.');
    const existing=await db('wc_profiles',{params:{username_key:'eq.'+name.toLowerCase(),select:'id'}});
    if(existing.length)fail(409,'Username unavailable.');
    if((await db('wc_profiles',{params:{email_key:'eq.'+mail,select:'id'}})).length)fail(409,'Email already in use.');
    // SMTP is optional: basic signup does not promise email ownership verification.
    const u=await sb('/auth/v1/admin/users',{method:'POST',body:{email:mail,password:pass,email_confirm:true}});
    const uid=u.id||u.user.id;
    try{await db('wc_profiles',{method:'POST',body:{id:uid,username:name,email:mail}});}
    catch(e){await sb('/auth/v1/admin/users/'+uid,{method:'DELETE'}).catch(()=>{});throw e;}
    res.status(201).json({ok:true});
  });
  app.post('/login',async(req,res)=>{
    const d=req.body||{},name=String(d.username||'').trim(),pass=String(d.password||'');
    limit('login-ip:'+req.ip,15,900000);limit('login-user:'+name.toLowerCase(),15,900000);
    let p;
    if(name.toLowerCase()===config.ownerUsername.toLowerCase()){
      if(!equal(pass,config.ownerPassword))fail(401,'Invalid username or password.');p=await peer(config.ownerUsername);
    }else{
      try{p=await peer(name);await sb('/auth/v1/token?grant_type=password',{method:'POST',body:{email:p.email,password:pass}});}
      catch{fail(401,'Invalid username or password.');}
    }
    if(p.banned)fail(403,'Account banned.');res.json(await session(p));
  });
  app.use(authenticate);
  app.post('/logout',async(req,res)=>{
    await db('wc_sessions',{method:'DELETE',params:{user_id:'eq.'+req.user.id}});
    disconnect(req.user.id,{type:'session_replaced',message:'Signed out.'});res.json({ok:true});
  });
  app.get('/me',async(req,res)=>{
    const {token,...p}=req.user;res.json({...p,storage_bytes:await rpc('wc_usage',{p_user:p.id}),storage_limit:STORAGE_LIMIT});
  });
  const emailChanges=new Set();
  app.put('/me/email',async(req,res)=>{
    limit('email:'+req.user.id,5,900000);limit('email-ip:'+req.ip,10,900000);
    const mail=email(req.body?.email),pass=String(req.body?.password||'');
    if(emailChanges.has(req.user.id))fail(409,'Email change already in progress.');
    emailChanges.add(req.user.id);
    try{
      if(req.user.is_owner){if(!equal(pass,config.ownerPassword))fail(401,'Incorrect current password.');}
      else{let verified;try{verified=await sb('/auth/v1/token?grant_type=password',{method:'POST',body:{email:req.user.email,password:pass}});}catch{fail(401,'Incorrect current password.');}
        if(verified.user?.id!==req.user.id)fail(401,'Incorrect current password.');
        if(verified.access_token)await sb('/auth/v1/logout?scope=local',{method:'POST',bearer:verified.access_token}).catch(()=>{});
      }
      if(mail===req.user.email)fail(400,'Enter a different email.');
      if((await db('wc_profiles',{params:{email_key:'eq.'+mail,select:'id'}})).length)fail(409,'Email already in use.');
      if(req.user.is_owner)await db('wc_profiles',{method:'PATCH',params:{id:'eq.'+req.user.id},body:{email:mail}});
      else await sb('/auth/v1/admin/users/'+req.user.id,{method:'PUT',body:{email:mail,email_confirm:true}});
      disconnect(req.user.id,{type:'session_replaced',message:'Email updated. Please sign in again.'});res.json({ok:true});
    }finally{emailChanges.delete(req.user.id);}
  });
  app.put('/me/preferences',async(req,res)=>{
    const d=req.body||{};if(!['dark','light','system'].includes(d.theme)||typeof d.enter!=='boolean'||typeof d.sound!=='boolean')fail(400,'Invalid preferences.');
    const preferences={theme:d.theme,enter:d.enter,sound:d.sound};await db('wc_profiles',{method:'PATCH',params:{id:'eq.'+req.user.id},body:{preferences}});res.json({preferences});
  });
  app.put('/me/bio',async(req,res)=>{
    const bio=String(req.body?.bio||'').trim();if(bio.length>1000||bio.split(/\s+/).filter(Boolean).length>100)fail(400,'Bio limit: 100 words / 1000 characters.');
    await rpc('wc_profile_update',{p_user:req.user.id,p_display:req.user.display_name||'',p_bio:bio});res.json({bio});
  });
  app.get('/users',async(req,res)=>{
    const q=String(req.query.q||'').replace(/[^A-Za-z0-9_]/g,'').slice(0,32).replaceAll('_','\\_');
    const users=await db('wc_profiles',{params:{select:'username,display_name,avatar_version,bio,badge,banned,created_at',username:'ilike.*'+q+'*',id:'neq.'+req.user.id,banned:'eq.false',limit:100,order:'username'}});res.json({users});
  });
  app.get('/users/:name/profile',async(req,res)=>{const p=await peer(req.params.name);const blocks=await db('wc_blocks',{params:{user_id:'eq.'+req.user.id,blocked_id:'eq.'+p.id,select:'blocked_id'}});res.json({blocked:blocks.length>0,username:p.username,display_name:p.display_name,avatar_version:p.avatar_version,bio:p.bio,badge:p.badge,banned:p.banned});});
  app.put('/users/:name/block',async(req,res)=>{
    const p=await peer(req.params.name);if(p.id===req.user.id)fail(400,'You cannot block yourself.');
    await rpc('wc_block_set',{p_user:req.user.id,p_blocked:p.id,p_block:req.body?.blocked===true});res.json({ok:true});
  });
  app.get('/messages/:name' ,async(req,res)=>{
    const p=await peer(req.params.name),before=String(req.query.before_id||'9223372036854775807');
    if(! /^\d{1,19}$/.test(before)||BigInt(before)>9223372036854775807n)fail(400,'Invalid message cursor.');
    const messages=await rpc('wc_history',{p_user:req.user.id,p_peer:p.id,p_before:before,p_limit:Math.min(100,Math.max(1,Number(req.query.limit)||30))});
    res.json({messages:messages.reverse()});
  });
  app.get('/conversations',async(req,res)=>res.json({conversations:await rpc('wc_conversations',{p_user:req.user.id})}));
  app.delete('/messages/:name',async(req,res)=>{
    const p=await peer(req.params.name);await rpc('wc_clear',{p_user:req.user.id,p_peer:p.id});
    emit(req.user.id,{type:'cleared',peer:p.username});res.json({ok:true});
  });
  const send=async(p,d,file)=>{
    limit('send:'+p.id,60);const valid=message(d,file),other=await peer(d.to);limit('incoming:'+other.id,120);
    const id=await rpc('wc_send',{p_sender:p.id,p_recipient:other.id,p_client:d.clientId,p_content:d.content,p_filename:valid.filename,p_hex:file?file.buffer.toString('hex'):null});
    const out=await rpc('wc_message',{p_id:id});
    emit(p.id,out);emit(other.id,out);
    emit(p.id,{type:'storage_changed'});emit(other.id,{type:'storage_changed'});return out;
  };
  app.post('/messages',async(req,res)=>res.json(await send(req.user,req.body||{})));
  // General file sharing is intentionally disabled, including old clients.
  app.all(['/files','/files/:id'],(req,res)=>res.status(410).json({detail:'File sharing is disabled.'}));
  app.get('/me/storage',async(req,res)=>res.json(await rpc('wc_storage',{p_user:req.user.id})));
  app.delete('/me/chats',async(req,res)=>{
    await rpc('wc_clear_all',{p_user:req.user.id});emit(req.user.id,{type:'storage_changed'});res.json({ok:true});
  });
  app.put('/me/profile',async(req,res)=>{
    const display=String(req.body?.display_name||'').trim(),bio=String(req.body?.bio||'').trim();
    if(display.length>50||bio.length>1000||bio.split(/\s+/).filter(Boolean).length>100)fail(400,'Name: 50 characters. Bio: 100 words / 1000 characters.');
    await rpc('wc_profile_update',{p_user:req.user.id,p_display:display,p_bio:bio});res.json({display_name:display,bio});
  });
  let photoUploads=0;
  const photoUpload=multer({storage:multer.memoryStorage(),limits:{fileSize:PHOTO_LIMIT,files:1,fields:0,parts:1}}).single('photo');
  app.put('/me/photo',(req,res,next)=>{
    try{limit('photo:'+req.user.id,10,3600000);if(photoUploads>=2)fail(503,'Photo uploads busy. Try again.');}catch(e){return next(e);}
    photoUploads++;let released=false;const release=()=>{if(!released){released=true;photoUploads--;}};
    req.releasePhoto=release;req.parsingPhoto=true;res.once('close',()=>{if(req.parsingPhoto)release();});photoUpload(req,res,err=>{req.parsingPhoto=false;if(err)release();next(err);});
  },async(req,res)=>{
    try{
    if(!req.file)fail(400,'Choose a JPEG, PNG or WebP photo.');
    const b=req.file.buffer;const isJpeg=b[0]===255&&b[1]===216&&b[2]===255;const isPng=b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));const isWebp=b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WEBP';
    if(!isJpeg&&!isPng&&!isWebp)fail(400,'Use a JPEG, PNG or WebP photo.');
    let data;
    try{
      const image=sharp(req.file.buffer,{limitInputPixels:16000000,failOn:'warning'});
      const info=await image.metadata();
      if(!['jpeg','png','webp'].includes(info.format)||(info.pages||1)>1)fail(400,'Use a still JPEG, PNG or WebP photo.');
      data=await image.rotate().resize(1024,1024,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).timeout({seconds:10}).toBuffer();
    }catch(e){if(e instanceof ApiError)throw e;fail(400,'Invalid photo. Use JPEG, PNG or WebP up to 5 MB and 16 megapixels.');}
    if(data.length>PHOTO_LIMIT)fail(413,'Photo exceeds 5 MB.');
    await rpc('wc_avatar_set',{p_user:req.user.id,p_hex:data.toString('hex')});
    emit(req.user.id,{type:'storage_changed'});res.json({ok:true,stored_bytes:data.length});
    }finally{req.releasePhoto();}
  });
  app.delete('/me/photo',async(req,res)=>{await rpc('wc_avatar_set',{p_user:req.user.id,p_hex:null});res.json({ok:true});});
  app.get('/users/:name/photo',async(req,res)=>{
    const p=await peer(req.params.name);if(p.banned)fail(404,'Photo unavailable.');
    const rows=await db('wc_avatars',{params:{user_id:'eq.'+p.id,select:'data',limit:1}});
    if(!rows.length)fail(404,'No profile photo.');
    res.type('image/webp').send(Buffer.from(rows[0].data.slice(2),'hex'));
  });
  app.get('/owner/users',owner,async(req,res)=>res.json({users:await db('wc_profiles',{params:{select:'username,display_name,avatar_version,bio,badge,banned,created_at',order:'created_at.desc',limit:1000}})}));
  app.post('/owner/users/:name/:action',owner,async(req,res)=>{
    const p=await peer(req.params.name);if(p.id===OWNER_ID)fail(403,'Owner cannot be modified.');
    let change;
    if(req.params.action==='badge')change={badge:req.body?.verified===true?'verified':null};
    else if(req.params.action==='ban')change={banned:req.body?.banned===true};else fail(404,'Unknown action.');
    await db('wc_profiles',{method:'PATCH',params:{id:'eq.'+p.id},body:change});
    if(change.banned){await db('wc_sessions',{method:'DELETE',params:{user_id:'eq.'+p.id}});disconnect(p.id,{type:'banned'});}
    res.json({ok:true});
  });
  const deleteUser=async p=>{
    if(p.id===OWNER_ID)fail(403,'Owner cannot be deleted.');
    // Auth deletion first: if it fails the account remains usable and retryable.
    await sb('/auth/v1/admin/users/'+p.id,{method:'DELETE'});
    await db('wc_profiles',{method:'DELETE',params:{id:'eq.'+p.id}});
    disconnect(p.id,{type:'account_deleted'});
  };
  app.delete('/owner/users/:name',owner,async(req,res)=>{await deleteUser(await peer(req.params.name));res.json({ok:true});});
  app.delete('/me',async(req,res)=>{await deleteUser(req.user);res.json({ok:true});});
  app.use((req,res)=>res.status(404).json({detail:'Not found.'}));
  app.use((err,req,res,next)=>{
    if(res.headersSent)return next(err);
    const status=err instanceof multer.MulterError?413:err.status||500;
    const detail=err instanceof multer.MulterError?'Upload one profile photo, maximum 5 MB.':status<500?err.message:'Service temporarily unavailable. Try again.';
    if(status>=500)console.error('Request failed:',err.name); // no secrets or request bodies
    res.status(status).json({detail});
  });
  server.on('upgrade',(req,socket,head)=>{
    try{limit('upgrade:'+req.socket.remoteAddress,40);if(req.url!=='/ws'||!config.origins.includes(req.headers.origin))throw new Error();
      wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req));
    }catch{socket.destroy();}
  });
  wss.on('connection',ws=>{
    let p,token,busy=false,last=Date.now();const timeout=setTimeout(()=>ws.close(4001),10000);
    ws.on('error',()=>{});
    ws.on('message',async raw=>{
      if(busy)return;busy=true;
      try{
        const d=JSON.parse(raw);last=Date.now();
        if(!p){token=d.token;p=await auth(token);if((sockets.get(p.id)?.size||0)>=5)fail(429,'Too many connections.');
          ws.username=p.username;if(!sockets.has(p.id))sockets.set(p.id,new Set());sockets.get(p.id).add(ws);clearTimeout(timeout);broadcastPresence();return;}
        limit('ws:'+p.id,120);p=await auth(token);
        if(d.type==='ping')ws.send(JSON.stringify({type:'pong'}));
        else if(d.type==='typing'){const other=await peer(d.to);const a=await db('wc_blocks',{params:{user_id:'eq.'+p.id,blocked_id:'eq.'+other.id,select:'blocked_id'}});const b=await db('wc_blocks',{params:{user_id:'eq.'+other.id,blocked_id:'eq.'+p.id,select:'blocked_id'}});if(!other.banned&&!a.length&&!b.length)emit(other.id,{type:'typing',from:p.username});}
      }catch(e){if(e.status===401||e.status===403)ws.close(4001);else if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'error',message:e instanceof ApiError?e.message:'Invalid request.'}));}
      finally{busy=false;}
    });
    const idle=setInterval(()=>{if(Date.now()-last>65000)ws.terminate();},30000);idle.unref();
    ws.on('close',()=>{clearTimeout(timeout);clearInterval(idle);if(p){sockets.get(p.id)?.delete(ws);if(!sockets.get(p.id)?.size)sockets.delete(p.id);broadcastPresence();}});
  });
  const initialize=async()=>{
    const fingerprint=scryptSync(config.ownerPassword,OWNER_ID+'|'+config.ownerUsername+'|'+config.ownerEmail,32).toString('hex');
    const rows=await db('wc_profiles',{params:{id:'eq.'+OWNER_ID,select:'id,owner_credential_hash,owner_email_config'}});
    const details={username:config.ownerUsername,owner_email_config:config.ownerEmail,badge:'verified',owner_credential_hash:fingerprint};
    if(!rows.length||rows[0].owner_email_config!==config.ownerEmail)details.email=config.ownerEmail;
    if(!rows.length)await db('wc_profiles',{method:'POST',body:{id:OWNER_ID,...details}});
    else {
      await db('wc_profiles',{method:'PATCH',params:{id:'eq.'+OWNER_ID},body:details});
      if(rows[0].owner_credential_hash!==fingerprint)await db('wc_sessions',{method:'DELETE',params:{user_id:'eq.'+OWNER_ID}});
    }
  };
  return {app,server,wss,initialize};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  // Render Secret Files are mounted here; dashboard env values take precedence.
  for(const file of ['/etc/secrets/.env','.env']){try{process.loadEnvFile(file);}catch(e){if(e.code!=='ENOENT')throw e;}}
  const config={supabaseUrl:process.env.SUPABASE_URL,serviceKey:process.env.SUPABASE_SERVICE_ROLE_KEY,ownerPassword:process.env.OWNER_PASSWORD,ownerUsername:process.env.OWNER_USERNAME,ownerEmail:process.env.OWNER_EMAIL,
    origins:(process.env.FRONTEND_URL||'http://localhost:8080').split(',').map(x=>x.trim().replace(/\/$/,'')),trustProxy:process.env.TRUST_PROXY==='1'?1:false};
  if(!config.supabaseUrl||!config.serviceKey||!config.ownerPassword)throw new Error('Set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, OWNER_PASSWORD. See .env.');
  const instance=createWireChat(config);await instance.initialize();
  instance.server.requestTimeout=30000;instance.server.headersTimeout=15000;
  instance.server.listen(Number(process.env.PORT)||8000,'0.0.0.0',()=>console.log('WireChat backend ready'));
  process.on('SIGTERM',()=>{for(const ws of instance.wss.clients)ws.close(1012,'Server restarting');instance.server.close(()=>process.exit(0));setTimeout(()=>process.exit(0),8000).unref();});
}
