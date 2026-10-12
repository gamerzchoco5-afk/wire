import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {WebSocket} from 'ws';
import {createWireChat} from '../server.js';
import {testStore} from './store.js';
import {message,FILE_LIMIT,newToken,hash,createStore} from '../core.js';

test('Input and transport protections',async()=>{
 assert.throws(()=>message({to:'alice',clientId:'x',content:''}),/1–2000/);
 assert.throws(()=>message({to:'alice',clientId:'bad"',content:'a'}),/message ID/);
 assert.throws(()=>message({to:'alice',clientId:'x',content:''},{buffer:Buffer.alloc(FILE_LIMIT+1),originalname:'x'}),/File sharing is disabled/);
 assert.equal(newToken().length,43);assert.equal(hash('token').length,64);
 const s=createStore({url:'https://test.invalid',key:'server-secret',fetcher:async(url,options)=>{
  assert.equal(options.headers.apikey,'server-secret');assert.equal(url.searchParams.get('username_key'),'eq.a_b');
  return new Response(JSON.stringify([{id:'one'}]),{status:200});
 }});
 assert.deepEqual(await s('/rest/v1/wc_profiles',{params:{username_key:'eq.a_b'}}),[{id:'one'}]);
});

test('Postgres + HTTP + WebSocket integration',async t=>{
 const {pg,store}=await testStore();const config={origins:['http://localhost:8080'],ownerPassword:'test-owner-password'};const instance=createWireChat(config,{store});
 await instance.initialize();instance.server.listen(0,'127.0.0.1');await once(instance.server,'listening');
 const base='http://127.0.0.1:'+instance.server.address().port;
 const call=async(path,{method='GET',body,token,headers={}}={})=>{
  const r=await fetch(base+path,{method,headers:{...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{}),...headers},body:body?JSON.stringify(body):undefined});
  return {status:r.status,data:await r.json()};
 };
 let alice,bob,carol,owner,aliceId,bobId;
 try{
 await t.test('signup, login, reserved owner, invalid auth and CORS',async()=>{
  for(const name of ['alice','bob','carol'])assert.equal((await call('/register',{method:'POST',body:{username:name,email:name+'@example.com',password:'long-password-1'}})).status,201);
  assert.equal((await call('/register',{method:'POST',body:{username:'rOhAn',email:'thief@example.com',password:'long-password-1'}})).status,409);
  for(const name of ['alice','bob','carol']){const r=await call('/login',{method:'POST',body:{username:name,password:'long-password-1'}});assert.equal(r.status,200);if(name==='alice')alice=r.data.access_token;if(name==='bob')bob=r.data.access_token;if(name==='carol')carol=r.data.access_token;}
  owner=(await call('/login',{method:'POST',body:{username:'Rohan',password:'test-owner-password'}})).data.access_token;
  assert.equal((await call('/me')).status,401);assert.equal((await call('/me',{token:alice,headers:{Origin:'https://evil.invalid'}})).status,403);
  assert.equal((await call('/owner/users',{token:alice})).status,403);
  assert.equal((await call('/owner/users',{token:owner})).status,200);
  aliceId=(await call('/me',{token:alice})).data.id;bobId=(await call('/me',{token:bob})).data.id;
 });
 await t.test('live messages, history, idempotency, cross-recipient replay protection',async()=>{
  const ws=new WebSocket(base.replace('http:','ws:')+'/ws',{origin:'http://localhost:8080'});await once(ws,'open');
  const events=[];ws.on('message',x=>events.push(JSON.parse(x)));ws.send(JSON.stringify({type:'auth',token:bob}));
  await new Promise(resolve=>setTimeout(resolve,50));
  const sender=new WebSocket(base.replace('http:','ws:')+'/ws',{origin:'http://localhost:8080'});await once(sender,'open');sender.send(JSON.stringify({type:'auth',token:alice}));await new Promise(r=>setTimeout(r,40));sender.send(JSON.stringify({type:'typing',to:'bob'}));await new Promise(r=>setTimeout(r,40));assert(events.some(e=>e.type==='typing'&&e.from==='alice'));sender.close();
  const body={to:'bob',content:'Hello <script>alert(1)</script>',clientId:'hello-1'};
  const first=await call('/messages',{method:'POST',token:alice,body});assert.equal(first.status,200);
  const second=await call('/messages',{method:'POST',token:alice,body});assert.equal(second.data.id,first.data.id);
  await new Promise(resolve=>setTimeout(resolve,50));assert(events.some(e=>e.type==='message'&&e.content===body.content));
  assert.equal((await call('/messages/alice',{token:bob})).data.messages.length,1);
  assert.equal((await call('/messages/alice',{token:carol})).data.messages.length,0);
  const replay=await call('/messages',{method:'POST',token:alice,body:{...body,to:'carol'}});assert.notEqual(replay.status,200);
  assert.equal((await call('/conversations',{token:bob})).data.conversations[0].peer,'alice');ws.close();await once(ws,'close');
 });
 await t.test('file sharing disabled, validated private photos, profile settings and storage',async()=>{
  assert.equal((await call('/files',{method:'POST',token:alice})).status,410);
  const upload=async(buffer,type='image/png')=>{const form=new FormData();form.append('photo',new Blob([buffer],{type}),'photo.png');const r=await fetch(base+'/me/photo',{method:'PUT',headers:{Authorization:'Bearer '+alice},body:form});return {status:r.status,data:await r.json()};};
  assert.equal((await upload(Buffer.alloc(5242881))).status,413);
  assert.equal((await upload(Buffer.from('<svg onload="alert(1)"></svg>'))).status,400);
  assert.equal((await upload(Buffer.from('not an image'))).status,400);
  const {default:sharp}=await import('sharp');const photo=await sharp({create:{width:64,height:64,channels:3,background:'#123456'}}).png().toBuffer();
  const result=await upload(photo);assert.equal(result.status,200);
  assert.equal((await call('/users/alice/photo')).status,401);
  const pic=await fetch(base+'/users/alice/photo',{headers:{Authorization:'Bearer '+bob}});assert.equal(pic.status,200);assert.equal(pic.headers.get('content-type'),'image/webp');
  const picInfo=await sharp(Buffer.from(await pic.arrayBuffer())).metadata();assert.equal(picInfo.format,'webp');assert.equal(picInfo.exif,undefined);
  assert.equal((await call('/me/profile',{method:'PUT',token:alice,body:{display_name:'Alice <script>',bio:'Hello!'}})).status,200);
  assert.equal((await call('/me/profile',{method:'PUT',token:alice,body:{display_name:'a'.repeat(51)}})).status,400);
  const storage=(await call('/me/storage',{token:alice})).data;assert.equal(storage.limit_bytes,10485760);assert(storage.photo_bytes>0);assert(storage.profile_bytes>0);
  assert.equal((await call('/me/chats',{method:'DELETE',token:alice})).status,200);
  const cleared=(await call('/me/storage',{token:alice})).data;assert.equal(cleared.chat_bytes,0);assert.equal(cleared.photo_bytes,storage.photo_bytes);
  assert((await call('/me',{token:bob})).data.storage_bytes>0);
  await call('/messages/alice',{method:'DELETE',token:bob});
  assert.equal((await pg.query('select count(*)::int as n from wc_messages')).rows[0].n,0);
 });
 await t.test('automatic oldest-first pruning keeps current photo, latest message and other user copy',async()=>{
  // Seed enough real UTF-8 message bytes to cross 10 MiB with a 5 MiB avatar.
  await pg.query('select wc_avatar_set($1,$2)',[aliceId,Buffer.alloc(5242880,1).toString('hex')]);
  await pg.query(`insert into wc_messages(sender,recipient,client_id,content) select $1,$2,'bulk-'||g,repeat('x',2000) from generate_series(1,2600) g`,[aliceId,bobId]);
  await pg.query(`insert into wc_entries select $1,id,octet_length(content)+128 from wc_messages where client_id like 'bulk-%'`,[aliceId]);
  await pg.query(`insert into wc_entries select $1,id,octet_length(content)+128 from wc_messages where client_id like 'bulk-%'`,[bobId]);
  const sent=await call('/messages',{method:'POST',token:alice,body:{to:'bob',content:'Newest message survives',clientId:'newest'}});assert.equal(sent.status,200);
  const storage=(await call('/me/storage',{token:alice})).data;assert(storage.used_bytes<=10485760);assert.equal(storage.photo_bytes,5242880);
  const first=(await pg.query(`select min(m.client_id) as first from wc_entries e join wc_messages m on m.id=e.message_id where e.user_id=$1 and m.client_id='bulk-1'`,[aliceId])).rows[0].first;assert.equal(first,null);
  assert.equal((await pg.query(`select count(*)::int n from wc_entries e join wc_messages m on m.id=e.message_id where e.user_id=$1 and m.client_id='bulk-1'`,[bobId])).rows[0].n,1);
  assert((await call('/messages/bob',{token:alice})).data.messages.some(m=>m.content==='Newest message survives'));
  await assert.rejects(pg.query('select wc_send($1,$2,$3,$4,$5,$6)',[aliceId,bobId,'illegal-file','','bad.txt','ff']),/File sharing/);
  await call('/me/chats',{method:'DELETE',token:alice});assert.equal((await call('/me/storage',{token:alice})).data.photo_bytes,5242880);
  await call('/me/photo',{method:'DELETE',token:alice});assert.equal((await call('/me/storage',{token:alice})).data.photo_bytes,0);
 });
 await t.test('database RLS and RPC permissions block public callers',async()=>{
  await pg.exec('set role anon');
  await assert.rejects(pg.query('select * from public.wc_messages'),/permission denied/);
  await assert.rejects(pg.query('select * from public.wc_avatars'),/permission denied/);
  await assert.rejects(pg.query('select public.wc_avatar_set($1,null)',[aliceId]),/permission denied/);
  await assert.rejects(pg.query('select public.wc_usage($1)',[aliceId]),/permission denied/);
  await pg.exec('reset role');
 });
 await t.test('blocking, profile mass assignment, payload limits and malformed identities',async()=>{
  assert.equal((await call('/users/bob/block',{method:'PUT',token:alice,body:{blocked:true}})).status,200);
  assert.equal((await call('/users/bob/profile',{token:alice})).data.blocked,true);
  assert.notEqual((await call('/messages',{method:'POST',token:bob,body:{to:'alice',content:'blocked attempt',clientId:'block-test'}})).status,200);
  assert.equal((await call('/users/bob/block',{method:'PUT',token:alice,body:{blocked:false}})).status,200);
  assert.equal((await call('/messages',{method:'POST',token:bob,body:{to:'alice',content:'allowed again',clientId:'unblock-test'}})).status,200);
  await call('/me/profile',{method:'PUT',token:alice,body:{display_name:'Alice',bio:'',badge:'verified',is_owner:true,id:bobId}});
  const me=(await call('/me',{token:alice})).data;assert.equal(me.is_owner,false);assert.equal(me.badge,null);assert.equal(me.id,aliceId);
  assert.equal((await call('/messages',{method:'POST',token:alice,body:{to:'bob',content:'x'.repeat(20000),clientId:'oversized'}})).status,413);
  assert.equal((await call('/users/'+encodeURIComponent("bob' or 1=1")+'/profile',{token:alice})).status,400);
 });
 await t.test('removed recovery, admin ban and logout revoke sessions',async()=>{
  assert.equal((await call('/password-reset/request',{method:'POST',body:{email:'alice@example.com'},token:alice})).status,404);
  assert.equal((await call('/owner/users/bob/ban',{method:'POST',token:owner,body:{banned:true}})).status,200);
  assert.equal((await call('/me',{token:bob})).status,401);
  await call('/logout',{method:'POST',token:alice});assert.equal((await call('/me',{token:alice})).status,401);
 });
 await t.test('one configurable owner, blue tick only, credential changes revoke sessions',async()=>{
  config.ownerUsername='new_owner';config.ownerPassword='next-owner-password';await instance.initialize();
  assert.equal((await call('/me',{token:owner})).status,401);
  const login=await call('/login',{method:'POST',body:{username:'new_owner',password:'next-owner-password'}});
  assert.equal(login.status,200);assert.equal(login.data.is_owner,true);
  const me=await call('/me',{token:login.data.access_token});assert.equal(me.data.badge,'verified');assert.equal(me.data.username,'new_owner');
  assert.equal((await call('/owner/users',{token:login.data.access_token})).status,200);
 });
 }finally{for(const ws of instance.wss.clients)ws.terminate();await new Promise(resolve=>instance.server.close(resolve));await pg.close();}
});
