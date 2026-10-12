import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {WebSocket} from 'ws';
import {createWireChat} from '../server.js';
import {testStore} from './store.js';

test('Email uniqueness, password confirmation, atomic Auth sync, session revocation and owner persistence',async()=>{
 const {pg,store,users}=await testStore();const config={origins:['http://localhost:8080'],ownerPassword:'test-owner-password'};const app=createWireChat(config,{store});await app.initialize();app.server.listen(0,'127.0.0.1');await once(app.server,'listening');
 const base='http://127.0.0.1:'+app.server.address().port;
 const call=async(path,method='GET',body,token)=>{const r=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});return {status:r.status,data:await r.json()};};
 const login=async(name,password='long-password-1')=>(await call('/login','POST',{username:name,password})).data.access_token;
 try{
  for(const name of ['alice','bob'])assert.equal((await call('/register','POST',{username:name,email:name+'@example.com',password:'long-password-1'})).status,201);
  assert.equal((await call('/register','POST',{username:'ALICE',email:'different@example.com',password:'long-password-1'})).status,409);
  assert.equal((await call('/register','POST',{username:'other',email:' ALICE@EXAMPLE.COM ',password:'long-password-1'})).status,409);
  let alice=await login('alice'),bob=await login('bob');const id=(await call('/me','GET',null,alice)).data.id;
  assert.equal((await call('/me/preferences','PUT',{theme:'light',enter:false,sound:false},alice)).status,200);
  const ownerToken=await login('Rohan','test-owner-password');assert.equal((await call('/owner/users/alice/badge','POST',{verified:true},ownerToken)).status,200);
  assert.equal((await call('/messages','POST',{to:'bob',content:'Persist across restart',clientId:'persist-1'},alice)).status,200);
  const restarted=createWireChat({...config},{store});await restarted.initialize();restarted.server.listen(0,'127.0.0.1');await once(restarted.server,'listening');
  try{const response=await fetch('http://127.0.0.1:'+restarted.server.address().port+'/me',{headers:{Authorization:'Bearer '+alice}});const saved=await response.json();assert.equal(response.status,200);assert.equal(saved.badge,'verified');assert.deepEqual(saved.preferences,{theme:'light',enter:false,sound:false});const history=await fetch('http://127.0.0.1:'+restarted.server.address().port+'/messages/bob',{headers:{Authorization:'Bearer '+alice}});assert((await history.json()).messages.some(m=>m.content==='Persist across restart'));}finally{restarted.wss.close();await new Promise(r=>restarted.server.close(r));}
  assert.equal((await call('/users/alice/profile','GET',null,bob)).data.email,undefined);
  assert.equal((await call('/me/email','PUT',{email:'new@example.com',password:'bad-password'},alice)).status,401);
  assert.equal((await call('/me/email','PUT',{email:'BOB@example.com',password:'long-password-1'},alice)).status,409);
  const ws=new WebSocket(base.replace('http:','ws:')+'/ws',{origin:config.origins[0]});await once(ws,'open');const events=[];ws.on('message',v=>events.push(JSON.parse(v)));ws.send(JSON.stringify({token:alice}));await new Promise(r=>setTimeout(r,40));
  assert.equal((await call('/me/email','PUT',{email:' NEW@EXAMPLE.COM ',password:'long-password-1'},alice)).status,200);
  await new Promise(r=>setTimeout(r,40));assert(events.some(v=>v.type==='session_replaced'));ws.terminate();
  assert.equal((await call('/me','GET',null,alice)).status,401);alice=await login('alice');const me=(await call('/me','GET',null,alice)).data;assert.equal(me.id,id);assert.equal(me.email,'new@example.com');assert.equal(users.get(id).email,me.email);
  await assert.rejects(pg.query('update auth.users set email=$1 where id=$2',['bob@example.com',id]));assert.equal((await pg.query('select email from auth.users where id=$1',[id])).rows[0].email,'new@example.com');
  assert.equal((await call('/me','GET',null,alice)).status,200);
  assert.equal((await call('/password-reset/request','POST',{},alice)).status,404);assert.equal((await call('/password-reset/confirm','POST',{},alice)).status,404);assert.equal((await call('/config')).data.password_reset_enabled,undefined);
  let owner=await login('Rohan','test-owner-password');assert.equal((await call('/me/email','PUT',{email:'owner-new@example.com',password:'test-owner-password'},owner)).status,200);await app.initialize();owner=await login('Rohan','test-owner-password');assert.equal((await call('/me','GET',null,owner)).data.email,'owner-new@example.com');
  const changed=createWireChat({...config,ownerEmail:'configured@example.com'},{store});await changed.initialize();assert.equal((await pg.query("select email from public.wc_profiles where username='Rohan'")).rows[0].email,'configured@example.com');changed.wss.close();
 }finally{for(const ws of app.wss.clients)ws.terminate();app.wss.close();await new Promise(r=>app.server.close(r));await pg.close();}
});
