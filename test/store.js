// Test-only Supabase transport backed by real PostgreSQL (PGlite), never used by server.js.
import {PGlite} from '@electric-sql/pglite';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {ApiError} from '../core.js';
export async function testStore(){
 const pg=new PGlite(),users=new Map();
 await pg.exec('create role anon;create role authenticated;create role service_role bypassrls;create schema auth;create table auth.users(id uuid primary key,email text unique);');
 await pg.exec(await readFile(new URL('../../database/setup.sql',import.meta.url),'utf8'));
 const store=async(path,{method='GET',body,params={}}={})=>{
  if(path.startsWith('/auth/')){
   if(path==='/auth/v1/admin/users'&&method==='POST'){
    if([...users.values()].some(x=>x.email===body.email))throw new ApiError(409,'Duplicate email');
    const id=randomUUID();await pg.query('insert into auth.users(id,email) values($1,$2)',[id,body.email]);users.set(id,{id,...body});return {id};
   }
   if(path.startsWith('/auth/v1/admin/users/')&&method==='DELETE'){users.delete(path.split('/').at(-1));return {};}
   if(path.startsWith('/auth/v1/logout'))return {};
   if(path.startsWith('/auth/v1/admin/users/')&&method==='PUT'){const id=path.split('/').at(-1);try{await pg.query('update auth.users set email=$1 where id=$2',[body.email,id]);}catch{throw new ApiError(409,'Email already in use.');}Object.assign(users.get(id),body);return users.get(id);}
   if(path.includes('/token')){const u=[...users.values()].find(x=>x.email===body.email&&x.password===body.password);if(!u)throw new ApiError(400,'Invalid');return {access_token:'test-auth-token',user:u};}
   throw new Error('Unhandled test auth '+path);
  }
  const table=path.replace('/rest/v1/','');
  if(table.startsWith('rpc/')){
   const fn=table.slice(4);if(!/^wc_[a-z_]+$/.test(fn))throw Error('Bad function');
   const args=Object.values(body||{});const result=await pg.query(`select * from public.${fn}(${args.map((_,i)=>'$'+(i+1)).join(',')})`,args);
   const rows=result.rows.map(r=>Object.values(r)[0]);
   return ['wc_history','wc_conversations'].includes(fn)?rows:rows[0];
  }
  if(!['wc_profiles','wc_messages','wc_entries','wc_sessions','wc_avatars','wc_blocks'].includes(table))throw Error('Unknown table');
  const values=[],where=[];
  for(const [k,v]of Object.entries(params)){
   if(['select','order','offset','limit'].includes(k))continue;
   if(!/^[a-z_]+$/.test(k))throw Error('Bad column');
   const dot=String(v).indexOf('.'),op=String(v).slice(0,dot),value=String(v).slice(dot+1);
   const ops={eq:'=',neq:'<>',gt:'>',lt:'<',ilike:'ilike'};if(!ops[op])throw Error('Bad operator');
   values.push(op==='ilike'?value.replaceAll('*','%'):value);where.push(`t.${k} ${ops[op]} $${values.length}`);
  }
  const filter=where.length?' where '+where.join(' and '):'';
  if(method==='GET'){
   const joined=table==='wc_sessions'&&params.select?.includes('wc_profiles!inner');
   const cols=joined?"t.user_id,row_to_json(p) as wc_profiles":params.select&&params.select!=='*'?params.select.split(',').map(x=>'t.'+x).join(','):'t.*';
   let tail='';if(params.order){const [col,dir]=params.order.split('.');tail+=` order by t.${col} ${dir==='desc'?'desc':'asc'}`;}
   tail+=` limit ${Number(params.limit)||1000} offset ${Number(params.offset)||0}`;
   return (await pg.query(`select ${cols} from public.${table} t ${joined?'join public.wc_profiles p on p.id=t.user_id':''}${filter}${tail}`,values)).rows.map(r=>{
    for(const key of ['file_data','data'])if(r[key] instanceof Uint8Array)r[key]='\\x'+Buffer.from(r[key]).toString('hex');return r;
   });
  }
  if(method==='POST'){
   const keys=Object.keys(body);return (await pg.query(`insert into public.${table} (${keys.join(',')}) values (${keys.map((_,i)=>'$'+(i+1)).join(',')}) returning *`,Object.values(body))).rows;
  }
  if(method==='PATCH'){
   const set=Object.entries(body).map(([k,v])=>{values.push(v);return `${k}=$${values.length}`;});
   return (await pg.query(`update public.${table} t set ${set.join(',')}${filter} returning *`,values)).rows;
  }
  if(method==='DELETE')return (await pg.query(`delete from public.${table} t${filter} returning *`,values)).rows;
  throw Error('Unsupported method');
 };
 return {pg,store,users};
}
