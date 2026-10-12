import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
export const OWNER_ID='00000000-0000-4000-8000-000000000001';
export const FILE_LIMIT=2*1024*1024; // Legacy constant; file endpoints are disabled.
export const PHOTO_LIMIT=5*1024*1024;
export const STORAGE_LIMIT=10*1024*1024;
export class ApiError extends Error {constructor(status,message){super(message);this.status=status;}}
export const fail=(status,msg)=>{throw new ApiError(status,msg);};
export const hash=t=>createHash('sha256').update(t).digest('hex');
export const newToken=()=>randomBytes(32).toString('base64url');
export function equal(a,b){return timingSafeEqual(createHash('sha256').update(String(a)).digest(),createHash('sha256').update(String(b)).digest());}
export function username(v){if(typeof v!=='string'||! /^[A-Za-z0-9_]{3,32}$/.test(v))fail(400,'Username: 3–32 letters, numbers or underscores.');return v;}
export function email(v){if(typeof v==='string')v=v.trim();if(typeof v!=='string'||v.length>254||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))fail(400,'Enter a valid email.');return v.trim().toLowerCase();}
export function password(v){if(typeof v!=='string'||v.length<8||v.length>72)fail(400,'Password must be 8–72 characters.');return v;}
export function message(d,file){
  if(file || d.filename || d.file || d.p_hex)fail(400,'File sharing is disabled.');
  username(d.to);
  if(typeof d.clientId!=='string'||! /^[A-Za-z0-9_-]{1,80}$/.test(d.clientId))fail(400,'Invalid message ID.');
  if(typeof d.content!=='string'||d.content.length>2000||(!file&&!d.content.trim()))fail(400,'Message must contain 1–2000 characters.');
  if(file&&file.buffer.length>FILE_LIMIT)fail(413,'Maximum file size is 2 MB.');
  return {...d,filename:file?file.originalname.replace(/[\x00-\x1f\x7f/\\]/g,'_').slice(0,180)||'file':null};
}
export function makeLimiter(){
  const store=new Map();
  return (key,count=90,window=60000)=>{
    const now=Date.now();let item=store.get(key);
    if(!item||item.until<=now){item={n:0,until:now+window};store.set(key,item);}
    if(++item.n>count)fail(429,'Too many attempts. Please try later.');
    if(store.size>10000)for(const [k,v] of store){if(v.until<=now)store.delete(k);}
    if(store.size>20000)fail(503,'Server busy. Please try later.');
  };
}
export function createStore({url,key,fetcher=fetch}){
  return async (path,{method='GET',body,params,bearer}={})=>{
    const endpoint=new URL(path,url);
    if(params)for(const [k,v]of Object.entries(params))endpoint.searchParams.set(k,String(v));
    let r;
    try{r=await fetcher(endpoint,{method,headers:{apikey:key,Authorization:`Bearer ${bearer||key}`,'Content-Type':'application/json',Prefer:'return=representation'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});}
    catch{fail(503,'Database temporarily unavailable. Try again.');}
    const data=await r.json().catch(()=>null);
    if(!r.ok){

      if(String(data?.message).includes('User unavailable'))fail(400,'User unavailable.');
      if(r.status===409)fail(409,'Username or email already in use.');
      fail(r.status>=500?503:400,'Request failed. Check your details or try again.');
    }
    return data;
  };
}
