// No npm install required: this uses only Node's built-in modules.
import {readFile,writeFile} from 'node:fs/promises';
import {parseEnv} from 'node:util';
const env=parseEnv(await readFile(new URL('./.env',import.meta.url),'utf8'));
for(const key of ['BACKEND_URL','FRONTEND_URL']){
 const u=new URL(env[key]);
 if(!['https:','http:'].includes(u.protocol)||u.username||u.password||u.pathname!=='/'||u.search||u.hash||u.host.includes('YOUR-'))throw new Error('Fill '+key+' in backend/.env with your site origin.');
 if(u.protocol==='http:'&&!['localhost','127.0.0.1'].includes(u.hostname))throw new Error(key+' must use HTTPS.');
}
if(!/^[A-Za-z0-9_]{3,32}$/.test(env.OWNER_USERNAME||''))throw new Error('OWNER_USERNAME must be 3–32 letters, numbers or underscores.');
if(!env.OWNER_PASSWORD)throw new Error('Fill OWNER_PASSWORD in backend/.env.');
const publicConfig={backendUrl:new URL(env.BACKEND_URL).origin};
await writeFile(new URL('../frontend/config.js',import.meta.url),'// Generated from backend/.env. Only the public backend URL is included.\nwindow.WIRECHAT_CONFIG = '+JSON.stringify(publicConfig,null,2)+';\n');
const connect=new URL(publicConfig.backendUrl);const wsOrigin=publicConfig.backendUrl.replace(/^http/,'ws');
const csp="default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self' "+connect.origin+" "+wsOrigin+"; img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
// Existing inline theme styles require style-src unsafe-inline; scripts remain external.
const policy=csp.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'");
await writeFile(new URL('../frontend/_headers',import.meta.url),"/*\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n  Content-Security-Policy: "+policy+"\n");
console.log('Ready. Upload frontend/ to Netlify. Deploy backend/ on Render and upload backend/.env as a Secret File named .env.');
console.log('No password or database key was copied into the frontend.');
