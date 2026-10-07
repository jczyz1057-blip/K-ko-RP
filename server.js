const express=require('express'),{DatabaseSync}=require('node:sqlite'),bcrypt=require('bcryptjs'),crypto=require('crypto'),path=require('path');
const E=process.env,PORT=+E.PORT||3000,BASE=(E.BASE_URL||'http://localhost:'+PORT).replace(/\/$/,''),SEC=BASE.startsWith('https');
const IDS=(E.ADMIN_DISCORD_IDS||'').split(',').map(s=>s.trim()).filter(Boolean),NAMES=(E.ADMIN_USERNAMES||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
const db=new DatabaseSync(E.DB_FILE||path.join(__dirname,'data.db'));db.exec('PRAGMA journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE COLLATE NOCASE,pass TEXT,discord_id TEXT UNIQUE,discord_name TEXT,role TEXT DEFAULT 'user',created INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER,exp INTEGER);
CREATE TABLE IF NOT EXISTS apps(id INTEGER PRIMARY KEY,user_id INTEGER,nick TEXT,discord TEXT,age INTEGER,story TEXT,status TEXT DEFAULT 'pending',note TEXT,reviewer TEXT,created INTEGER,decided INTEGER);`);
const now=()=>Date.now(),q=(s,...a)=>db.prepare(s).run(...a),one=(s,...a)=>db.prepare(s).get(...a);
const isAdm=u=>IDS.includes(u.discord_id)||NAMES.includes((u.username||'').toLowerCase());
const sync=u=>{if(isAdm(u)&&u.role!=='admin'){q("UPDATE users SET role='admin' WHERE id=?",u.id);u.role='admin'}return u};
const pub=u=>({id:u.id,name:u.username||u.discord_name,discord:u.discord_name||'',role:u.role});
const getCookie=(r,n)=>{for(const p of(r.headers.cookie||'').split(/;\s*/)){const i=p.indexOf('=');if(p.slice(0,i)===n)return p.slice(i+1)}};
const setCookie=(res,n,v,age)=>res.append('Set-Cookie',`${n}=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${SEC?'; Secure':''}`);
const start=(res,u)=>{const t=crypto.randomBytes(32).toString('hex');q('INSERT INTO sessions VALUES(?,?,?)',t,u.id,now()+30*864e5);setCookie(res,'sid',t,2592000)};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'20kb'}));
app.use((req,res,next)=>{const t=getCookie(req,'sid');if(t){const u=one('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.exp>?',t,now());if(u)req.user=sync(u)}next()});
app.use('/api',(req,res,next)=>req.method==='GET'||req.is('json')?next():res.status(415).json({error:'Očekáván JSON.'}));
const hits=new Map(),limit=(req,res,next)=>{const h=hits.get(req.ip)||{n:0,t:now()};if(now()-h.t>6e5){h.n=0;h.t=now()}if(++h.n>15)return res.status(429).json({error:'Příliš mnoho pokusů, zkus to za chvíli.'});hits.set(req.ip,h);next()};
const need=(req,res,next)=>req.user?next():res.status(401).json({error:'Nejdřív se přihlas.'});
const adm=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Jen pro adminy.'});
const bad=(res,m,c=400)=>res.status(c).json({error:m});

app.post('/api/register',limit,(req,res)=>{
  const n=String(req.body.username||''),p=req.body.password;
  if(!/^[\w.-]{3,24}$/.test(n))return bad(res,'Jméno: 3–24 znaků (písmena, čísla, . _ -).');
  if(typeof p!=='string'||p.length<8||p.length>100)return bad(res,'Heslo musí mít aspoň 8 znaků.');
  try{const id=q('INSERT INTO users(username,pass,created) VALUES(?,?,?)',n,bcrypt.hashSync(p,10),now()).lastInsertRowid;
    const u=sync(one('SELECT * FROM users WHERE id=?',id));start(res,u);res.json({user:pub(u)})}
  catch(e){bad(res,'Toto jméno je už obsazené.',409)}
});
app.post('/api/login',limit,(req,res)=>{
  const u=one('SELECT * FROM users WHERE username=?',String(req.body.username||'')),p=String(req.body.password||'');
  if(!u||!u.pass||!bcrypt.compareSync(p,u.pass))return bad(res,'Špatné jméno nebo heslo.',401);
  sync(u);start(res,u);res.json({user:pub(u)});
});
app.post('/api/logout',(req,res)=>{const t=getCookie(req,'sid');if(t)q('DELETE FROM sessions WHERE token=?',t);setCookie(res,'sid','',0);res.json({ok:1})});
app.get('/api/me',(req,res)=>res.json({user:req.user?pub(req.user):null}));

const fail=m=>'/?autherr='+encodeURIComponent(m)+'#/prihlaseni';
app.get('/auth/discord',(req,res)=>{
  if(!E.DISCORD_CLIENT_ID||!E.DISCORD_CLIENT_SECRET)return res.redirect(fail('Přihlášení přes Discord není na serveru nastavené.'));
  const s=crypto.randomBytes(16).toString('hex');setCookie(res,'ost',s,600);
  res.redirect('https://discord.com/oauth2/authorize?'+new URLSearchParams({client_id:E.DISCORD_CLIENT_ID,response_type:'code',scope:'identify',redirect_uri:BASE+'/auth/discord/callback',state:s}));
});
app.get('/auth/discord/callback',async(req,res)=>{
  try{
    if(!req.query.code||!req.query.state||req.query.state!==getCookie(req,'ost'))return res.redirect(fail('Přihlášení vypršelo, zkus to znovu.'));
    const tr=await fetch('https://discord.com/api/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:E.DISCORD_CLIENT_ID,client_secret:E.DISCORD_CLIENT_SECRET,grant_type:'authorization_code',code:String(req.query.code),redirect_uri:BASE+'/auth/discord/callback'})});
    const t=await tr.json();if(!t.access_token)throw 0;
    const me=await(await fetch('https://discord.com/api/users/@me',{headers:{Authorization:'Bearer '+t.access_token}})).json();if(!me.id)throw 0;
    const name=me.username;let u=one('SELECT * FROM users WHERE discord_id=?',me.id);
    if(u)q('UPDATE users SET discord_name=? WHERE id=?',name,u.id);
    else if(req.user&&!req.user.discord_id){q('UPDATE users SET discord_id=?,discord_name=? WHERE id=?',me.id,name,req.user.id);u=req.user}
    else u={id:q('INSERT INTO users(discord_id,discord_name,created) VALUES(?,?,?)',me.id,name,now()).lastInsertRowid};
    u=sync(one('SELECT * FROM users WHERE id=?',u.id));start(res,u);setCookie(res,'ost','',0);res.redirect('/#/prihlaska');
  }catch(e){res.redirect(fail('Přihlášení přes Discord se nepovedlo.'))}
});

app.post('/api/applications',need,(req,res)=>{
  const b=req.body,nick=String(b.nick||'').trim(),dc=String(b.discord||'').trim(),age=+b.age,story=String(b.story||'').trim();
  if(nick.length<3||nick.length>40||!/^[\w.#]{2,32}$/.test(dc)||!(age>=15&&age<=99)||story.length<80||story.length>4000)return bad(res,'Zkontroluj prosím údaje v přihlášce.');
  if(one("SELECT 1 FROM apps WHERE user_id=? AND status IN('pending','accepted')",req.user.id))return bad(res,'Už máš podanou přihlášku.',409);
  res.json({id:q('INSERT INTO apps(user_id,nick,discord,age,story,created) VALUES(?,?,?,?,?,?)',req.user.id,nick,dc,age,story,now()).lastInsertRowid});
});
app.get('/api/applications/mine',need,(req,res)=>res.json({item:one('SELECT id,status,note,created FROM apps WHERE user_id=? ORDER BY id DESC LIMIT 1',req.user.id)||null}));

app.get('/api/admin/applications',need,adm,(req,res)=>res.json({items:db.prepare("SELECT a.*,COALESCE(u.username,u.discord_name) AS account FROM apps a LEFT JOIN users u ON u.id=a.user_id ORDER BY (a.status='pending') DESC,a.id DESC").all()}));
app.post('/api/admin/applications/:id',need,adm,(req,res)=>{
  const s=req.body.status;if(!['pending','accepted','rejected'].includes(s))return bad(res,'Neplatný stav.');
  const r=q('UPDATE apps SET status=?,note=?,reviewer=?,decided=? WHERE id=?',s,String(req.body.note||'').slice(0,500),pub(req.user).name,now(),+req.params.id);
  r.changes?res.json({ok:1}):bad(res,'Přihláška neexistuje.',404);
});
app.get('/api/admin/users',need,adm,(req,res)=>res.json({items:db.prepare('SELECT id,username,discord_name,role,created FROM users ORDER BY id').all()}));
app.post('/api/admin/users/:id/role',need,adm,(req,res)=>{
  if(+req.params.id===req.user.id)return bad(res,'Sám sobě roli měnit nemůžeš.');
  if(!['admin','user'].includes(req.body.role))return bad(res,'Neplatná role.');
  q('UPDATE users SET role=? WHERE id=?',req.body.role,+req.params.id);res.json({ok:1});
});
/* ---- stav FiveM serveru ---- */
const FIVEM=(()=>{let u=(E.FIVEM_URL||'').trim().replace(/\/+$/,'');if(u&&!/^https?:\/\//i.test(u))u='http://'+u;return u})(),JOIN=(E.FIVEM_JOIN_CODE||'').trim();
const jget=async(u,ms=5000)=>{const r=await fetch(u,{signal:AbortSignal.timeout(ms),headers:{'User-Agent':'Mozilla/5.0 kacko-status'}});if(!r.ok){const e=new Error('http');e.code=r.status;throw e}return r.json()};
async function fetchStatus(){
  if(!FIVEM&&!JOIN)return{state:'unconfigured'};
  if(FIVEM){
    try{const[p,i]=await Promise.all([jget(FIVEM+'/players.json'),jget(FIVEM+'/info.json')]);
      return{state:'on',n:p.length,max:+(i.vars&&i.vars.sv_maxClients)||+E.FIVEM_MAX||64}}
    catch(e){console.warn('[status] FIVEM_URL selhalo ('+FIVEM+'):',e.cause&&e.cause.code||e.code||e.name||e.message);if(!JOIN)return{state:'off'}}
  }
  try{const d=(await jget('https://servers-frontend.fivem.net/api/servers/single/'+JOIN)).Data;
    if(d)return{state:'on',n:d.clients??(d.players||[]).length,max:+d.sv_maxclients||+E.FIVEM_MAX||64}}
  catch(e){console.warn('[status] cfx.re API selhalo:',e.code||e.name||e.message);return{state:e.code===404?'off':'unknown'}}
  return{state:'unknown'};
}
let cache={t:0,v:null};
app.get('/api/status',async(req,res)=>{
  if(!cache.v||now()-cache.t>15000)cache={t:now(),v:await fetchStatus().catch(()=>({state:'unknown'}))};
  res.json({...cache.v,join:JOIN});
});
app.use(express.static(path.join(__dirname,'public')));
setInterval(()=>q('DELETE FROM sessions WHERE exp<?',now()),36e5);
app.listen(PORT,()=>console.log('Běží na '+BASE+(FIVEM||JOIN?'':'  (POZOR: v .env chybí FIVEM_URL i FIVEM_JOIN_CODE)')));
