'use strict';
/* =================================================================
   Taskscope — user interface.
   Data comes from the Rust engine (Service::call). In the app — through Tauri,
   in development mode (`tm serve`) — through POST /rpc. Same logic either way.
   ================================================================= */

/* ----- utilities ----- */
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
const nf=(v,d=1)=>v.toFixed(d);
const MB=1048576;
const fmtMem=mb=>mb>=1024?nf(mb/1024,mb>=10240?1:2)+' GB':mb>=10?Math.round(mb)+' MB':nf(mb,1)+' MB';
const fmtPct=v=>v<0.05?'0 %':v<10?nf(v)+' %':Math.round(v)+' %';
const fmtMBs=v=>v<0.005?'0':v<0.1?Math.round(v*1024)+' KB/s':v<10?nf(v)+' MB/s':Math.round(v)+' MB/s';
const fmtMbit=v=>v<0.005?'0 Mbit/s':v<0.1?Math.round(v*1000)+' Kbit/s':v<10?nf(v)+' Mbit/s':Math.round(v)+' Mbit/s';
const hexA=(hex,a)=>{const n=parseInt(hex.slice(1),16);return `rgba(${n>>16},${n>>8&255},${n&255},${a})`;};
const agoStr=s=>s<60?Math.round(s)+' s':s<3600?Math.round(s/60)+' min':s<86400?Math.floor(s/3600)+' h '+Math.round(s%3600/60)+' min':Math.floor(s/86400)+' d '+Math.floor(s%86400/3600)+' h';
const CHEV='<svg width="10" height="10" viewBox="0 0 10 10"><path d="M3.5 1.5 7 5l-3.5 3.5" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICON_WARN='<svg width="16" height="16" viewBox="0 0 16 16"><path d="M8 1.8 15 14H1z" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M8 6.2v3.8M8 11.8v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
const ICON_INFO='<svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="6" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M7 6.2v3.6M7 4.2v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const ctToMs=ct=>(ct-116444736000000000)/10000;

/* ----- talking to the engine ----- */
const TAURI=window.__TAURI__;
/* window errors go to the log (%LOCALAPPDATA%\tm\logs): an app without a console has nowhere else to show them */
const LOGGED=new Map(); /* the same error from the render loop — once a minute */
function logUi(msg){msg=String(msg).slice(0,2000);const t=Date.now();if(t-(LOGGED.get(msg)||0)<60e3)return;LOGGED.set(msg,t);if(LOGGED.size>200)LOGGED.clear();try{rpc('log',{msg}).catch(()=>{});}catch(e){}}
addEventListener('error',e=>logUi(`${e.message} @ ${e.filename||''}:${e.lineno||0}:${e.colno||0}${e.error&&e.error.stack?'\n'+e.error.stack:''}`));
addEventListener('unhandledrejection',e=>{const r=e.reason;const m=String(r&&r.message||r);if(/Failed to fetch|NetworkError|no connection/i.test(m))return;logUi('promise: '+m+(r&&r.stack?'\n'+r.stack:''));});
async function rpc(method,params={}){
  if(TAURI)return TAURI.core.invoke('rpc',{method,params});
  const r=await fetch('/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,params})});
  const j=await r.json();if(j.error)throw new Error(j.error);return j.result;
}
async function appCmd(cmd,arg=null){
  if(!TAURI)throw new Error('only available in the app');
  return TAURI.core.invoke('app_cmd',{cmd,arg});
}

/* ----- palettes ----- */
const PAL=['#486de8','#e07f9d','#018977','#b088f5','#c55305','#8ea9ff','#ffb0c8','#40bfa9','#d6baff','#f89256'];
const OTHER='#5f6b7a';
const CATS={
  browser:{n:'Browsers',c:'#3f7fd9'},
  dev:{n:'Development',c:'#8456ce'},
  ai:{n:'AI tools',c:'#d9822b'},
  docker:{n:'Docker / WSL',c:'#1f9e89'},
  comm:{n:'Communication',c:'#c33d69'},
  media:{n:'Media and games',c:'#b8a226'},
  vpn:{n:'Network and VPN',c:'#5aa33b'},
  security:{n:'Security',c:'#9e4a2f'},
  system:{n:'Windows',c:'#6b7785'},
  other:{n:'Other',c:'#7d746a'},
};
const CAT_RULES=[
  ['browser',/^(chrome|msedge|firefox|brave|opera|opera_gx|vivaldi|arc|browser|yandex|thorium|librewolf|waterfox|zen)\.exe$/],
  ['ai',/^(claude|chatgpt|codex|copilot|cursor|windsurf|ollama|lm studio|jan|perplexity)(\.exe)?$|^ollama/],
  ['docker',/^(docker|com\.docker|vmmem|vmmemwsl|wsl|wslhost|wslservice|vmcompute|vmwp)/],
  ['dev',/^(idea64|idea|code|code - insiders|devenv|rider64|pycharm64|webstorm64|clion64|goland64|datagrip64|rustrover64|studio64|node|java|javaw|python|pythonw|py|git|git-remote-https|cargo|rustc|rust-analyzer|go|gopls|dotnet|msbuild|vbcscompiler|windowsterminal|openconsole|pwsh|powershell|cmd|conhost|bash|sh|mintty|gradle|fsnotifier64|jetbrains-toolbox|github|gh|postman|insomnia|dbeaver|sublime_text|notepad\+\+)(\.exe)?$/],
  ['comm',/^(discord|telegram|slack|teams|ms-teams|zoom|skype|whatsapp|viber|signal|element|thunderbird|outlook|olk)(\.exe)?$/],
  ['vpn',/^(mullvad|openvpn|wireguard|nordvpn|protonvpn|amnezia|expressvpn|windscribe|outline|hiddify|v2ray|xray|sing-box|clash)/],
  ['security',/^(msmpeng|nissrv|securityhealth|mbam|avp|bdservicehost|beservice|easyanticheat|vgc|vgtray|faceit|smartscreen|mssense)/],
  ['media',/^(spotify|vlc|mpc-hc64|mpv|potplayer|steam|steamwebhelper|epicgameslauncher|upc|ubisoftconnect|battle\.net|galaxyclient|eadesktop|obs64|audiodg|musicbee|foobar2000|aimp|itunes|yandexmusic)/],
];
function catOfExe(exe,path){
  const e=(exe||'').toLowerCase();
  for(const [c,re] of CAT_RULES)if(re.test(e))return c;
  const p=(path||'').toLowerCase();
  if(!p||p.startsWith('c:\\windows\\'))return 'system';
  if(p.includes('\\steamapps\\')||p.includes('\\games\\')||p.includes('ubisoft game launcher'))return 'media';
  return 'other';
}

/* =================================================================
   Model: live processes, tree, apps
   ================================================================= */
const SPARKN=300; // 5 minutes, one point per second — for sparklines and the map over a short period
const ring=()=>({a:new Float32Array(SPARKN),i:0,n:0});
function rpush(r,v){r.a[r.i]=v;r.i=(r.i+1)%SPARKN;if(r.n<SPARKN)r.n++;}
function rtail(r,k){const out=new Array(k).fill(0);const m=Math.min(k,r.n);for(let j=0;j<m;j++)out[k-1-j]=r.a[(r.i-1-j+SPARKN)%SPARKN];return out;}
function rfill(r,vals){r.a.fill(0);r.i=0;r.n=0;for(const v of vals.slice(-SPARKN))rpush(r,v);}

const NODES=new Map();           // "pid:create time" → node
const INFO=new Map();            // id → {path, description, company, role}
const ICONS=new Map();           // lowercase path → data URL | null
let APPS=new Map(), NETS=[], GPUS=[], NETPP=false, MEMD=null, ISS=new Map(), EVENTS=[];
const SHORT_R=new Map();const shortAvg=(k,n)=>{const r=SHORT_R.get(k);if(!r)return 0;const t=rtail(r,Math.min(n,r.n||1));return t.reduce((s,v)=>s+v,0)/Math.max(1,t.length);};
let SYS=null, SYSINFO=null, SEQ=0, EVSEQ=0, NOW=Date.now(), CPUS=1, TOTAL_MB=1;
let NEWKEYS=[], needBackfill=true;

function applySnap(s){
  SEQ=s.seq;const f=s.frame;SYS=f.system;NOW=f.at_ms;CPUS=SYS.logical_cpus;TOTAL_MB=SYS.memory.total/MB;
  const seen=new Set();
  GPUS=s.gpus||[];syncGpuCols();
  for(const p of f.procs){
    if(p.pid===0)continue;
    const id=p.pid+':'+p.create_time;
    let n=NODES.get(id);
    if(!n){n={id,pid:p.pid,ct:p.create_time,exe:p.name,kids:[],parent:null,rc:ring(),rio:ring(),appKey:null,bornAt:BOOTING?0:NOW};NODES.set(id,n);NEWKEYS.push(id);}
    n.alive=true;n.ppid=p.ppid;n.cpu=p.cpu;n.mem=p.mem/MB;n.rd=p.io_read_bps/MB;n.wr=p.io_write_bps/MB;n.dsk=n.rd+n.wr;
    n.threads=p.threads;n.handles=p.handles;n.up=Math.max(0,(NOW-ctToMs(p.create_time))/1000);n.session=p.session;n.susp=!!p.suspended;n.cpuMs=p.cpu_time_ms;n.ws=p.working_set/MB;n.priv=p.private_bytes/MB;n.bprio=p.base_priority;n.gpu=p.gpu||0;n.gmem=(p.gpu_mem||0)/MB;n.nrx=(p.net_rx_bps||0)*8/1e6;n.ntx=(p.net_tx_bps||0)*8/1e6;n.net=n.nrx+n.ntx;
    for(const k of GK)n[k]=0;if(p.gpu_by)for(const x of p.gpu_by)n['g:'+x.key]=x.util;
    n.netBy=null;if(p.net_by){n.netBy={};for(const x of p.net_by)n.netBy[x.key]={rx:x.rx_bps*8/1e6,tx:x.tx_bps*8/1e6};}
    rpush(n.rc,n.cpu);rpush(n.rio,n.dsk);seen.add(id);
  }
  for(const n of NODES.values()){
    if(n.alive&&!seen.has(n.id)){n.alive=false;n.deadAt=NOW;n.cpu=0;n.dsk=0;n.rd=0;n.wr=0;n.gpu=0;for(const k of GK)n[k]=0;n.kids=[];n.ghostOf=n.parent?n.parent.id:null;}
    // exited processes are kept for 2 minutes (or while selected / open in a tab)
    if(!n.alive&&NOW-n.deadAt>120e3&&S.sel!==n.id&&!PROC_TABS.has(n.id)){NODES.delete(n.id);INFO.delete(n.id);}
  }
  const byPid=new Map();for(const n of NODES.values())if(n.alive)byPid.set(n.pid,n);
  for(const n of NODES.values())if(n.alive)n.kids=[];
  for(const n of NODES.values()){
    if(!n.alive)continue;
    const p=byPid.get(n.ppid);
    n.parent=p&&p!==n&&p.ct<=n.ct?p:null;
    if(n.parent)n.parent.kids.push(n);
  }
  APPS=new Map();
  for(const a of s.apps){
    const app={key:a.key,title:a.title,rootPid:a.root_pid,path:a.path,count:a.count,cpu:a.cpu,mem:a.mem/MB,dsk:(a.io_read_bps+a.io_write_bps)/MB,gpu:a.gpu||0,pids:a.pids,short:a.short_cpu||0,spawn:a.spawn_rate||0,spawnNames:a.spawn_names||[]};
    APPS.set(a.key,app);
    for(const pid of a.pids){const n=byPid.get(pid);if(n)n.appKey=a.key;}
  }
  /* CPU of short-lived processes — per second by app ('' — not attributed to anyone) */
  const shortSeen=new Set();
  for(const a of APPS.values())if(a.short>0||SHORT_R.has(a.key)){if(!SHORT_R.has(a.key))SHORT_R.set(a.key,ring());rpush(SHORT_R.get(a.key),a.short);shortSeen.add(a.key);}
  if(!SHORT_R.has(''))SHORT_R.set('',ring());rpush(SHORT_R.get(''),SYS.unseen_cpu||0);shortSeen.add('');
  for(const [k,r] of SHORT_R)if(!shortSeen.has(k)){rpush(r,0);if(rtail(r,SPARKN).every(v=>!v))SHORT_R.delete(k);}
  NETS=s.nets||[];NETPP=!!s.net_per_process;MEMD=s.mem_detail||null;POOLA=s.pool_alerts||[];
  ISS=new Map();
  for(const i of s.issues||[]){const id=i.pid+':'+i.create_time;if(!ISS.has(id))ISS.set(id,[]);ISS.get(id).push({lvl:i.level,txt:i.text,kind:i.kind});}
  for(const e of s.events||[]){
    EVENTS.push(e);EVSEQ=Math.max(EVSEQ,e.seq);
    if(EVENTS.length>500)EVENTS.shift();
    if(e.level==='red'&&!BOOTING)toast(e.text,'red',6000);
  }
}

const alive=n=>!!n&&n.alive;
const privateMB=()=>{let s=0;for(const n of NODES.values())if(n.alive)s+=n.mem;return s;};
/* what the used memory outside process private memory consists of (MB) */
function memParts(){
  const rest=Math.max(0,SYS.memory.used/MB-privateMB());
  if(!MEMD)return [{label:'Kernel, drivers and Windows caches',v:rest}];
  const d={np:MEMD.pool_nonpaged/MB,pp:MEMD.pool_paged/MB,cache:MEMD.cache/MB,code:MEMD.kernel_code/MB,mod:MEMD.modified/MB};
  const known=d.np+d.pp+d.cache+d.code+d.mod;
  return [
    {label:'Non-paged kernel pool (drivers)',v:d.np,warn:d.np>1024},
    {label:'Paged kernel pool',v:d.pp},
    {label:'File cache',v:d.cache},
    {label:'Kernel and driver code',v:d.code},
    {label:'Waiting to be written to disk',v:d.mod},
    {label:'Shared program memory (DLLs, shared buffers)',v:Math.max(0,rest-known)},
  ];
}
const aliveKids=n=>n.alive?n.kids:[];
function desc(n){const out=[];const st=[n];const seen=new Set();while(st.length){const x=st.pop();if(seen.has(x))continue;seen.add(x);out.push(x);if(x.alive)for(const k of x.kids)st.push(k);}return out;}
/* subtree totals are computed once per sample — sorting and the table use them as is */
let AGG=new Map(),AGG_SEQ=-1,AGG_F=['cpu','mem','dsk','rd','wr','gpu','net'];
function agg(n){
  if(AGG_SEQ!==SEQ){AGG=new Map();AGG_SEQ=SEQ;}
  let a=AGG.get(n.id);if(a)return a;
  /* Σ — only processes of the same app. Programs started from a process
     (almost everything is started from Explorer) are not in its total: they are separate apps.
     all — the total over the whole subtree, for the “with everything started from it” tooltip. */
  const own=()=>{const o={cpu:n.cpu||0,mem:n.mem||0,dsk:n.dsk||0,rd:n.rd||0,wr:n.wr||0,gpu:n.gpu||0,net:n.net||0};for(const k of GK)o[k]=n[k]||0;return o;};
  a={...own(),all:own(),cnt:1,spark:null};AGG.set(n.id,a);
  if(n.alive)for(const k of n.kids){
    const b=agg(k),same=k.appKey===n.appKey;a.cnt+=b.cnt;
    for(const f of AGG_F){a.all[f]+=b.all[f];if(same)a[f]+=b[f];}
  }
  return a;
}
function cur(n,m,incl){return incl?agg(n)[m]||0:n[m]||0;}
const curAll=(n,m)=>agg(n).all[m]||0;
const sameApp=n=>n.alive?n.kids.filter(k=>k.appKey===n.appKey):[];
/* descendants from the same app (for the “with children” charts) */
function appDesc(n){const out=[],st=[n];while(st.length){const x=st.pop();out.push(x);st.push(...sameApp(x));}return out;}
function sparkSum(n){
  const a=agg(n);if(a.spark)return a.spark;
  const s=rtail(n.rc,120);for(const k of sameApp(n)){const t=sparkSum(k);for(let i=0;i<120;i++)s[i]+=t[i];}
  return a.spark=s;
}
function ancestors(n){const a=[];const seen=new Set([n]);for(let p=n.parent;p&&!seen.has(p);p=p.parent){seen.add(p);a.unshift(p);}return a;}
/* engine pseudo-processes: CPU time spent on interrupts and deferred procedure calls (DPC) — not programs */
const PSEUDO={4294967293:'Interrupts',4294967294:'Deferred procedure calls (DPC)'};
const procCount=()=>{let c=0;for(const n of NODES.values())if(n.alive&&!PSEUDO[n.pid])c++;return c;};
const appOf=n=>n&&n.appKey?APPS.get(n.appKey):null;
function catOf(n){const a=appOf(n);const i=INFO.get(n.id);return catOfExe(a?a.key:n.exe,i?i.path:(a&&a.path));}
function nameOf(n){
  if(PSEUDO[n.pid])return PSEUDO[n.pid];
  /* svchost.exe — named by the services inside, like in System Informer */
  const sv=n.exe==='svchost.exe'&&SVC_BY_PID.get(n.pid);
  if(sv&&sv.length)return sv.length===1?sv[0].display:`${sv[0].display} and ${sv.length-1} more`;
  const bt=BTASKS.tasks.get(n.id);if(bt)return taskLabel(bt);
  const i=INFO.get(n.id),a=appOf(n);
  if(i&&i.role)return i.role;
  const base=a&&a.rootPid===n.pid&&a.key!=='windows'?a.title:i&&i.description&&i.description.length<60?i.description:n.exe.replace(/\.exe$/i,'');
  const w=winTitle(n,base);
  return w?`${base} — ${w}`:base;
}
/* Which browser process serves which tab is known only to the browser itself: it shows that in its own task manager
   (Shift+Esc). While that is open, the engine reads its rows and remembers them while the process lives. */
let BTASKS={open:false,tasks:new Map(),at:0,busy:false};
function pollBrowserTasks(){
  if(BTASKS.busy||Date.now()-BTASKS.at<3000)return;BTASKS.busy=true;
  rpc('browser_tasks').then(r=>{BTASKS={open:r.open,tasks:new Map(Object.entries(r.tasks)),at:Date.now(),busy:false};})
    .catch(()=>{BTASKS.at=Date.now();BTASKS.busy=false;});
}
const TASK_KIND=[[/^Tab: /,'Tab: '],[/^Subframe: /,'Frame: '],[/^Extension: /,'Extension: '],[/^App: /,'App: '],
  [/^Service Worker: /,'Service Worker: '],[/^Shared Worker: /,'Shared Worker: '],[/^Dedicated Worker: /,'Worker: '],[/^Prerender: /,'Prerender: '],
  [/^Back\/Forward cache: /,'Back cache: '],[/^Tool: Preloaded UI Renderer$/,'Browser UI (preloaded)'],[/^Tool: /,'Browser UI: ']];
function taskText(t){
  for(const [re,ru] of TASK_KIND)if(re.test(t)){t=t.replace(re,ru);break;}
  return t.replace(/https?:\/\/([^/]+)\/?\S*/,'$1'); // for a frame or a worker the site matters, not the full address
}
/* for a map tile — first what sets the process apart: tab title, site, extension name, and the kind
   after it (the tile is already inside the browser group, and “Tab: …” on a narrow tile left just “Ta…”) */
const TASK_SHORT=[[/^Tab: /,''],[/^Frame: (.*)/,'$1 · frame'],[/^Extension: (.*)/,'$1 · extension'],[/^App: (.*)/,'$1 · app'],
  [/^(Service Worker|Shared Worker|Worker): (.*)/,'$2 · $1'],[/^Prerender: (.*)/,'$1 · prerender'],[/^Back cache: (.*)/,'$1 · back cache']];
function taskShort(t){t=taskText(t);for(const [re,to] of TASK_SHORT)if(re.test(t))return t.replace(re,to);return t;}
/* tabs matter more than frames and workers: the process is named after its first tab, the rest is “and N more” */
function taskLabel(list,short){
  const txt=short?taskShort:taskText,rank=t=>/^Tab/.test(t)?0:/^(Extension|App)/.test(t)?1:/^Subframe/.test(t)?2:3;
  const s=list.slice().sort((a,b)=>rank(a)-rank(b)),first=txt(s[0]);
  const same=s.filter(t=>txt(t)===first).length,more=s.length-same;
  return first+(more?` (and ${more} more)`:'');
}
/* process name on a map tile */
function mapName(n){const bt=BTASKS.tasks.get(n.id);return mapLabel(bt?taskLabel(bt,true):nameOf(n));}
/* Titles of the processes’ main windows (polled every 3 s): for a browser — the open tab, for an editor — the file
   and project. A “- Brave”, “— Cursor” suffix and a title equal to the program name are not repeated. */
let WTITLES=new Map(),WT_AT=0,WT_BUSY=false;
function pollWindows(){
  if(WT_BUSY||Date.now()-WT_AT<3000)return;WT_BUSY=true;
  rpc('windows').then(r=>{WTITLES=new Map(Object.entries(r).map(([k,v])=>[+k,v]));WT_AT=Date.now();WT_BUSY=false;})
    .catch(()=>{WT_AT=Date.now();WT_BUSY=false;});
}
function winTitle(n,base){
  /* a browser’s window title is one of its tabs: one long line for the whole browser explains nothing,
     the tabs are in the details */
  if(BROWSERS.has(n.exe.toLowerCase()))return '';
  const list=WTITLES.get(n.pid);if(!list||!list.length)return '';
  const i=INFO.get(n.id),names=[base,i&&i.description,n.exe.replace(/\.exe$/i,''),n.exe==='explorer.exe'&&'file explorer'].filter(Boolean).map(s=>s.toLowerCase());
  const same=s=>{const l=s.trim().toLowerCase();return !l||names.some(x=>x===l||x.split(' ')[0]===l||l.split(' ')[0]===x);};
  const clean=t=>{const m=t.match(/^(.*\S)\s+[-–—]\s+([^-–—]+)$/);return m&&same(m[2])?m[1]:t;};
  const ts=list.map(clean).filter(t=>!same(t));
  if(!ts.length)return '';
  return ts[0]+(ts.length>1?` (and ${ts.length-1} more ${plural(ts.length-1,'window','windows','windows')})`:'');
}
const label=n=>nameOf(n);

/* ----- problems (yellow / red badges) — computed by the engine ----- */
function worstIn(n){let w=null;for(const x of appDesc(n)){if(x===n)continue;const i=ISS.get(x.id);if(i){if(i.some(z=>z.lvl==='red'))return 'red';w='yel';}}return w;}

/* =================================================================
   Interface state
   ================================================================= */
const RANGES=[
  {key:'2m',label:'2 min',ms:120e3},
  {key:'15m',label:'15 min',ms:900e3},
  {key:'1h',label:'1 h',ms:3600e3},
  {key:'3h',label:'3 h',ms:3*3600e3},
  {key:'12h',label:'12 h',ms:12*3600e3},
  {key:'24h',label:'24 h',ms:86400e3},
];
const S={
  range:RANGES[0],res:'cpu',sel:null,multi:new Set(),hoverT:null,hl:null,
  procMode:'tree',incl:true,sort:'cpu',dir:-1,q:'',open:new Set(),freeze:false,order:null,
  map:{color:'exe',root:null},chartMode:'apps',rail:true,main:true,right:true,bottom:true,btab:'chart',more:false,bh:300,rw:360,
};
try{const r=RANGES.find(r=>r.key===localStorage.getItem('tm-range'));if(r)S.range=r;}catch(e){}
try{const u=JSON.parse(localStorage.getItem('tm-ui')||'{}');for(const k of ['chartMode','rail','main','right','bottom','btab','res','bh','rw','more','procMode','incl','sort','dir'])if(k in u)S[k]=u[k];
  /* old or broken values fall back to defaults, otherwise no mode button is highlighted */
  if(S.procMode!=='tree'&&S.procMode!=='apps')S.procMode='tree';if(S.dir!==1&&S.dir!==-1)S.dir=-1;if(typeof S.sort!=='string')S.sort='cpu';}catch(e){}
const saveUI=()=>{try{localStorage.setItem('tm-ui',JSON.stringify({chartMode:S.chartMode,rail:S.rail,main:S.main,right:S.right,bottom:S.bottom,btab:S.btab,res:S.res,bh:S.bh,rw:S.rw,more:S.more,procMode:S.procMode,incl:S.incl,sort:S.sort,dir:S.dir}));}catch(e){}};
/* settings shared with the CLI and MCP (%LOCALAPPDATA%\tm\settings.json): protected processes, confirmation */
let SETTINGS={protected:[],confirm_kill:true};
const stem=x=>String(x).toLowerCase().replace(/\.exe$/,'');
const isProt=n=>SETTINGS.protected.some(p=>!/[\\/]/.test(p)&&stem(p)===stem(n.exe));
async function loadSettings(){
  try{SETTINGS={...SETTINGS,...await rpc('settings_get')};}catch(e){return;}
  /* migrate the old protected list from the window’s localStorage */
  try{const old=JSON.parse(localStorage.getItem('tm-protect')||'[]');const add=old.filter(x=>!SETTINGS.protected.some(p=>stem(p)===stem(x)));
    if(add.length){SETTINGS.protected.push(...add);await saveSettings();}localStorage.removeItem('tm-protect');}catch(e){}
}
async function saveSettings(){try{await rpc('settings_set',SETTINGS);}catch(e){toast('Settings not saved: '+(e.message||e),'red',6000);}}
let DRAGGING=false;
const vis=el=>!!el&&el.isConnected&&el.clientWidth>0&&el.clientHeight>0;
function openPath(n){for(let x=n;x.parent&&x.parent.appKey===x.appKey;x=x.parent)S.open.add(x.parent.id);}

/* =================================================================
   History data: requests pile up while drawing and go out in one batch
   ================================================================= */
const HC=new Map();   // request key → {at, res}
const NEED=new Map(); // key → {method, params, ttl}
function need(method,params,ttl){const k=method+JSON.stringify(params);const c=HC.get(k);if(!c||Date.now()-c.at>ttl)NEED.set(k,{method,params});return c?c.res:null;}
const stepTtl=R=>R.ms<=900e3?900:R.ms<=3*3600e3?9e3:55e3;
const BY={cpu:'cpu',mem:'mem',dsk:'io',gpu:'gpu'};
function H(scope,by,top,keys,R=S.range){return need('history',{scope,range_ms:R.ms,by,top,keys:keys||[]},stepTtl(R));}
function SP(keys,metric,points){return need('sparks',{groups:[keys],metric,points},900);}
let flushing=false;
async function flushNeeds(){
  if(flushing||!NEED.size)return;flushing=true;
  const list=[...NEED.entries()];NEED.clear();
  try{
    const res=await rpc('batch',list.map(([,v])=>({method:v.method,params:v.params})));
    const now=Date.now();
    res.forEach((r,i)=>{if(r.result!==undefined)HC.set(list[i][0],{at:now,res:r.result});});
    if(HC.size>300){const old=[...HC.entries()].sort((a,b)=>a[1].at-b[1].at).slice(0,100);for(const [k] of old)HC.delete(k);}
    renderCharts();renderRail();renderMap(true);
  }catch(e){showErr(e);}
  flushing=false;
}
/* unit conversion: memory and I/O arrive in bytes */
const conv=m=>m==='mem'||m==='dsk'?(v=>v/MB):m==='net'?(v=>v*8/1e6):(v=>v);

/* =================================================================
   Actions
   ================================================================= */
function toast(txt,lvl='info',ms=4200,btn=null){const el=document.createElement('div');el.className='toast';el.innerHTML=`<span class="dot ${lvl==='red'?'red':lvl==='yel'?'yel':''}" style="${lvl==='ok'?'background:var(--success)':lvl==='info'?'background:var(--accent)':''}"></span><span>${esc(txt)}</span>`;if(btn){const b=document.createElement('button');b.className='btn';b.textContent=btn.t;b.onclick=()=>{el.remove();btn.f();};el.appendChild(b);}$('#toasts').appendChild(el);setTimeout(()=>el.remove(),ms);}
function showErr(e){const b=$('#errbar');b.textContent='No connection to the engine: '+(e&&e.message||e);b.style.display='block';clearTimeout(showErr.t);showErr.t=setTimeout(()=>b.style.display='none',4000);}
const PRIO_NAMES={idle:'Low',below_normal:'Below normal',normal:'Normal',above_normal:'Above normal',high:'High'};
async function doAct(action,nodes,opts={}){
  const targets=nodes.map(n=>[n.pid,n.ct]);
  try{return await rpc('act',{action,targets,tree:!!opts.tree,priority:opts.priority||null,dry_run:!!opts.dry,force:!!opts.force,confirmed:!!opts.confirmed});}
  catch(e){toast(e.message||String(e),'red',6000);return null;}
}
/* refusals and failures in one message; “did not close” comes with a “force” button */
function reportBad(r,action,opts){
  const bad=r.results.filter(x=>!x.ok);if(!bad.length)return;
  const b=bad[0],who=b.name||('PID '+b.pid);
  const forceable=bad.filter(x=>x.can_force);
  if(forceable.length&&action==='kill'){
    const nodes=forceable.map(x=>NODES.get(x.pid+':'+x.create_time)).filter(alive);
    toast(`${who}: ${b.error}${bad.length>1?` (and ${bad.length-1} more)`:''}`,'yel',12000,nodes.length?{t:'Force end',f:()=>runAct('kill',nodes,{...opts,force:true,confirmed:true})}:null);
  }else if(bad.length>1&&!r.results.some(x=>x.ok))
    toast(`Not done: ${who} — ${b.error}. Processes not affected: ${bad.length}.`,'red',9000);
  else toast(`Not done: ${who} — ${b.error}${bad.length>1?` (and ${bad.length-1} more)`:''}`,'red',b.error.length>60?9000:6500);
}
const VERBS={kill:'End',suspend:'Suspend',resume:'Resume',restart:'Restart'};
let DIALOG=null; /* one confirmation dialog at a time */
/* confirmation dialog: targets and refusals come from the core’s dry run (dry_run), the same rules as tm kill */
function dialog({title,body,ok,danger,check}){
  return new Promise(res=>{
    const bg=document.createElement('div');bg.className='modal-bg';
    bg.innerHTML=`<div class="modal" role="dialog" aria-modal="true" aria-labelledby="m-title"><h3 id="m-title">${esc(title)}</h3><div class="m-body scroll">${body}</div>
      ${check?`<label class="m-check"><input type="checkbox"> ${esc(check)}</label>`:''}
      <div class="m-acts"><button class="btn" data-r="0">Cancel</button>${ok?`<button class="btn ${danger?'danger-fill':'primary'}" data-r="1">${esc(ok)}</button>`:''}</div></div>`;
    const prevFocus=document.activeElement;
    const done=v=>{const c=bg.querySelector('.m-check input');bg.remove();DIALOG=null;document.removeEventListener('keydown',key,true);if(prevFocus&&prevFocus.focus)prevFocus.focus();res(v?{check:!!(c&&c.checked)}:null);};
    const key=e=>{
      /* while the dialog is open, list hotkeys (Delete etc.) do nothing */
      e.stopImmediatePropagation();
      if(e.repeat){e.preventDefault();return;} /* a held Enter does not confirm the action */
      if(e.key==='Escape'){e.preventDefault();done(false);}
      else if(e.key==='Enter'&&!e.target.matches('input')){e.preventDefault();done(e.target.dataset.r==='1');}
      else if(e.key==='Tab'){const f=[...bg.querySelectorAll('button,input')];const i=f.indexOf(document.activeElement);e.preventDefault();f[(i+(e.shiftKey?f.length-1:1))%f.length].focus();}
    };
    bg.addEventListener('click',e=>{const b=e.target.closest('[data-r]');if(b)done(b.dataset.r==='1');else if(e.target===bg)done(false);});
    document.addEventListener('keydown',key,true);
    document.body.appendChild(bg);DIALOG=bg;
    const mb=bg.querySelector('.m-body');if(mb.scrollHeight>mb.clientHeight+1)mb.classList.add('over');
    /* for a dangerous action the focus goes to Cancel: a habitual Enter ends nothing */
    (danger||!ok?bg.querySelector('[data-r="0"]'):bg.querySelector('[data-r="1"]')).focus();
  });
}
function targetRows(rs,why){
  const shown=rs.slice(0,12);
  return shown.map(r=>{const n=NODES.get(r.pid+':'+r.create_time);
    return `<div class="m-row">${n?ico(n):'<span class="m-ico"></span>'}<span class="m-n">${esc(n?nameOf(n):r.name||('PID '+r.pid))}</span><span class="caption num">${r.pid}</span><span class="caption num m-mem">${n?fmtMem(cur(n,'mem',false)):''}</span></div>${why&&r.error?`<div class="m-why">${esc(r.error)}</div>`:''}${!why&&r.note?`<div class="m-why warn">${esc(r.note.replace(/^warning: /,''))}</div>`:''}`;
  }).join('')+(rs.length>shown.length?`<div class="caption m-more">and ${rs.length-shown.length} more</div>`:'');
}
/* action with confirmation. Ending and restarting always ask (ending a single process — until
   “don’t ask again” is chosen); suspending asks if it touches several processes or there is a warning */
async function runAct(action,nodes,opts={}){
  const n=nodes[0];
  if(!opts.confirmed){
    if(DIALOG||runAct.busy)return;
    runAct.busy=true;let pre;
    try{pre=await doAct(action,nodes,{...opts,dry:true});}finally{runAct.busy=false;}
    if(!pre)return;
    const ok=pre.results.filter(x=>x.ok),bad=pre.results.filter(x=>!x.ok),warn=ok.filter(x=>x.note);
    if(!ok.length){reportBad(pre,action,opts);return;}
    const single=ok.length===1&&!opts.tree;
    const ask=action==='restart'||warn.length||bad.length||(action==='kill'?(!single||SETTINGS.confirm_kill):ok.length>1);
    if(ask){
      const others=new Map();
      if(opts.tree)for(const r of nodes)for(const x of desc(r))if(x!==r&&x.appKey!==r.appKey&&x.alive){const ap=appOf(x);const k=x.appKey||x.exe;if(!others.has(k))others.set(k,ap?ap.title:nameOf(x));}
      /* roots first in the list, so it is clear whose tree it is */
      const roots=new Set(nodes.map(x=>x.pid+':'+x.ct));
      ok.sort((a,b)=>roots.has(b.pid+':'+b.create_time)-roots.has(a.pid+':'+a.create_time));
      const title=opts.tree?`${VERBS[action]} “${label(n)}” and its children (${ok.length})?`:ok.length>1?`${VERBS[action]} ${ok.length} processes?`:`${VERBS[action]} “${label(n)}”?`;
      const win=ok.filter(x=>x.window).length;
      const lead={
        kill:win===ok.length?'The program will first be asked to close, as if its window were closed — it will have time to save its data.'
          :win?'Programs with a window will first be asked to close themselves — they will have time to save their data. Other processes end immediately.'
          :'The process ends immediately; unsaved data in it will be lost.',
        restart:'The process will be ended and started again with the same file, command line, folder and rights. Unsaved data in it will be lost.',
        suspend:'A suspended process gets no CPU time and does not respond until it is resumed. Its windows and memory stay in place.',
        resume:''}[action];
      const body=`${lead?`<p class="m-lead">${lead}</p>`:''}
        ${others.size?`<div class="m-warn">${ICON_WARN}<span>Programs started from it will end too: ${esc([...others.values()].slice(0,8).join(', '))}${others.size>8?` and ${others.size-8} more`:''}.</span></div>`:''}
        <div class="m-list">${targetRows(ok,false)}</div>
        ${bad.length?`<div class="m-sub">Will not be affected</div><div class="m-list">${targetRows(bad,true)}</div>`:''}`;
      const r=await dialog({title,body,ok:VERBS[action],danger:action==='kill'||action==='restart',check:action==='kill'&&single&&!warn.length?'Don’t ask again when ending a single process':null});
      if(!r)return;
      if(r.check){SETTINGS.confirm_kill=false;saveSettings();}
    }
    opts={...opts,confirmed:true};
  }
  const slow=action==='kill'&&!opts.force?setTimeout(()=>toast('Waiting for the program to close by itself…','info',5000),700):0;
  const r=await doAct(action,nodes,opts);clearTimeout(slow);
  if(!r)return;
  reportBad(r,action,opts);
  const done=r.results.filter(x=>x.ok);if(!done.length)return renderAll();
  const more=done.length>1?` and ${done.length-1} more`:'';
  if(action==='kill'){
    toast(`Ended: ${label(n)}${more} — freed ${fmtMem(r.freed/MB)}`,'ok');
    if(S.sel&&done.some(x=>x.pid+':'+x.create_time===S.sel)){const p=NODES.get(S.sel)?.parent;S.sel=p&&p.alive?p.id:null;}
  }else if(action==='suspend')toast(`${label(n)}${more}: suspended. CPU = 0, windows and memory stay in place.`,'info');
  else if(action==='resume')toast(`${label(n)}${more}: resumed`,'info');
  else if(action==='restart')toast(`${label(n)} restarted${done[0].new_pid?` (new PID ${done[0].new_pid})`:''}`,'ok');
  renderAll();
}
async function info(n,full){
  if(full){try{const r=await rpc('info',{pid:n.pid,create_time:n.ct});n.full=r.info;n.prio=r.priority;return r.info;}catch(e){return null;}}
  return INFO.get(n.id);
}
async function act(a,ids){
  /* interrupts and DPC are kernel load rows: nothing to act on except opening a separate tab */
  if(a!=='open')ids=ids.filter(id=>!PSEUDO[(NODES.get(id)||{}).pid]);
  const nodes=ids.map(id=>NODES.get(id)).filter(alive);if(!nodes.length)return;
  const n=nodes[0];
  if(a==='kill')return runAct('kill',nodes);
  if(a==='tree')return runAct('kill',nodes,{tree:true});
  /* suspend by default touches only the process itself; with children is a separate item */
  if(a==='suspend'||a==='suspend_tree'){
    const on=!nodes.every(x=>x.susp);
    return runAct(on?'suspend':'resume',nodes,{tree:a==='suspend_tree'||!on});
  }
  if(a==='restart')return runAct('restart',[n]);
  if(a.startsWith('prio:')){
    const p=a.slice(5);const r=await doAct('priority',nodes,{priority:p});
    if(r){reportBad(r,'priority',{});if(r.ok){nodes.forEach(x=>x.prio=p);toast(`${label(n)}: priority “${PRIO_NAMES[p]}”`,'info');}}
  }else if(a==='folder'){const i=INFO.get(n.id);if(!i||!i.path)return toast('File path not available (administrator rights needed)','yel');rpc('reveal',{path:i.path}).catch(e=>toast(e.message,'red'));}
  else if(a==='web'){const i=INFO.get(n.id);rpc('web',{q:`${n.exe} ${i&&i.company?i.company+' ':''}what is this process`}).catch(e=>toast(e.message,'red'));}
  else if(a==='copycmd'){const f=await info(n,true);if(!f||!f.cmdline)return toast('Command line not available','yel');try{await navigator.clipboard.writeText(f.cmdline);toast('Command line copied','info');}catch(e){toast('Could not copy','red');}}
  else if(a==='protect'){
    const on=isProt(n);
    SETTINGS.protected=on?SETTINGS.protected.filter(p=>stem(p)!==stem(n.exe)):[...SETTINGS.protected,n.exe.toLowerCase()];
    await saveSettings();
    toast(on?`${n.exe}: protection removed`:`${n.exe}: protected — it cannot be ended by the window, tm kill or an AI agent`,'info');
  }
  else if(a==='open')return openProcTab(n.id);
  renderAll();
}
const menu=$('#menu');let menuIds=null;
function openMenu(x,y,ids){
  const n=NODES.get(ids[0]);if(!n)return;menuIds=ids;
  const many=ids.length>1,sp=n.susp,hasKids=aliveKids(n).length>0;
  const it=[];
  if(!many&&PSEUDO[n.pid]){
    it.push({h:nameOf(n)},{t:'Open in a separate tab',a:'open'});
  }else{
  it.push({h:many?`Selected: ${ids.length}`:`${nameOf(n)} · PID ${n.pid}`});
  it.push({t:many?'End selected':'End',a:'kill',k:'Del',d:1});
  if(hasKids)it.push({t:'End with children',a:'tree',k:'Shift+Del',d:1});
  it.push('-',{t:sp?'Resume':'Suspend',a:'suspend'});
  if(hasKids&&!sp)it.push({t:'Suspend with children',a:'suspend_tree'});
  it.push({t:'Restart',a:'restart',d:1});
  it.push('-',{h:'Priority'},...['idle','below_normal','normal','above_normal','high'].map(p=>({t:PRIO_NAMES[p],a:'prio:'+p,c:n.prio===p})));
  it.push('-',{t:'Open in a separate tab',a:'open'},{t:'Open file location',a:'folder'},{t:'Copy command line',a:'copycmd'},{t:'What is this process?',a:'web'},{t:isProt(n)?'Remove protection':'Protect from ending',a:'protect'});
  }
  menu.innerHTML=it.map(i=>i==='-'?'<div class="sep"></div>':i.h?`<div class="mh">${esc(i.h)}</div>`:`<div class="mi${i.d?' danger':''}" data-a="${i.a}"><span>${i.c?'✓ ':''}${esc(i.t)}</span>${i.k?`<kbd>${i.k}</kbd>`:''}</div>`).join('');
  menu.style.display='block';const r=menu.getBoundingClientRect();
  menu.style.left=Math.min(x,innerWidth-r.width-8)+'px';menu.style.top=Math.max(8,Math.min(y,innerHeight-r.height-8))+'px';
  if(!n.prio&&!PSEUDO[n.pid])info(n,true);
}
const closeMenu=()=>{menu.style.display='none';menuIds=null;menu.classList.remove('col-menu');};
document.addEventListener('pointerdown',e=>{if(!menu.contains(e.target))closeMenu();},true);
menu.addEventListener('click',e=>{const mi=e.target.closest('.mi[data-a]');if(!mi||!menuIds)return;const ids=menuIds;closeMenu();act(mi.dataset.a,ids);});
function select(id,reveal){S.sel=id;if(!S.right&&!overlay('right'))toggleRight(true);S.multi=new Set([id]);const n=NODES.get(id);if(n){if(reveal)openPath(n);info(n,true).then(()=>renderDetails());}renderAll();if(reveal)requestAnimationFrame(()=>revealRow(id));}

/* =================================================================
   Charts (CloudWatch / Cloudscape style)
   ================================================================= */
function prep(cv){
  const r=devicePixelRatio||1,w=cv.clientWidth,h=cv.clientHeight;
  if(!w||!h)return [null,0,0];
  if(cv.width!==Math.round(w*r)||cv.height!==Math.round(h*r)){cv.width=Math.round(w*r);cv.height=Math.round(h*r);}
  const x=cv.getContext('2d');x.setTransform(r,0,0,r,0,0);x.clearRect(0,0,w,h);return [x,w,h];
}
function niceMax(v){if(v<=0)return 1;const p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;return (f<=1?1:f<=2?2:f<=2.5?2.5:f<=5?5:10)*p;}
function tLabel(ms,step){const d=new Date(ms);const hh=String(d.getHours()).padStart(2,'0'),mm=String(d.getMinutes()).padStart(2,'0');return step<5000?`${hh}:${mm}:${String(d.getSeconds()).padStart(2,'0')}`:`${hh}:${mm}`;}
const stepStr=ms=>ms<60e3?Math.round(ms/1000)+' s':Math.round(ms/60e3)+' min';
/* o: {series:[{name,color,data,key?,nodeId?}], t0, step, stacked, fmt, max, fill, missing} */
function drawTS(cv,o){
  const [x,w,h]=prep(cv);if(!x)return;
  const n=Math.max(2,o.series.reduce((m,s)=>Math.max(m,s.data.length),0));
  let mx=0;
  for(let i=0;i<n;i++){let s=0;for(const se of o.series){const v=se.data[i]||0;s=o.stacked?s+v:Math.max(s,v);}mx=Math.max(mx,s);}
  const max=o.max||niceMax(mx*1.08||1);
  x.font='12px "Segoe UI Variable Text","Segoe UI",sans-serif';
  /* left padding follows the widest axis label: “375 MB/s” did not fit into a fixed 52 px */
  const padL=Math.max(40,Math.ceil(Math.max(...[1,.75,.5,.25].map(k=>x.measureText(o.fmt(max*k)).width)))+12),padR=6,padT=6,padB=20,W=w-padL-padR,H=h-padT-padB;
  if(!o.series.length||(mx<1e-6&&!o.max)){x.fillStyle='rgba(255,255,255,.5442)';x.textAlign='center';x.textBaseline='middle';x.strokeStyle='#424650';x.beginPath();x.moveTo(padL,Math.round(padT+H)+.5);x.lineTo(padL+W,Math.round(padT+H)+.5);x.stroke();x.fillText(o.empty||'No activity in this period',padL+W/2,padT+H/2);cv._g=null;return;}
  x.textBaseline='middle';x.strokeStyle='#424650';x.lineWidth=1;x.fillStyle='#c6c6cd';x.textAlign='right';
  const TK=H<90?2:4;for(let k=0;k<=TK;k++){const y=Math.round(padT+H-H*k/TK)+.5;x.beginPath();x.moveTo(padL,y);x.lineTo(padL+W,y);x.stroke();x.fillText(o.fmt(max*k/TK),padL-6,y);}
  x.textAlign='center';x.textBaseline='top';
  const X=i=>padL+W*i/(n-1);
  const XT=W<420?2:4;for(let k=0;k<=XT;k++){const i=Math.round(k*(n-1)/XT);x.fillText(tLabel(o.t0+i*o.step,o.step),clamp(X(i),padL+22,padL+W-22),padT+H+5);}
  const Y=v=>padT+H-clamp(v/max,0,1.02)*H;
  /* the part of the period before the engine started — no data */
  if(o.missing>0){x.fillStyle='rgba(255,255,255,.03)';x.fillRect(padL,padT,X(Math.min(o.missing,n-1))-padL,H);}
  if(o.stacked){
    let base=new Array(n).fill(0);
    for(const se of o.series){
      const top=base.map((b,i)=>b+(se.data[i]||0));
      x.beginPath();for(let i=0;i<n;i++){i?x.lineTo(X(i),Y(top[i])):x.moveTo(X(i),Y(top[i]));}
      for(let i=n-1;i>=0;i--)x.lineTo(X(i),Y(base[i]));
      const dim=S.hl&&S.hl!==se.key;
      x.closePath();x.fillStyle=hexA(se.color,dim?.21:.7);x.fill();
      x.beginPath();for(let i=0;i<n;i++){i?x.lineTo(X(i),Y(top[i])):x.moveTo(X(i),Y(top[i]));}
      x.strokeStyle=hexA(se.color,dim?.3:1);x.lineWidth=1;x.stroke();
      base=top;
    }
  }else{
    for(const se of o.series){
      x.beginPath();for(let i=0;i<n;i++){const v=se.data[i]||0;i?x.lineTo(X(i),Y(v)):x.moveTo(X(i),Y(v));}
      x.strokeStyle=se.color;x.lineWidth=2;x.lineJoin='round';x.stroke();
      if(o.fill&&o.series.length===1){x.lineTo(X(n-1),Y(0));x.lineTo(X(0),Y(0));x.closePath();x.fillStyle=hexA(se.color,.12);x.fill();}
    }
  }
  if(S.hoverT!=null){
    const i=Math.round((S.hoverT-o.t0)/o.step);
    if(i>=0&&i<n){
      x.strokeStyle='#8c8c94';x.lineWidth=1;x.beginPath();x.moveTo(Math.round(X(i))+.5,padT);x.lineTo(Math.round(X(i))+.5,padT+H);x.stroke();
      let acc=0;for(const se of o.series){const v=se.data[i]||0;acc=o.stacked?acc+v:v;x.beginPath();x.arc(X(i),Y(acc),3.5,0,7);x.fillStyle='#282828';x.fill();x.strokeStyle=se.color;x.lineWidth=2;x.stroke();}
    }
  }
  cv._g={padL,padT,W,H,n,max,o};
}
function chartHover(cv,pop,e){
  const g=cv._g;if(!g)return;
  const r=cv.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  const i=clamp(Math.round((mx-g.padL)/g.W*(g.n-1)),0,g.n-1);
  const o=g.o;S.hoverT=o.t0+i*o.step;
  let rows=o.series.map(se=>({se,v:se.data[i]||0}));
  if(o.stacked)rows=rows.filter(r=>r.v>=.005).sort((a,b)=>b.v-a.v).slice(0,9);
  const total=o.stacked?o.series.reduce((s,se)=>s+(se.data[i]||0),0):null;
  pop.innerHTML=`<div class="pt">${tLabel(S.hoverT,o.step)}${o.step>1000?` · average over ${stepStr(o.step)}`:''}${total!=null?` · total <b>${o.fmt(total)}</b>`:''}</div>`+rows.map(r=>`<div class="pr"><i style="background:${r.se.color}"></i><span>${esc(r.se.name)}</span><b>${o.fmt(r.v)}</b></div>`).join('');
  pop.style.display='block';
  const pr=pop.parentElement.getBoundingClientRect(),pw=pop.offsetWidth,ph=pop.offsetHeight;
  let left=e.clientX-pr.left+16;if(left+pw>pr.width)left=e.clientX-pr.left-pw-16;
  pop.style.left=Math.max(0,left)+'px';pop.style.top=clamp(e.clientY-pr.top-ph/2,0,Math.max(0,pr.height-ph))+'px';
  if(o.stacked){const v=(g.padT+g.H-my)/g.H*g.max;let acc=0;cv._hit=null;for(const se of o.series){acc+=se.data[i]||0;if(v<=acc){cv._hit=se;break;}}}
  renderCharts();
}
function sparkSVG(data,max,color,w=72,h=18){
  if(!data.length)return '';const n=data.length;
  const pts=data.map((v,i)=>`${(i*w/(n-1)).toFixed(1)},${(h-1-clamp(v/max,0,1)*(h-2)).toFixed(1)}`).join(' ');
  return `<svg class="sp" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.2" vector-effect="non-scaling-stroke"/></svg>`;
}

/* ----- icons: the real one from the .exe; until it loads — a letter on the category color ----- */
function ico(n,l){
  const i=INFO.get(n.id),a=appOf(n);const path=(i&&i.path)||(a&&a.rootPid===n.pid&&a.path)||'';
  const src=path&&ICONS.get(path.toLowerCase());
  if(src)return `<img class="ico${l?' l':''}" src="${src}" alt="">`;
  const c=CATS[catOf(n)]||CATS.other;const ch=(nameOf(n).replace(/^[^A-Za-zА-Яа-яЁё0-9]+/,'')[0]||'?');
  return `<span class="ico${l?' l':''}" style="background:${hexA(c.c,.55)};box-shadow:inset 0 0 0 1px ${hexA(c.c,.9)}">${esc(ch.toUpperCase())}</span>`;
}
let iconsBusy=false;
/* a data: URL becomes a short blob: URL: the table redraws every second,
   and a long base64 in every row would make the browser parse and decode the images again */
function blobUrl(d){try{const b=atob(d.slice(d.indexOf(',')+1)),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return URL.createObjectURL(new Blob([u],{type:'image/png'}));}catch(e){return d;}}
async function ensureInfos(){
  pollWindows();pollBrowserTasks();
  if(NEWKEYS.length){
    const ids=NEWKEYS.splice(0,NEWKEYS.length).filter(id=>NODES.has(id)),keys=ids.map(id=>{const n=NODES.get(id);return [n.pid,n.ct];});
    for(let i=0;i<keys.length;i+=600){
      try{const r=await rpc('infos',{keys:keys.slice(i,i+600)});for(const [k,v] of Object.entries(r))INFO.set(k,v);}catch(e){NEWKEYS.push(...ids.slice(i,i+600));}
    }
  }
  if(iconsBusy)return;
  const want=new Set();
  for(const n of NODES.values()){const i=INFO.get(n.id);if(i&&i.path&&!ICONS.has(i.path.toLowerCase()))want.add(i.path);}
  for(const a of APPS.values())if(a.path&&!ICONS.has(a.path.toLowerCase()))want.add(a.path);
  if(!want.size)return;
  iconsBusy=true;
  const list=[...want].slice(0,150);
  rpc('icons',{paths:list}).then(r=>{for(const [p,v] of Object.entries(r))ICONS.set(p.toLowerCase(),v?blobUrl(v):null);iconsBusy=false;renderProcs();renderDetails();}).catch(()=>{iconsBusy=false;});
}

/* =================================================================
   Resources (left strip). Choosing a resource switches the whole window.
   ================================================================= */
function resList(){
  if(!SYS)return [];
  const m=SYS.memory,ioR=[...NODES.values()].reduce((s,n)=>s+(n.alive?n.rd:0),0),ioW=[...NODES.values()].reduce((s,n)=>s+(n.alive?n.wr:0),0);
  const out=[
    {id:'cpu',name:'CPU',m:'cpu',col:0,max:100,fmt:fmtPct,sub:SYSINFO&&SYSINFO.cpu_name,hist:['system','cpu'],
     now:()=>SYS.cpu,line:v=>`${fmtPct(v)} · ${procCount()} processes`,
     keys:v=>[`${CPUS} logical processors`,`${procCount()} processes`,`${SYS.threads.toLocaleString('en')} threads`],
     more:()=>[['Handles',SYS.handles.toLocaleString('en')],['Interrupts',fmtPct(SYS.interrupt_cpu||0)],['Deferred procedure calls (DPC)',fmtPct(SYS.dpc_cpu||0)],['Uptime',agoStr(SYS.uptime_ms/1000)]],
     get note(){return SYS.by_cycles
       ?'Load is measured in CPU cycles, like in System Informer: more precise than by time, and it does not lose processes that exited between samples. Interrupts and DPC are separate rows in the process list.'
       :'Load is measured by CPU time: the cycle counter is not available (a virtual machine or more than 64 processors). Interrupts and DPC are separate rows in the process list.';}},
    {id:'mem',name:'Memory',m:'mem',col:2,max:TOTAL_MB,fmt:fmtMem,sub:`${nf(TOTAL_MB/1024,1)} GB`,hist:['system','mem'],
     now:()=>m.used/MB,line:v=>`${nf(v/1024,1)} / ${nf(TOTAL_MB/1024,1)} GB (${m.load_pct} %)`,
     keys:v=>[`${m.load_pct} % in use`,`${fmtMem(m.available/MB)} available`,`committed ${nf(m.commit_used/MB/1024,1)} / ${nf(m.commit_limit/MB/1024,1)} GB`],
     more:()=>[['In use',fmtMem(m.used/MB)],['Available',fmtMem(m.available/MB)],
       ...(MEMD&&MEMD.standby?[['· standby (cache)',fmtMem(MEMD.standby/MB)],['· free',fmtMem((MEMD.free||0)/MB)]]:[]),['Committed',fmtMem(m.commit_used/MB)],['Commit limit',fmtMem(m.commit_limit/MB)],['Processes (private)',fmtMem(privateMB())],
       ...memParts().map(p=>[p.label,fmtMem(p.v)+(p.warn?' — more than usual':'')]),
       ...(MEMD&&MEMD.compressed?[['Compressed memory (part of in use)',fmtMem(MEMD.compressed/MB)]]:[]),
       ...POOLA.map(a=>['Kernel alert',a.text.split('. ')[0]+' — see the Kernel pool tab'])],
     note:'Available = standby + free: standby is the file cache of recently read files, Windows hands it to programs on first request. Compressed memory is pages Windows compressed instead of writing them to disk; it is already part of “In use”. A process’s “Memory” is its private working set, like in the Windows Task Manager. The rest of the used memory: kernel pools (driver memory), the file cache and shared program memory — DLLs and shared buffers used by several processes at once (especially browsers and Electron apps). A non-paged pool above 1 GB happens with a memory leak in a driver — which driver grows is shown in the Kernel pool tab.'},
    ...GPUS.map(g=>{
      const short=gpuShort(g);
      return {id:'gpu:'+g.key,name:GPUS.length>1?'GPU · '+short:'GPU',m:'gpu',gpu:g,col:3,max:100,fmt:fmtPct,sub:g.name,hist:['gpu','gpu','gpu:'+g.key],
        now:()=>g.util,line:v=>`${fmtPct(v)} · ${nf(g.mem_used/MB/1024,1)} / ${nf(g.mem_total/MB/1024,1)} GB`,
        keys:v=>[g.engine?`busiest engine ${g.engine}`:'',`video memory ${fmtMem(g.mem_used/MB)} of ${fmtMem(g.mem_total/MB)}`,`shared ${fmtMem(g.shared_used/MB)}`].filter(Boolean),
        more:()=>[['Load',fmtPct(g.util)],['Busiest engine',g.engine||'—'],['Dedicated video memory',`${fmtMem(g.mem_used/MB)} of ${fmtMem(g.mem_total/MB)}`],['Shared memory',fmtMem(g.shared_used/MB)]],
        note:'Load is the busiest GPU engine (3D, video, copy, compute), like in the Windows Task Manager. Each process is credited with its busiest engine, so the total over processes can exceed the GPU load.'+(GPUS.length>1?' The map and the “GPU · '+short+'” table column (right-click a header) show the load of this GPU; the per-app chart is shared by all GPUs.':'')};
    }),
    {id:'disk',name:'Disk',m:'dsk',col:4,fmt:fmtMBs,hist:['system','io'],
     now:()=>ioR+ioW,line:v=>`↓ ${fmtMBs(ioR)} ↑ ${fmtMBs(ioW)}`,
     keys:v=>[`read ${fmtMBs(ioR)}`,`write ${fmtMBs(ioW)}`],
     more:()=>[['Read',fmtMBs(ioR)],['Write',fmtMBs(ioW)]],
     note:'How much processes read from and write to disk — by the kernel disk counters, like in System Informer: reads from cache, pipes and devices are not included. On old Windows versions without these counters — all of the process I/O.'},
  ];
  for(const a of NETS){
    const rx=a.rx_bps*8/1e6,tx=a.tx_bps*8/1e6,vpn=a.kind==='vpn';
    out.push({id:'net:'+a.key,name:'Network · '+a.name,m:'net',net:a,col:5,fmt:fmtMbit,sub:a.description,hist:['net','io',a.key],
      now:()=>rx,line:v=>`↓ ${fmtMbit(rx)} ↑ ${fmtMbit(tx)}`,
      keys:v=>[`↑ ${fmtMbit(tx)}`,vpn?'VPN tunnel':a.kind==='wifi'?'Wi-Fi':'Ethernet',a.link_bps?`link ${a.link_bps>=1e9?nf(a.link_bps/1e9,1)+' Gbit/s':Math.round(a.link_bps/1e6)+' Mbit/s'}`:''].filter(Boolean),
      more:()=>[['Received',fmtMbit(rx)],['Sent',fmtMbit(tx)],['Adapter',a.description]],
      note:(vpn?'All app traffic goes through this tunnel. ':'Traffic through the adapter. With a VPN on, this is already the encrypted tunnel traffic. ')+(NETPP?'Traffic of individual processes is in the Network column of the table and on the map.':'Windows shows per-process traffic only to programs with administrator rights.')});
  }
  return out;
}
let RES=[];
const curRes=()=>RES.find(r=>r.id===S.res)||RES[0];
/* a GPU uses its own column if it is enabled, otherwise the shared “GPU” one */
const SORT_OF=r=>r.m==='mem'?'mem':r.m==='dsk'?'dsk':r.m==='gpu'?(r.gpu&&GK.length&&COL_ON.has('g:'+r.gpu.key)?'g:'+r.gpu.key:'gpu'):r.m==='net'&&NETPP?'net':'cpu';
function setRes(id){S.res=id;const r=curRes();if(r)S.sort=SORT_OF(r);S.dir=-1;S.order=null;S.hl=null;saveUI();renderAll();}
function resStatus(r,v){
  if(r.id==='cpu')return v>90?'red':v>60?'yel':null;
  if(r.id==='mem')return SYS.memory.load_pct>90?'red':SYS.memory.load_pct>80?'yel':null;
  return null;
}
const R2={key:'2m',label:'2 min',ms:120e3};
function railData(r){
  const [scope,by,key]=r.hist;const h=H(scope,by,key?20:0,key?[key]:[],R2);
  if(!h)return null;const s=key?h.series.find(x=>x.key===key):h.total;
  return s?s.values.map(conv(r.m)):null;
}
function renderRail(){
  const el=$('#rail');if(!SYS||!railOn()||selIn(el))return;
  el.innerHTML='<div class="rh"><span>Resources</span><button class="ib" data-close="rail" title="Hide · Ctrl+B"><svg width="12" height="12" viewBox="0 0 12 12"><path d="M2.5 2.5l7 7m0-7l-7 7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg></button></div>'+RES.map(r=>{
    const v=r.now(),st=resStatus(r,v),col=PAL[r.col];
    const data=railData(r)||[v,v];
    const max=r.max||niceMax(Math.max(...data)*1.2||1);
    const pts=data.map((d,i)=>`${(i*100/(data.length-1)).toFixed(2)},${(29-clamp(d/max,0,1)*27).toFixed(2)}`).join(' ');
    return `<div class="ri${S.res===r.id?' on':''}" data-r="${esc(r.id)}"><div class="rn">${esc(r.name)}${st?`<span class="dot ${st}"></span>`:''}</div><div class="rv">${esc(r.line(v))}</div>
      <svg viewBox="0 0 100 30" preserveAspectRatio="none"><polygon points="0,30 ${pts} 100,30" fill="${hexA(col,.16)}"/><polyline points="${pts}" fill="none" stroke="${col}" stroke-width="1.2" vector-effect="non-scaling-stroke"/></svg></div>`;
  }).join('')+'<div class="rfoot">Choosing a resource switches the whole window: the chart, the process sorting and the map.</div>';
}
$('#rail').addEventListener('click',e=>{if(e.target.closest('[data-close]'))return toggleRail(false);const it=e.target.closest('.ri');if(it)setRes(it.dataset.r);});

/* =================================================================
   Bottom panel: one chart + “Total / By app / By process”
   ================================================================= */
function histMeta(h){return {t0:h.start_ms,step:h.step_ms,missing:h.missing||0};}
function totalSeries(r){
  if(r.m==='net'){
    const k=r.net.key,a=H('net','read',20,[k]),b=H('net','write',20,[k]);
    if(!a||!b)return null;const sa=a.series[0],sb=b.series[0],n=a.points;
    return {meta:histMeta(a),series:[{name:'Received',color:PAL[5],data:sa?sa.values.map(conv('net')):new Array(n).fill(0)},{name:'Sent',color:PAL[4],data:sb?sb.values.map(conv('net')):new Array(n).fill(0)}]};
  }
  if(r.m==='gpu'){
    const k=r.hist[2],h=H('gpu','gpu',20,[k]);if(!h)return null;const s=h.series[0];
    const out={meta:histMeta(h),series:[{name:'Load',color:PAL[3],data:s?s.values:new Array(h.points).fill(0)}]};
    return out;
  }
  if(r.m==='dsk'){
    const a=H('system','read',0),b=H('system','write',0);if(!a||!b)return null;
    return {meta:histMeta(a),series:[{name:'Read',color:PAL[0],data:a.total.values.map(conv('dsk'))},{name:'Write',color:PAL[4],data:b.total.values.map(conv('dsk'))}]};
  }
  const h=H('system',BY[r.m],0);if(!h)return null;
  return {meta:histMeta(h),series:[{name:r.m==='cpu'?'CPU load':'In use',color:PAL[r.col],data:h.total.values.map(conv(r.m))}]};
}
function nodeForSeries(scope,s){
  if(scope==='procs')return NODES.has(s.key)?s.key:null;
  const a=APPS.get(s.key);if(!a)return null;
  for(const n of NODES.values())if(n.alive&&n.pid===a.rootPid)return n.id;
  return null;
}
function breakdown(r,mode){
  const scope=mode==='procs'?'procs':'apps';
  const h=H(scope,BY[r.m],24);if(!h)return null;
  const cv=conv(r.m),top=h.series.slice(0,6),rest=h.series.slice(6);
  const series=top.map((s,i)=>({key:s.key,name:s.title,color:PAL[i%PAL.length],data:s.values.map(cv),nodeId:nodeForSeries(scope,s)}));
  if(rest.length||h.other){
    /* everything outside the top six goes into one band, with a breakdown in the tooltip */
    const data=new Array(h.points).fill(0);
    for(const s of rest)s.values.forEach((v,i)=>data[i]+=cv(v));
    if(h.other)h.other.values.forEach((v,i)=>data[i]+=cv(v));
    const more=h.other?+((h.other.title.match(/\d+/)||[0])[0]):0,count=rest.length+more;
    const last=s=>cv(s.values[s.values.length-1]||0);
    const list=rest.slice().sort((a,b)=>last(b)-last(a)).slice(0,15).map(s=>`${s.title} — ${r.fmt(last(s))}`);
    const tip=`Included (now):\n${list.join('\n')}${count>15?`\nand ${count-15} smaller ones`:''}`;
    series.push({key:'__o',name:`Others (${count})`,color:OTHER,data,tip});
  }
  return {meta:histMeta(h),series};
}
function mountChart(el){
  el._m=1;
  el.innerHTML=`<div class="ch-head"><h2 class="c-title"></h2><span class="big c-val"></span><div class="ch-keys c-keys"></div><div class="spacer"></div>
      <div class="seg c-mode"></div>
      <button class="more-t c-more-t"></button></div>
    <div class="ch-more c-more"></div>
    <div class="ch-area"><canvas class="c-cv"></canvas><div class="pop"></div></div>
    <div class="legend c-leg"></div>`;
  const cv=$('.c-cv',el),pop=$('.pop',el);
  cv.addEventListener('mousemove',e=>chartHover(cv,pop,e));
  cv.addEventListener('mouseleave',()=>{S.hoverT=null;pop.style.display='none';renderCharts();});
  cv.addEventListener('click',()=>{const h=cv._hit;if(h&&h.nodeId)select(h.nodeId,true);});
  cv.addEventListener('dblclick',()=>setMax('bottom'));
  $('.c-mode',el).addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;S.chartMode=b.dataset.m;S.hl=null;saveUI();renderCharts();flushNeeds();});
  $('.c-more-t',el).addEventListener('click',()=>{S.more=!S.more;saveUI();renderCharts();});
  $('.c-more',el).addEventListener('click',e=>{const r=e.target.closest('.dfs-r[data-id]');if(r)select(r.dataset.id,true);});
  const leg=$('.c-leg',el);
  leg.addEventListener('mouseover',e=>{const lg=e.target.closest('.lg');S.hl=lg?lg.dataset.k:null;renderCharts();});
  leg.addEventListener('mouseleave',()=>{S.hl=null;renderCharts();});
  leg.addEventListener('click',e=>{const lg=e.target.closest('.lg');if(lg&&lg.dataset.id)select(lg.dataset.id,true);});
}
function renderChart(){
  const el=$('#bChart');if(!S.bottom||S.btab!=='chart'||!vis(el)||!SYS)return;
  if(!el._m)mountChart(el);
  const r=curRes(),v=r.now();
  setHTML($('.c-title',el),esc(r.name));
  setHTML($('.c-val',el),esc(r.m==='net'?'↓ '+fmtMbit(v):r.m==='mem'?`${nf(v/1024,1)} GB`:r.fmt(v)));
  setHTML($('.c-keys',el),r.keys(v).map(k=>`<span>${esc(k)}</span>`).join(''));
  const modes=r.m==='net'?[['total','Total']]:[['total','Total'],['apps','By app'],['procs','By process']];
  let mode=S.chartMode;if(!modes.some(m=>m[0]===mode))mode='total';
  const seg=$('.c-mode',el);if(seg._r!==r.id){seg.innerHTML=modes.map(([k,t])=>`<button data-m="${k}">${t}</button>`).join('');seg._r=r.id;}
  seg.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.m===mode));
  $('.c-more-t',el).textContent=S.more?'Hide details':'More';
  const more=$('.c-more',el);more.hidden=!S.more;
  if(S.more)setHTML(more,[...(r.sub?[['Device',r.sub]]:[]),...r.more(v)].map(([a,b])=>`<div><span>${esc(a)}</span><b>${esc(String(b))}</b></div>`).join('')+(r.m==='dsk'?chartFiles():'')+(r.note?`<div class="note">${esc(r.note)}${r.m==='net'&&!NETPP&&!isAdmin()?ADMIN_LINK:''}</div>`:''));
  const d=mode==='total'?totalSeries(r):breakdown(r,mode);
  const cv=$('.c-cv',el);
  if(!d){drawTS(cv,{series:[],t0:NOW,step:1000,fmt:r.fmt,empty:'Loading history…'});return;}
  const stacked=mode!=='total';
  drawTS(cv,{...d.meta,series:d.series,stacked,fmt:r.fmt,max:r.m==='cpu'||r.m==='gpu'?100:undefined,fill:!stacked});
  const n=d.series[0]?d.series[0].data.length:0;
  const hi=S.hoverT!=null?clamp(Math.round((S.hoverT-d.meta.t0)/d.meta.step),0,n-1):n-1;
  setHTML($('.c-leg',el),d.series.length<2?'':d.series.map(s=>`<span class="lg" data-k="${esc(s.key||s.name)}" ${s.nodeId?`data-id="${esc(s.nodeId)}"`:''} ${s.tip?`title="${esc(s.tip)}"`:''}><i style="background:${s.color}"></i>${esc(s.name)} <b class="num">${r.fmt(s.data[hi]||0)}</b></span>`).join(''));
}
/* Maximize: the bottom panel or a process chart fills the whole window; Esc / another click — back */
const IC_MAX='<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><path d="M7 1.5h3.5V5M5 10.5H1.5V7M10.5 1.5L7 5M1.5 10.5L5 7"/></svg>';
const IC_RESTORE='<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><path d="M10.5 5H7V1.5M1.5 7H5v3.5M7 5l3.5-3.5M5 7l-3.5 3.5"/></svg>';
function maxMark(el,cls,on,btn){el.classList.toggle(cls,on);if(btn&&btn._on!==on){btn._on=on;btn.innerHTML=on?IC_RESTORE:IC_MAX;btn.title=on?'Restore · Esc':'Maximize to the whole window · double-click the chart';}}
function setMax(v){S.max=S.max===v?null:v;if(S.max==='bottom'&&!S.bottom)S.bottom=true;
  maxMark($('#shell'),'max-bottom',S.max==='bottom',$('#maxBottom'));applyShell();requestAnimationFrame(()=>requestAnimationFrame(renderCharts));}
function renderCharts(){renderChart();renderDetailChart();renderProcTabs(true);}

/* log */
function renderLog(){
  const el=$('#bLog');if(!S.bottom||S.btab!=='log'||!vis(el)||selIn(el))return;
  if(!EVENTS.length){el.innerHTML='<div class="empty">The log is empty. Hung processes, memory leaks, system overloads and your actions show up here.</div>';return;}
  el.innerHTML='<div class="evs">'+EVENTS.slice().reverse().map(e=>{
    const id=e.pid!=null?e.pid+':'+e.create_time:null,n=id&&NODES.get(id);
    const lvl=e.level==='red'?'red':e.level==='yel'?'yel':'';
    const st=e.level==='ok'?'background:var(--success)':e.level==='info'?'background:var(--text-4)':'';
    return `<div class="ev" ${n?`data-id="${esc(n.id)}"`:''}><span class="t">${new Date(e.at_ms).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'})}</span><span class="dot ${lvl}" style="${st}"></span><span>${esc(e.text)}${n?`<br><span class="who">${esc(ancestors(n).slice(-2).map(nameOf).concat(nameOf(n)).join(' › '))}</span>`:''}</span></div>`;
  }).join('')+'</div>';
}
$('#bLog').addEventListener('click',e=>{const it=e.target.closest('.ev');if(it&&it.dataset.id)select(it.dataset.id,true);});
$('#btabs').addEventListener('click',e=>{const b=e.target.closest('[data-t]');if(!b)return;S.btab=b.dataset.t;saveUI();applyShell();});

/* =================================================================
   Main area: Processes
   ================================================================= */
const COLS_BASE=[
  {k:'cpu',t:'CPU',m:'cpu',fmt:fmtPct,bar:100,w:76},
  {k:'mem',t:'Memory',m:'mem',fmt:fmtMem,bar:4096,w:88},
  {k:'dsk',t:'Disk',m:'dsk',fmt:fmtMBs,bar:50,w:84},
  {k:'net',t:'Network',m:'net',fmt:fmtMbit,bar:100,w:96},
  {k:'gpu',t:'GPU',m:'gpu',fmt:fmtPct,bar:100,w:64},
  /* extra columns — via right-click on a header; values of the process itself, without Σ */
  {k:'pid',t:'PID',m:'pid',fmt:v=>String(v),w:64,own:1,extra:1,asc:1},
  {k:'threads',t:'Threads',m:'threads',fmt:v=>String(v),w:66,own:1,extra:1},
  {k:'handles',t:'Handles',m:'handles',fmt:v=>v.toLocaleString('en'),w:96,own:1,extra:1},
  {k:'ws',t:'Working set',m:'ws',fmt:fmtMem,w:104,own:1,extra:1},
  {k:'priv',t:'Committed',m:'priv',fmt:fmtMem,w:88,own:1,extra:1},
  {k:'started',t:'Started',m:'ct',fmt:ct=>{const t=new Date(ctToMs(ct));return (t.toDateString()===new Date().toDateString()?'':t.toLocaleDateString('en-GB',{day:'2-digit',month:'2-digit'})+' ')+t.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});},w:96,own:1,extra:1},
  /* how long the process has been running; sorting ↓ puts the oldest on top */
  {k:'up',t:'Running for',m:'up',fmt:agoStr,w:112,own:1,extra:1},
];
/* with more than one GPU each gets its own column (enabled by right-clicking a header): a game may
   load the discrete one and a browser the integrated one, and the shared “GPU” (the busiest engine of any) cannot tell them apart */
let COLS_ALL=COLS_BASE,GK=[];
const gpuShort=g=>g.name.replace(/\((TM|R)\)/g,'').replace(/^(NVIDIA GeForce|NVIDIA|AMD|Intel) /,'').replace(/ (Laptop )?GPU$/,'').replace(/ Graphics$/,'').trim();
function syncGpuCols(){
  const gs=GPUS.length>1?GPUS:[],keys=gs.map(g=>'g:'+g.key);
  if(keys.join()===GK.join())return;
  GK=keys;AGG_F=['cpu','mem','dsk','rd','wr','gpu','net',...GK];AGG_SEQ=-1;
  const i=COLS_BASE.findIndex(c=>c.k==='gpu')+1;
  COLS_ALL=[...COLS_BASE.slice(0,i),...gs.map(g=>({k:'g:'+g.key,t:'GPU · '+gpuShort(g),mt:'GPU · '+g.name.replace(/\((TM|R)\)/g,''),m:'g:'+g.key,fmt:fmtPct,bar:100,w:112})),...COLS_BASE.slice(i)];
}
const COLS_KEY='tm-cols';
let COL_ON=new Set(['cpu','mem','dsk','gpu','net']);
try{const j=JSON.parse(localStorage.getItem(COLS_KEY)||'null');if(Array.isArray(j))COL_ON=new Set(j);}catch(e){}
/* column order and widths — as the user arranged them (dragging headers and their edges) */
const COLW_KEY='tm-colw',CORD_KEY='tm-colorder';
let COL_W={},COL_ORD=[];
try{COL_W=JSON.parse(localStorage.getItem(COLW_KEY)||'{}')||{};COL_ORD=JSON.parse(localStorage.getItem(CORD_KEY)||'[]')||[];}catch(e){}
const saveColLayout=()=>{try{localStorage.setItem(COLW_KEY,JSON.stringify(COL_W));localStorage.setItem(CORD_KEY,JSON.stringify(COL_ORD));}catch(e){}};
const SPARK_W=88;
/* width limits: a number like “12.3 %” is never wider than 120 px — stretching further is pointless */
const COL_LIM={name:[160,900],cpu:[56,120],gpu:[52,110],g:[64,170],mem:[64,150],dsk:[64,150],net:[72,170],pid:[52,100],threads:[56,100],handles:[72,130],ws:[72,150],priv:[72,150],started:[80,150],up:[96,160],spark:[60,200]};
const colLim=k=>COL_LIM[k]||COL_LIM[k.startsWith('g:')?'g':'']||[56,200];
const colW=c=>{const [mn,mx]=colLim(c.k);return clamp(COL_W[c.k]||c.w,mn,mx);},sparkW=()=>clamp(COL_W.spark||SPARK_W,...colLim('spark'));
/* until the user resizes anything, Name takes all the free space. Once a width
   is set, Name gets its own width and the free space stays empty to the right of the table — then the edge
   of any column follows the mouse exactly, like in Explorer */
const nameFixed=()=>COL_W.name>0;
/* all columns in the user’s order; new ones (added in an update) go to their usual place at the end */
const colsOrdered=()=>{const by=new Map(COLS_ALL.map(c=>[c.k,c]));const o=COL_ORD.filter(k=>by.has(k)).map(k=>by.get(k));return [...o,...COLS_ALL.filter(c=>!COL_ORD.includes(c.k))];};
const colOn=c=>COL_ON.has(c.k)&&(c.k!=='net'||NETPP);
const colByK=k=>COLS_ALL.find(c=>c.k===k);
/* the Network column — only when the engine sees per-process traffic (running as administrator) */
let COLS=colsOrdered().filter(colOn);
const PANEL_EL={};
let CDRAG=null,CRESIZE=null,CSKIP=false; // column drag, width change, “a click after a drag is not a sort”
function mountProcs(el){
  el.innerHTML=`<div class="ph">
      <input class="search p-q" placeholder="Search: name, description, PID…  (Ctrl+F)">
      <div class="seg p-mode"><button data-m="tree">Tree</button><button data-m="apps">Apps</button></div>
      <label class="chk" title="Show a parent’s total together with child processes of the same app. Programs started from it (for example from Explorer) are counted separately — hover over the number to see the full total."><input type="checkbox" class="p-incl"> Σ by app</label>
      <div class="spacer"></div><span class="caption p-frz" style="visibility:hidden">order frozen while the cursor is over the list</span>
      <button class="btn subtle p-who" title="Which processes keep a file or folder open (cannot be deleted, “in use by another process”)">Who holds a file…</button>
    </div>
    <div class="p-short" hidden></div>
    <div class="tbl-wrap"><table class="tbl procs"><colgroup></colgroup><thead></thead><tbody></tbody></table></div>
    <div class="foot p-foot"></div>`;
  $('.p-q',el).addEventListener('input',e=>{S.q=e.target.value.trim().toLowerCase();S.order=null;renderProcs();});
  $('.p-who',el).addEventListener('click',whoHolds);
  $('.p-mode',el).addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;S.procMode=b.dataset.m;S.order=null;saveUI();renderProcs();});
  $('.p-incl',el).addEventListener('change',e=>{S.incl=e.target.checked;saveUI();renderProcs();});
  const wrap=$('.tbl-wrap',el);
  let sraf=0;wrap.addEventListener('scroll',()=>{if(!sraf)sraf=requestAnimationFrame(()=>{sraf=0;renderProcs();});},{passive:true});
  wrap.addEventListener('mouseenter',()=>{S.freeze=true;$('.p-frz',el).style.visibility='visible';});
  wrap.addEventListener('mouseleave',()=>{S.freeze=false;$('.p-frz',el).style.visibility='hidden';});
  $('.p-short',el).addEventListener('click',e=>{const a=e.target.closest('[data-app]');if(!a)return;const ap=APPS.get(a.dataset.app);if(!ap)return;
    const n=[...NODES.values()].find(x=>alive(x)&&x.pid===ap.rootPid);if(n){openPath(n);select(n.id,true);revealRow(n.id);}});
  /* The header’s right edge is the width: the border follows the mouse, columns to the right shift.
     The header itself reorders: it follows the cursor and columns swap places on the fly. */
  const thead=$('thead',el);
  let ghost=null;
  const capture=e=>{try{thead.setPointerCapture(e.pointerId);}catch(x){}};
  thead.addEventListener('pointerdown',e=>{
    if(e.button!==0)return;const th=e.target.closest('th[data-k]');if(!th)return;const k=th.dataset.k;
    if(e.target.closest('.crz')){
      /* first resize: Name gets its current width so the columns to its left do not move */
      if(!nameFixed()){const n=thead.querySelector('th[data-k="name"]');COL_W.name=Math.round(n.getBoundingClientRect().width);}
      const w0=k==='name'?COL_W.name:k==='spark'?sparkW():colW(colByK(k));
      CRESIZE={k,w0,x0:e.clientX};capture(e);document.body.classList.add('col-resizing');e.preventDefault();renderProcs();return;
    }
    if(k==='name'||k==='spark')return;
    const r=th.getBoundingClientRect();
    CDRAG={k,x0:e.clientX,dx:e.clientX-r.left,w:r.width,top:r.top,h:r.height,label:colByK(k).t,moved:false};capture(e);
  });
  thead.addEventListener('pointermove',e=>{
    if(CRESIZE){const [mn,mx]=colLim(CRESIZE.k);COL_W[CRESIZE.k]=Math.round(clamp(CRESIZE.w0+(e.clientX-CRESIZE.x0),mn,mx));renderProcs();return;}
    if(!CDRAG)return;
    if(!CDRAG.moved){if(Math.abs(e.clientX-CDRAG.x0)<5)return;CDRAG.moved=true;document.body.classList.add('col-dragging');
      ghost=document.createElement('div');ghost.className='col-ghost';ghost.textContent=CDRAG.label;
      Object.assign(ghost.style,{width:CDRAG.w+'px',height:CDRAG.h+'px',top:CDRAG.top+'px'});document.body.appendChild(ghost);}
    ghost.style.left=(e.clientX-CDRAG.dx)+'px';
    /* where to drop: how many visible columns (except this one) are left of the cursor by their midpoints */
    const ths=[...thead.querySelectorAll('th[data-k]')].filter(t=>t.dataset.k!=='name'&&t.dataset.k!=='spark');
    const others=ths.filter(t=>t.dataset.k!==CDRAG.k);
    const idx=others.filter(t=>{const r=t.getBoundingClientRect();return r.left+r.width/2<e.clientX;}).length;
    const vis=ths.map(t=>t.dataset.k),cur=vis.indexOf(CDRAG.k);
    if(idx!==cur){
      const want=vis.filter(k=>k!==CDRAG.k);want.splice(idx,0,CDRAG.k);
      /* hidden columns keep their place among the others */
      const all=colsOrdered().map(c=>c.k),visSet=new Set(want);let vi=0;
      COL_ORD=all.map(k=>visSet.has(k)?want[vi++]:k);renderProcs();
    }
  });
  const endCol=()=>{
    if(CRESIZE){CRESIZE=null;document.body.classList.remove('col-resizing');saveColLayout();CSKIP=true;renderProcs();return;}
    if(!CDRAG)return;const d=CDRAG;CDRAG=null;
    if(ghost){ghost.remove();ghost=null;}document.body.classList.remove('col-dragging');
    if(d.moved){CSKIP=true;saveColLayout();}
    renderProcs();
  };
  thead.addEventListener('pointerup',endCol);thead.addEventListener('pointercancel',endCol);
  thead.addEventListener('dblclick',e=>{const z=e.target.closest('.crz');if(!z)return;const k=z.closest('th[data-k]').dataset.k;delete COL_W[k];saveColLayout();renderProcs();});
  $('thead',el).addEventListener('click',e=>{if(CSKIP||e.target.closest('.crz')){CSKIP=false;return;}const th=e.target.closest('th[data-k]');if(!th||th.dataset.k==='spark')return;const k=th.dataset.k;
    /* name and PID ascending, resources descending */
    if(S.sort===k)S.dir*=-1;else{S.sort=k;S.dir=k==='name'||(colByK(k)||{}).asc?1:-1;}S.order=null;renderProcs();});
  $('thead',el).addEventListener('contextmenu',e=>{e.preventDefault();colMenu(e.clientX,e.clientY);});
  const tb=$('tbody',el);
  tb.addEventListener('pointerdown',e=>{
    if(e.button!==0)return;const tr=e.target.closest('tr');if(!tr)return;const id=tr.dataset.id;
    /* rows take no focus: remove it from the previously pressed button so the arrows go to the list */
    const f=document.activeElement;if(f&&f!==document.body&&f.blur)f.blur();
    if(e.target.closest('.tw')){S.open.has(id)?S.open.delete(id):S.open.add(id);S.order=null;renderProcs();return;}
    if(e.ctrlKey){S.multi.has(id)?S.multi.delete(id):S.multi.add(id);S.sel=id;S.anchor=id;renderAll();return;}
    if(e.shiftKey&&S.anchor){e.preventDefault();selectRange(S.anchor,id);return;}
    S.anchor=id;select(id);
  });
  tb.addEventListener('dblclick',e=>{const tr=e.target.closest('tr');if(!tr)return;const id=tr.dataset.id;S.open.has(id)?S.open.delete(id):S.open.add(id);S.order=null;renderProcs();});
  tb.addEventListener('contextmenu',e=>{const tr=e.target.closest('tr');if(!tr)return;e.preventDefault();const id=tr.dataset.id;if(!S.multi.has(id)){S.sel=id;S.multi=new Set([id]);renderAll();}openMenu(e.clientX,e.clientY,[...S.multi]);});
}
function matchQ(n){if(!S.q)return true;const i=INFO.get(n.id);return (nameOf(n)+' '+n.exe+' '+n.pid+' '+(i&&i.description||'')+' '+(i&&i.path||'')).toLowerCase().includes(S.q);}
/* the top row of an app has the CPU of its short-lived processes in Σ too: otherwise “Claude 12 %” sat below
   the antivirus, even though together with the git and grep it started it used a third of the CPU */
const shortOf=(n,m)=>{if(m!=='cpu'||!n.appKey)return 0;const a=APPS.get(n.appKey);return a&&a.rootPid===n.pid?shortAvg(n.appKey,5):0;};
/* sort key: name as a string, own columns (PID, threads…) — the process’s own value, resources — with Σ */
function sortKey(n,k=S.sort){
  if(k==='name')return nameOf(n).toLowerCase();
  const c=colByK(k)||colByK('cpu');
  return c.own?n[c.m]||0:cur(n,c.m,S.incl)+(S.incl?shortOf(n,c.m):0);
}
const sortCmp=(x,y)=>typeof x==='string'?x.localeCompare(y,'en'):x-y;
function sortNodes(list){
  if(S.freeze&&S.order){const idx=S.order;return list.sort((a,b)=>(idx.has(a.id)?idx.get(a.id):1e9)-(idx.has(b.id)?idx.get(b.id):1e9));}
  const key=new Map(list.map(n=>[n,sortKey(n)]));
  return list.sort((a,b)=>S.dir*sortCmp(key.get(a),key.get(b))||a.pid-b.pid);
}
/* A row contains only processes of the same app (as in Σ). A program started
   from another one (Java tests from IntelliJ, everything from Explorer) is a separate top-level row
   marked “from …”: otherwise a heavy process hid in the collapsed branch of a light parent. */
const foreignRoot=n=>!n.parent||n.parent.appKey!==n.appKey;
/* common launchers — a “from Explorer” mark on half the list says nothing */
const LAUNCHERS=new Set(['windows','explorer.exe','svchost.exe','services.exe','wininit.exe','winlogon.exe','userinit.exe','sihost.exe','smss.exe','csrss.exe','system','sihost','explorer']);
function walkRows(roots){
  const out=[],keep=n=>!S.q||appDesc(n).some(matchQ);
  const walk=(n,d)=>{if(!keep(n))return;out.push({n,d});if(S.open.has(n.id)||S.q){sortNodes(sameApp(n).slice()).forEach(k=>walk(k,d+1));for(const g of GHOSTS)if((g.ghostOf===n.id||GHOST_TOP.get(g)===n)&&g.appKey===n.appKey)out.push({n:g,d:d+1});}};
  sortNodes(roots).forEach(r=>walk(r,0));return out;
}
/* an exited process stays in its place as a red row for another 2.5 s, a new one is green (like in System Informer) */
const GONE_MS=2500;
const isGhost=n=>!n.alive&&n.deadAt&&NOW-n.deadAt<GONE_MS&&!PSEUDO[n.pid];
const isFresh=n=>n.alive&&n.bornAt&&NOW-n.bornAt<GONE_MS;
let GHOSTS=[],GHOST_TOP=new Map();
function procRows(){
  const all=[...NODES.values()],live=all.filter(alive);
  GHOSTS=all.filter(isGhost).filter(matchQ);
  /* a ghost without a live parent is a separate top-level row. But if its app has
     a live row (Claude with dozens of git and conhost), it is shown inside it and only when expanded:
     otherwise red rows flickered under a collapsed app that nobody had ever seen green */
  const tops=new Map();for(const n of live)if(n.appKey&&foreignRoot(n)&&!tops.has(n.appKey))tops.set(n.appKey,n);
  GHOST_TOP=new Map();
  const ghostRoots=GHOSTS.filter(g=>{const p=g.ghostOf&&NODES.get(g.ghostOf);if(p&&p.alive&&p.appKey===g.appKey)return false;
    const t=g.appKey&&tops.get(g.appKey);if(t){GHOST_TOP.set(g,t);return false;}return true;});
  if(S.procMode==='tree')return walkRows([...live.filter(foreignRoot),...ghostRoots]);
  const out=[],groups=new Map();
  for(const n of [...live,...ghostRoots]){const k=n.appKey||n.exe;if(!groups.has(k))groups.set(k,[]);if(!n.alive||!n.parent||n.parent.appKey!==n.appKey)groups.get(k).push(n);}
  const apps=[...groups.entries()].map(([k,tops])=>({k,tops})).filter(a=>a.tops.length);
  const c=colByK(S.sort);
  /* name, PID, threads… — the group key is taken from the first process after sorting (for resources — the total) */
  const tot=a=>S.sort==='name'||(c&&c.own)?sortKey(sortNodes(a.tops)[0]):a.tops.reduce((s,n)=>s+cur(n,(c||colByK('cpu')).m,true),0);
  const key=new Map(apps.map(a=>[a,tot(a)]));
  apps.sort((a,b)=>S.dir*sortCmp(key.get(a),key.get(b)));
  for(const a of apps)out.push(...walkRows(a.tops));
  return out;
}
let sparkReq=0;
const ROW_H=32,ROW_BUF=12;
/* the row may not be drawn (outside the visible part) — scroll to it by its index */
function revealRow(id){
  const el=PANEL_EL.procs;if(!vis(el))return;const wrap=$('.tbl-wrap',el);
  const r=el.querySelector(`tr[data-id="${CSS.escape(id)}"]`);if(r){r.scrollIntoView({block:'nearest'});return;}
  const i=procRows().findIndex(x=>x.n.id===id);if(i<0)return;
  wrap.scrollTop=($('thead',el).offsetHeight||33)+i*ROW_H-wrap.clientHeight/2;renderProcs();
}
/* Short-lived processes (git, grep, sh from scripts) live less than a second and never make it into the list, but they can
   take the whole CPU: “CPU 100 %” while the table shows 8 % at the top. This shows how many there are and who starts them */
function renderShort(el){
  const box=$('.p-short',el),sec=5,list=[...APPS.values()].map(a=>({a,v:shortAvg(a.key,sec)})).filter(x=>x.v>=1).sort((p,q)=>q.v-p.v);
  const un=shortAvg('',sec),tot=list.reduce((s,x)=>s+x.v,0);
  if(tot+un<5){box.hidden=true;return;}box.hidden=false;
  const who=list.slice(0,3).map(({a,v})=>`<a data-app="${esc(a.key)}" title="Show ${esc(a.title)} in the list">${esc(mapLabel(a.title))}</a> — ${fmtPct(v)}${a.spawnNames.length?` <span class="n2">(${esc(a.spawnNames.join(', '))})</span>`:''}`).join(' · ');
  setHTML(box,`${ICON_INFO}<span>${tot>=1?`<b>${fmtPct(tot)} CPU — short-lived processes</b> not in the list: each lives less than a second, but they are started by the dozen every second. Started by ${who}.`:''}${un>=5?` ${tot>=1?'Another':'<b>'}${fmtPct(un)} CPU${tot>=1?'':'</b>'} could not be attributed to any process — interrupts, drivers or processes that exited before the sample.`:''}</span>`);
}
/* column picker: right-click on the table header */
function colMenu(x,y){
  menuIds=null;
  menu.innerHTML='<div class="mh">Columns</div>'+COLS_ALL.filter(c=>c.k!=='net'||NETPP).map(c=>`<div class="mi" data-col="${c.k}"><span><input type="checkbox" ${COL_ON.has(c.k)?'checked':''}>${esc(c.mt||(c.k==='gpu'&&GK.length?'GPU (any GPU)':c.t))}</span></div>`).join('')
    +'<div class="sep"></div><div class="mi" data-col="-"><span>Reset (columns, order and width)</span></div><div class="mh" style="font-weight:400">Drag a column by its header, resize it by its edge</div>';
  menu.classList.add('col-menu');menu.style.display='block';const r=menu.getBoundingClientRect();
  menu.style.left=Math.min(x,innerWidth-r.width-8)+'px';menu.style.top=Math.max(8,Math.min(y,innerHeight-r.height-8))+'px';
}
menu.addEventListener('click',e=>{
  const mi=e.target.closest('[data-col]');if(!mi)return;e.stopPropagation();
  const k=mi.dataset.col;
  if(k==='-'){COL_ON=new Set(['cpu','mem','dsk','gpu','net']);COL_W={};COL_ORD=[];saveColLayout();}
  else if(COL_ON.has(k)){if(k!=='cpu'&&k!=='mem')COL_ON.delete(k);else return toast('CPU and memory cannot be hidden: the charts and the map are built from them','info');}
  else COL_ON.add(k);
  try{localStorage.setItem(COLS_KEY,JSON.stringify([...COL_ON]));}catch(x){}
  if(k==='-')closeMenu();else{const cb=mi.querySelector('input');if(cb)cb.checked=COL_ON.has(k);}
  if(S.sort!=='name'&&!COL_ON.has(S.sort)){S.sort='cpu';S.dir=-1;S.order=null;}
  renderProcs();
},true);
/* range selection (Shift+click, Shift+arrows) follows the visible row order */
function selectRange(from,to){
  const ids=procRows().map(r=>r.n.id),a=ids.indexOf(from),b=ids.indexOf(to);if(a<0||b<0)return select(to);
  S.multi=new Set(ids.slice(Math.min(a,b),Math.max(a,b)+1));S.sel=to;renderAll();revealRow(to);
}
/* keyboard in the list: arrows, Home/End, PageUp/PageDown, → expand, ← collapse or go to the parent,
   Enter — separate tab, Ctrl+C — copy rows, Ctrl+A — select all */
function procKeys(e){
  const el=PANEL_EL.procs;if(!vis(el))return false;
  /* only when the focus is in the process list or nowhere: buttons, fields and other panels have their own keys */
  const f=document.activeElement;
  if(f&&f!==document.body&&(!el.contains(f)||f.matches('button,select,textarea,input,[contenteditable],a')))return false;
  const rows=procRows(),ids=rows.map(r=>r.n.id);if(!ids.length)return false;
  const at=ids.indexOf(S.sel),i=Math.max(0,at),page=Math.max(1,Math.floor(($('.tbl-wrap',el).clientHeight||320)/ROW_H)-1);
  const go=j=>{j=clamp(j,0,ids.length-1);const id=ids[j];
    if(e.shiftKey){if(!S.anchor)S.anchor=S.sel||id;selectRange(S.anchor,id);}else{S.anchor=id;select(id);}
    revealRow(id);};
  const k=e.key;
  if(e.ctrlKey&&(e.code==='KeyC')){if(getSelection()&&!getSelection().isCollapsed)return false;copyRows();return true;}
  if(e.ctrlKey&&e.code==='KeyA'){S.multi=new Set(ids);renderAll();return true;}
  if(e.ctrlKey||e.altKey||e.metaKey)return false;
  if(k==='ArrowDown'){go(at<0?0:i+1);return true;} /* the selected one is not in the list (collapsed, exited) — from the start */
  if(k==='ArrowUp'){go(i-1);return true;}
  if(k==='PageDown'){go(i+page);return true;}
  if(k==='PageUp'){go(i-page);return true;}
  if(k==='Home'){go(0);return true;}
  if(k==='End'){go(ids.length-1);return true;}
  const n=NODES.get(S.sel);if(!n)return false;
  if(k==='ArrowRight'){if(sameApp(n).length&&!S.open.has(n.id)){S.open.add(n.id);S.order=null;renderProcs();}else go(i+1);return true;}
  if(k==='ArrowLeft'){if(S.open.has(n.id)){S.open.delete(n.id);S.order=null;renderProcs();}else if(n.parent&&n.parent.alive){S.anchor=n.parent.id;select(n.parent.id);revealRow(n.parent.id);}return true;}
  if(k==='Enter'){openProcTab(n.id);return true;}
  return false;
}
/* Ctrl+C: the selected rows as a tab-separated table (pastes into Excel and a chat as is) */
function copyRows(){
  const ids=S.multi.size?[...S.multi]:S.sel?[S.sel]:[];if(!ids.length)return;
  const order=procRows().map(r=>r.n.id),sorted=ids.slice().sort((a,b)=>order.indexOf(a)-order.indexOf(b));
  const cs=COLS.filter(c=>c.k!=='pid'); /* PID is the second column anyway */
  const head=['Name','PID',...cs.map(c=>c.t),'Path'].join('\t');
  const lines=sorted.map(id=>NODES.get(id)).filter(Boolean).map(n=>{const i=INFO.get(n.id)||{};
    const incl=S.incl&&sameApp(n).length>0; /* as in the table: with Σ by app if it is on */
    return [nameOf(n),n.pid,...cs.map(c=>c.own?c.fmt(n[c.m]||0):c.fmt(cur(n,c.m,incl)+(S.incl?shortOf(n,c.m):0))),i.path||''].join('\t');});
  const text=(lines.length>1?head+'\n':'')+lines.join('\n');
  (navigator.clipboard?navigator.clipboard.writeText(text):Promise.reject()).then(()=>toast(lines.length>1?`Rows copied: ${lines.length}`:'Row copied','info',1500)).catch(()=>{
    const t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();let ok=false;try{ok=document.execCommand('copy');}catch(x){}t.remove();
    toast(ok?(lines.length>1?`Rows copied: ${lines.length}`:'Row copied'):'Could not copy: the clipboard is not available',ok?'info':'red',ok?1500:undefined);});
}
function renderProcs(){
  const el=PANEL_EL.procs;if(!vis(el)||!SYS)return;
  $('.p-mode',el).querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.m===S.procMode));
  $('.p-incl',el).checked=S.incl;
  const want=colsOrdered().filter(colOn);
  if(want.map(c=>c.k).join()!==COLS.map(c=>c.k).join()){COLS=want;const tb=$('tbody',el);tb._rows=null;tb.innerHTML='';if(S.sort!=='name'&&!COLS.some(c=>c.k===S.sort))S.sort='cpu';}
  const nf=nameFixed();
  setHTML($('colgroup',el),(nf?`<col style="width:${COL_W.name}px">`:'<col>')+COLS.map(c=>`<col style="width:${colW(c)}px">`).join('')+`<col style="width:${sparkW()}px">`);
  /* name is at least 180 px: in a narrow panel the table scrolls sideways instead of squeezing names to an icon */
  const tw=(nf?COL_W.name:180)+COLS.reduce((a,c)=>a+colW(c),0)+sparkW();
  /* widths are set — the table is exactly that wide, the free space on the right is empty (the sparkline does not stretch) */
  $('table',el).style.minWidth=tw+'px';$('table',el).style.width=nf?tw+'px':'';
  const act=SORT_OF(curRes());
  const arrow=k=>S.sort===k?(S.dir<0?' ↓':' ↑'):'';
  setHTML($('thead',el),`<tr><th data-k="name" class="${S.sort==='name'?'on':''}" title="Sort by name · right-click — choose columns">Name${arrow('name')}<span class="crz" title="Drag — width · double-click — reset"></span></th>${COLS.map(c=>`<th data-k="${c.k}" class="${c.k===act?'act':''} ${S.sort===c.k?'on':''} ${CDRAG&&CDRAG.k===c.k&&CDRAG.moved?'cdrag':''}" title="Click — sort · drag — move">${c.t}${S.sort===c.k?(S.dir<0?' ↓':' ↑'):''}<span class="crz" title="Drag — width · double-click — reset"></span></th>`).join('')}<th data-k="spark" style="cursor:default">CPU · 2 min<span class="crz" title="Drag — width · double-click — reset"></span></th></tr>`);
  const rows=procRows();
  if(!S.freeze||!S.order)S.order=new Map(rows.map((r,i)=>[r.n.id,i]));
  const core=100/CPUS;
  /* only the visible rows are drawn (plus a margin): all ~400 rows made every frame
     of a border drag and every update noticeably heavier */
  const wrap=$('.tbl-wrap',el),hd=$('thead',el).offsetHeight||33;
  const i0=Math.max(0,Math.floor((wrap.scrollTop-hd)/ROW_H)-ROW_BUF),i1=Math.min(rows.length,Math.ceil((wrap.scrollTop+wrap.clientHeight)/ROW_H)+ROW_BUF);
  patchRows($('tbody',el),rows.slice(i0,i1).map(({n,d})=>{
    const kids=sameApp(n),iss=ISS.get(n.id),w=kids.length&&!S.open.has(n.id)?worstIn(n):null,sp=n.susp;
    const from=n.parent&&n.parent.appKey!==n.appKey&&!LAUNCHERS.has(n.parent.appKey)&&!LAUNCHERS.has(n.parent.exe.toLowerCase())?(APPS.get(n.parent.appKey)||{}).title||nameOf(n.parent):null;
    const lvl=iss?(iss.some(i=>i.lvl==='red')?'red':'yel'):null;
    const cells=COLS.map(c=>{if(c.own)return {c:'',t:'',h:`<span class="cell-v">${PSEUDO[n.pid]?'<span style="color:var(--text-4)">—</span>':esc(c.fmt(n[c.m]||0))}</span>`};const sh=S.incl?shortOf(n,c.m):0,vi=cur(n,c.m,S.incl&&kids.length>0)+sh,vo=cur(n,c.m,false),bw=clamp(vi/c.bar,0,1)*100;
      const other=aliveKids(n).length>kids.length;
      return {c:c.k===act?'act':'',t:kids.length||other?`The process itself: ${c.fmt(vo)}${kids.length?`\nWith the app’s child processes: ${c.fmt(cur(n,c.m,true))}`:''}${other?`\nWith everything started from it (other apps are separate rows): ${c.fmt(curAll(n,c.m))}`:''}${sh>=.05?`\nShort-lived processes it starts (not visible in the list): ${c.fmt(sh)}`:''}`:'',
        h:`<span class="cell-bar" style="width:${bw.toFixed(1)}%"></span><span class="cell-v">${(vi<.05&&c.k!=='mem')||(PSEUDO[n.pid]&&c.k==='mem')?'<span style="color:var(--text-4)">—</span>':c.fmt(vi)}</span>`};});
    const sd=S.incl&&kids.length?sparkSum(n):rtail(n.rc,120);
    const spk=sparkSVG(sd,Math.max(core*1.2,5),PAL[0]);
    const nm=nameOf(n),showExe=nm.toLowerCase()!==n.exe.toLowerCase().replace(/\.exe$/,'');
    const name=`<div class="nm" style="padding-left:${d*18}px"><span class="tw${S.open.has(n.id)?' open':''}" style="${kids.length?'':'visibility:hidden'}">${CHEV}</span>${ico(n)}
        <span class="n1">${esc(nm)}</span>${lvl?`<span class="dot ${lvl}" title="${esc(iss.map(i=>i.txt).join('\n'))}"></span>`:w?`<span class="dot ring ${w}" title="There is a problem inside — expand"></span>`:''}
        <span class="n2">${PSEUDO[n.pid]?'kernel load, not a process':(showExe?esc(n.exe)+' · ':'')+n.pid}${kids.length&&!S.open.has(n.id)?` · ${appDesc(n).length-1} ${plural(appDesc(n).length-1,'child','children')}`:''}${from&&S.procMode==='tree'?` · from ${esc(from)}`:''}</span>
        ${sp?'<span class="chip">suspended</span>':''}${isProt(n)?'<span class="chip">protected</span>':''}${n.prio==='idle'||n.prio==='below_normal'?'<span class="chip">low priority</span>':''}</div>`;
    return {id:n.id,cls:`${S.sel===n.id||S.multi.has(n.id)?'sel':''}${sp?' susp':''}${!n.alive?' gone':isFresh(n)?' new':''}`,cells:[{h:name},...cells,{h:spk}]};
  }),{top:i0*ROW_H,bot:(rows.length-i1)*ROW_H,cols:COLS.length+2});
  renderShort(el);
  const apps=new Set();for(const n of NODES.values())if(n.alive&&n.appKey)apps.add(n.appKey);
  setHTML($('.p-foot',el),`<span>Processes: ${procCount()}</span><span>Apps: ${apps.size}</span><div class="spacer"></div><span><span class="kbd">Del</span> end · <span class="kbd">Shift+Del</span> with children · <span class="kbd">Ctrl+click</span> several · <span class="kbd">Right-click</span> menu</span>`);
}
/* The table updates in place: rows are reused by process key, and a cell
   is redrawn only if its content changed. A full rebuild cost ~10 ms every second. */
function setHTML(el,h){if(el._h!==h&&!selIn(el)){el.innerHTML=h;el._h=h;}}
/* While text is selected in a block, the block is not redrawn: replacing the content drops
   the selection, and copying a path or a command line was impossible. */
function selIn(el){
  const s=getSelection();if(!el||!s||s.isCollapsed||!s.rangeCount)return false;
  const r=s.getRangeAt(0);return el.contains(r.startContainer)||el.contains(r.endContainer);
}
function patchRows(tb,list,pad){
  if(selIn(tb))return; // reordering rows would drop the selection too
  const map=tb._rows||(tb._rows=new Map()),keep=new Set();let prev=null;
  /* pad — height of the invisible rows above and below (spacers instead of them) */
  /* colspan — exactly the number of columns: extra columns squeezed Name almost to zero */
  const spacer=k=>{let t=tb[k];if(!t||!t.isConnected){t=tb[k]=document.createElement('tr');t.className='vsp';t.appendChild(document.createElement('td'));}t.firstChild.colSpan=pad.cols;return t;};
  if(pad){const t=spacer('_top');if(tb.firstChild!==t)tb.insertBefore(t,tb.firstChild);t.firstChild.style.height=pad.top+'px';t.hidden=!pad.top;prev=t;}
  for(const r of list){
    let e=map.get(r.id);
    if(!e){const tr=document.createElement('tr');tr.dataset.id=r.id;e={tr,cls:null,tds:r.cells.map(()=>tr.appendChild(document.createElement('td'))),h:[],c:[],t:[]};map.set(r.id,e);}
    keep.add(r.id);
    if(e.cls!==r.cls){e.tr.className=r.cls;e.cls=r.cls;}
    r.cells.forEach((c,j)=>{
      const td=e.tds[j];
      if(e.h[j]!==c.h){td.innerHTML=c.h;e.h[j]=c.h;}
      const cc=c.c||'',tt=c.t||'';
      if(e.c[j]!==cc){td.className=cc;e.c[j]=cc;}
      if(e.t[j]!==tt){td.title=tt;e.t[j]=tt;}
    });
    const want=prev?prev.nextSibling:tb.firstChild;
    if(want!==e.tr)tb.insertBefore(e.tr,want);
    prev=e.tr;
  }
  for(const [id,e] of map)if(!keep.has(id)){e.tr.remove();map.delete(id);}
  if(pad){const b=spacer('_bot');if(tb.lastChild!==b)tb.appendChild(b);b.firstChild.style.height=pad.bot+'px';b.hidden=!pad.bot;}
}

/* =================================================================
   Main area: the Map — by the selected resource.
   Memory — how much is used now. CPU and I/O — the average over the period,
   otherwise the tiles would jump every second.
   ================================================================= */
const mapMetric=()=>{const r=curRes();return r.m==='net'?(NETPP?'net':'cpu'):r.m;};
/* one of several GPUs is selected — the map follows its load (the per-app history is shared, so — now) */
const mapGpuKey=()=>{const r=curRes();return r.m==='gpu'&&r.gpu&&GK.length?'g:'+r.gpu.key:null;};
const mapSecs=()=>Math.min(SPARKN,Math.round(S.range.ms/1000));
function mapDesc(){
  const m=mapMetric(),p=S.range.label;
  if(m==='mem')return 'size — memory in use now';
  if(m==='net'){const a=curRes().net;return a?`size — process traffic through “${a.name}” now`+(a.kind==='vpn'?'':'. With a VPN on, its client is here too: it sends the programs’ traffic encrypted'):'size — process network traffic now';}
  if(curRes().m==='net')return 'per-process traffic is visible only with administrator rights (button at the top) — showing CPU load';
  if(m==='gpu'&&mapGpuKey())return `size — load of “${gpuShort(curRes().gpu)}” by processes now`;
  if(m==='gpu')return S.range.ms>SPARKN*1000?`size — average GPU load over ${p}`:'size — GPU load now';
  const h=H('system',BY[m],0);const avg=h?h.total.avg:0;
  return m==='cpu'?`size — average CPU load over ${p} · idle ${fmtPct(Math.max(0,100-avg))}`:`size — average I/O over ${p}`;
}
/* a process’s average over the period: short periods use the process’s per-second data,
   long ones use the app history spread over its processes in proportion to the last 5 minutes */
function ownAvg(n,m){
  const r=m==='cpu'?n.rc:n.rio,k=mapSecs(),t=rtail(r,k);let s=0,c=0;for(const v of t){s+=v;c++;}return c?s/c:0;
}
/* process traffic by adapter — “via VPN …, via Wi-Fi …” (if there is more than one adapter or the address is not recognized) */
function netSplit(n){
  const by=n.netBy;if(!by)return '';const ks=Object.keys(by).filter(k=>by[k].rx+by[k].tx>=.001);
  if(ks.length<2&&!(ks.length===1&&ks[0]===''))return ks.length===1?` · via ${esc((NETS.find(a=>a.key===ks[0])||{name:'?'}).name)}`:'';
  return '<br>'+ks.map(k=>{const a=NETS.find(a=>a.key===k);return `${a?esc(a.name):'unknown adapter'}: ↓ ${fmtMbit(by[k].rx)} ↑ ${fmtMbit(by[k].tx)}`;}).join('<br>');
}
function mapFmt(v){const m=mapMetric();return m==='net'?fmtMbit(v):m==='mem'?fmtMem(v):m==='dsk'?fmtMBs(v):fmtPct(v);}
function mountMap(el){
  el.innerHTML=`<div class="ph"><div class="crumbs m-crumbs" style="padding:0"></div><span class="caption m-desc"></span><div class="spacer"></div>
     <div class="m-cw"><span class="lbl">Color</span><div class="seg m-color"><button data-c="exe">By program</button><button data-c="cat">By type</button><button data-c="cpu">By CPU load</button></div></div></div>
    <div class="map-wrap"><canvas></canvas></div><div class="mapstat m-stat"></div><div class="maplegend m-leg"></div>`;
  const cv=$('canvas',el);
  $('.m-color',el).addEventListener('click',e=>{const b=e.target.closest('button');if(b){S.map.color=b.dataset.c;renderMap(true);}});
  $('.m-crumbs',el).addEventListener('click',e=>{const a=e.target.closest('[data-z]');if(a){S.map.root=a.dataset.z==='root'?null:a.dataset.z;renderMap(true);}});
  /* like in WizTree: the path and size of the tile under the cursor — a line under the map, the tile is outlined */
  cv.addEventListener('mousemove',e=>{MAP.mouse={clientX:e.clientX,clientY:e.clientY};const h=hitMap(cv,e);mapHover(h&&h.id);mapStatus();});
  cv.addEventListener('mouseleave',()=>{MAP.mouse=null;mapHover(null);mapStatus();});
  const leg=$('.m-leg',el);
  leg.addEventListener('mouseover',e=>{const s=e.target.closest('[data-k]');mapHl(s?s.dataset.k:null);});
  leg.addEventListener('mouseleave',()=>mapHl(null));
  $('.m-stat',el).textContent=MAP_HINT;
  cv.addEventListener('click',e=>{const h=hitMap(cv,e);if(h&&h.node)select(h.node.id,true);});
  cv.addEventListener('mouseup',e=>{if(e.button===3&&mapUp())e.preventDefault();});
  cv.addEventListener('dblclick',e=>{const h=hitMap(cv,e);if(h&&h.zoom){S.map.root=h.zoom;renderMap(true);}});
}
const plural=(n,a,b)=>n===1?a:b; // 1 process, 3 processes
/* the line under the map follows the tile under the cursor; it updates on every sample too, even if the mouse is still */
/* one level up — like the second-to-last crumb */
function mapUp(){const el=PANEL_EL.map;if(!S.map.root||!vis(el))return false;const a=[...el.querySelectorAll('.m-crumbs a[data-z]')].pop();if(!a)return false;a.click();return true;}
function mapStatus(){
  const el=PANEL_EL.map;if(!el)return;const st=$('.m-stat',el),cv=$('canvas',el),h=MAP.hover&&(cv._rects||[]).find(q=>q.id===MAP.hover);
  if(!h){st.textContent=MAP_HINT;return;}const n=h.node,c=h.cpu;
  const path=h.path.split(' › ').filter((s,i,a)=>!i||s!==a[i-1]).join(' › '); // «WizTree › WizTree» → «WizTree»
  const pv=MAP.total>0?h.v/MAP.total*100:null;
  const pct=pv!=null?` · ${pv<.1?'<0.1 %':fmtPct(pv)} ${S.map.root?`of “${esc(MAP.rootLabel)}”`:'of everything'}`:'';
  /* an “N more” tile — what is in it; a group tile — that the PID is only the main process’s, the size includes children */
  const cnt=h.rest&&[...h.rest.reduce((m,s)=>m.set(s,(m.get(s)||0)+1),new Map())].map(([s,c])=>c>1?`${s} ×${c}`:s); // “svchost ×12”, not twelve times
  const what=h.short?` · starts ${esc(h.short.join(', ')||'processes')} — each lives less than a second, so they are not in the list`
    :h.done?' · processes of this app that already exited during the period, and short-lived launches'
    :h.unseen?' · interrupts, drivers and processes that exited before the sample':h.rest?` · ${esc(cnt.slice(0,6).join(', '))}${cnt.length>6?'…':''}`
    :h.procs>1?(h.own?` · ${esc(n.exe)} · PID ${n.pid} and ${h.procs-1} ${plural(h.procs-1,'child','children','children')}`:` · ${h.procs} ${plural(h.procs,'process','processes','processes')}`)
    :n?` · ${esc(n.exe)} · PID ${n.pid}`:'';
  setHTML(st,`<b>${esc(path)}${h.self?' · the process itself, without children':''}</b> — ${mapFmt(h.v)}${pct}${n&&!h.rest&&mapMetric()!=='cpu'?` · CPU ${fmtPct(c)}`:''}${what}`);
}
const MAP_HINT='Hover over a tile to see its path and size here · click — select · double-click — zoom in';
function mapHl(k){if(MAP.hl===k)return;MAP.hl=k;const el=PANEL_EL.map;if(el&&MAP.nodes&&!MAP.from&&!MAP.fade)mapFrames($('canvas',el),MAP.nodes,i=>MAP.nodes[i].r);}
function mapHover(id){if(MAP.hover===id)return;MAP.hover=id;const el=PANEL_EL.map;if(el&&MAP.nodes&&!MAP.from&&!MAP.fade)mapFrames($('canvas',el),MAP.nodes,i=>MAP.nodes[i].r);}
function hitMap(cv,e){const r=cv.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;const L=cv._rects||[];for(let i=L.length-1;i>=0;i--){const q=L[i];if(x>=q.x&&x<q.x+q.w&&y>=q.y&&y<q.y+q.h)return q;}return null;}
/* plan — the split into rows from the previous layout: [[how many tiles, along the width or not], …].
   With it a small change in values only slightly changes sizes instead of throwing tiles
   from row to row. The resulting split is returned in out.plan. */
function squarify(items,x,y,w,h,plan){
  const total=items.reduce((s,i)=>s+i.v,0);if(!total||w<1||h<1)return [];
  const sc=w*h/total;let rest=items.map(i=>({...i,a:i.v*sc})),R={x,y,w,h};const out=[],rows=[];let pi=0;
  const worst=(row,s)=>{let sum=0,mx=0,mn=Infinity;for(const r of row){sum+=r.a;mx=Math.max(mx,r.a);mn=Math.min(mn,r.a);}return Math.max(s*s*mx/(sum*sum),sum*sum/(s*s*mn));};
  while(rest.length){
    let i,horiz;
    if(plan&&pi<plan.length){i=Math.min(plan[pi][0],rest.length);horiz=plan[pi][1];pi++;}
    else{const s=Math.min(R.w,R.h);let row=[rest[0]];i=1;
      while(i<rest.length&&worst([...row,rest[i]],s)<=worst(row,s)){row.push(rest[i]);i++;}
      horiz=R.w>=R.h;}
    const row=rest.slice(0,i),sum=row.reduce((t,r)=>t+r.a,0);
    if(horiz){const cw=sum/Math.max(R.h,1e-9);let cy=R.y;for(const r of row){const hh=r.a/cw;out.push({...r,x:R.x,y:cy,w:cw,h:hh});cy+=hh;}R={x:R.x+cw,y:R.y,w:R.w-cw,h:R.h};}
    else{const rh=sum/Math.max(R.w,1e-9);let cx=R.x;for(const r of row){const ww=r.a/rh;out.push({...r,x:cx,y:R.y,w:ww,h:rh});cx+=ww;}R={x:R.x,y:R.y+rh,w:R.w,h:R.h-rh};}
    rows.push([i,horiz]);rest=rest.slice(i);
  }
  out.plan=rows;
  return out;
}
function mapTree(){
  const m=mapMetric(),eps=m==='net'?.001:m==='mem'?1:m==='cpu'?.02:.001;
  const gk=mapGpuKey(),long=m!=='mem'&&m!=='net'&&!gk&&S.range.ms>SPARKN*1000;
  /* for long periods — how much the app used over the period (from history) */
  let appAvg=null;
  if(long){const h=H('apps',BY[m],1000);if(h){appAvg=new Map();for(const s of h.series)appAvg.set(s.key,conv(m)(s.avg));}}
  /* a process’s CPU over a long period — how much CPU time it used during that time: a java started
     a minute ago is a minute of work, not “last 5 minutes × 3 hours” (a fresh process used to
     balloon to half the app right away, and its exit reshuffled the whole group) */
  const rangeS=S.range.ms/1000;
  /* a process older than the period — its lifetime average (CPU time / age): precise and steady,
     unlike the last 5 minutes (right after the engine starts that is still empty) */
  const rangeCpu=n=>{const age=Math.max(1,(NOW-(n.ct/1e4-11644473600000))/1000);return (n.cpuMs||0)/10/(Math.min(age,rangeS)*CPUS)*(age<=rangeS?Math.min(age,rangeS)/rangeS:1);};
  /* network — only through the selected adapter: otherwise a program’s traffic through the VPN and the same traffic at the VPN client
     (encrypted, over Wi-Fi) added up, and it looked as if the program bypassed the tunnel */
  const na=curRes().net,netOf=n=>{if(!na)return n.net;const x=n.netBy&&n.netBy[na.key];return x?x.rx+x.tx:0;};
  const own=n=>m==='mem'?n.mem:m==='gpu'?(gk?n[gk]||0:n.gpu):m==='net'?netOf(n):m==='cpu'&&long&&!PSEUDO[n.pid]?rangeCpu(n):ownAvg(n,m); /* interrupts and DPC have no create time and no accumulated CPU — only history */
  /* you can zoom into a process (id “pid:time”) or an app group (“a…”, “mWIN”). Inside —
     exactly what was in the group on the overall map: processes of the same app. Programs started
     from it are their own groups (before, a 100 MB Explorer zoomed into a 3 GB tree of other programs) */
  const procRoot=S.map.root&&/^\d/.test(S.map.root);
  const mk=n=>{
    const kids=aliveKids(n).filter(k=>k.appKey===n.appKey).map(mk).filter(k=>k.v>eps);
    const o=own(n),lbl=mapName(n);
    if(!kids.length)return {key:'p'+n.id,label:lbl,v:o,node:n,cat:catOf(n)};
    return {key:'p'+n.id,label:lbl,v:o+kids.reduce((s,k)=>s+k.v,0),node:n,cat:catOf(n),kids:[{key:'s'+n.id,label:lbl,v:o,node:n,cat:catOf(n),self:1},...kids]};
  };
  if(procRoot){const r=NODES.get(S.map.root);if(alive(r))return mk(r);S.map.root=null;}
  const live=[...NODES.values()].filter(alive);
  const groups=new Map();
  for(const n of live){const k=n.appKey||n.exe;if(!groups.has(k))groups.set(k,[]);if(!n.parent||n.parent.appKey!==n.appKey)groups.get(k).push(n);}
  const scaleTree=(t,f)=>{t.v*=f;if(t.kids)t.kids.forEach(k=>scaleTree(k,f));};
  let apps=[...groups.entries()].map(([k,tops])=>{
    const kids=tops.map(mk).filter(x=>x.v>eps||appAvg);let v=kids.reduce((s,x)=>s+x.v,0);
    const a=APPS.get(k),root=tops.find(t=>a&&t.pid===a.rootPid)||tops[0];
    let gone=0;
    if(appAvg){const target=appAvg.get(k)||0;
      /* CPU: what the app used over the period beyond its live processes — already exited and short-lived
         processes, as a tile of their own. Stretching the live processes over it would lie about their share */
      if(m==='cpu'&&v<=target)gone=target-v;
      else if(v>0){const f=target/v;kids.forEach(x=>scaleTree(x,f));}else if(target>0&&kids.length){kids.forEach(x=>scaleTree(x,0));kids[0].v=target;}v=target;}
    const flat=kids.filter(x=>x.v>eps);
    if(gone>eps)flat.push({key:'z'+k,label:'exited and short-lived processes',v:gone,rep:root,cat:root?catOf(root):'other',done:1});
    if(m==='cpu'&&!long){const sv=shortAvg(k,mapSecs());if(sv>eps){const sa=APPS.get(k);flat.push({key:'x'+k,label:'short-lived processes',v:sv,rep:root,cat:root?catOf(root):'other',short:sa?sa.spawnNames:[]});v+=sv;}}
    return {key:'a'+k,label:mapLabel(a?a.title:k),v,kids:flat,node:flat.length===1?flat[0].node:null,rep:root,cat:root?catOf(root):'other',zoomId:'a'+k};
  });
  /* a zoomed-in app does not jump back to the overall view when it goes quiet (in CPU mode) */
  if(S.map.root&&!procRoot){const g=apps.find(a=>a.key===S.map.root);if(g&&g.kids&&g.kids.length)return g;}
  apps=apps.filter(a=>a.v>eps);
  if(m==='cpu'&&!long){const un=shortAvg('',mapSecs());if(un>eps)apps.push({key:'mUNSEEN',label:'Not attributed to processes',v:un,cat:'system'});}
  if(m==='mem'){
    /* used but not owned by any single process — split into parts, not one grey tile */
    const parts=memParts().filter(p=>p.v>=1).map(p=>({key:'m'+p.label,label:p.label,v:p.v,cat:'system'}));
    const v=parts.reduce((s,p)=>s+p.v,0);
    if(v>0)apps.push(parts.length>1?{key:'mWIN',label:'Windows outside processes',v,cat:'system',kids:parts,zoomId:'mWIN'}:{...parts[0],label:'Kernel, drivers and Windows caches'});
  }
  if(S.map.root){const g=apps.find(a=>a.key===S.map.root);if(g&&g.kids)return g;S.map.root=null;}
  /* program key → readable name for the legend (“IntelliJ IDEA”, not “idea64”) */
  MAP.exeName=new Map();
  for(const [k,tops] of groups){const a=APPS.get(k);if(!a)continue;const r=tops.find(t=>t.pid===a.rootPid)||tops[0];
    if(r&&INFO.has(r.id)){const e=mapExe({node:r});if(!MAP.exeName.has(e))MAP.exeName.set(e,mapLabel(a.title));}}
  for(const n of live)if(INFO.has(n.id)){const e=mapExe({node:n});if(!MAP.exeName.has(e))MAP.exeName.set(e,mapName(n));} // as on the tiles: “OpenJDK Platform binary”, not “java”
  return {key:'root',label:'All',v:apps.reduce((s,a)=>s+a.v,0),kids:apps};
}
/* “By program” — like file types in WizTree: every program has its own color.
   - The color belongs to the program (exe). Roles of one program (renderer, GPU process, Claude Code) get the same
     color lighter or darker: Brave does not eat five colors, and roles inside the app stay distinguishable.
   - The palette is 14 colors of similar lightness (they neither sink into the dark background nor glare),
     any two differ noticeably (ΔE ≥ 22; the old palette had pairs with ΔE 14).
   - The color is pinned to the program and kept between runs: zooming, switching the resource, leaving
     the tab and restarting do not change it. It is handed out by the program’s weight smoothed over minutes across the whole
     system (memory share + CPU share) — instant CPU reshuffled the ranking every second.
     It is taken away only from a program that has been out of the top 14 for more than 10 minutes, and only for a new big one.
   - Windows processes and components and memory outside processes are a cool grey, programs that
     did not get a color are a warm grey: the two greys are not confused. */
const EXE_PAL=['#fb7188','#d15228','#e98b11','#9d7b0b','#a3af0f','#3c9729','#28c091','#129390','#2bb6d6','#1687cd','#819ffc','#8966d9','#d37de5','#c44d95'];
/* role lightness is constant: renderers (a browser has dozens) are noticeably lighter, GPU noticeably darker,
   other helpers slightly darker; the process itself is the base color */
const ROLE_F={'Renderer':1.3,'Extension':1.15,'GPU process':.72,'Node.js':.78},ROLE_OTHER=.92;
const WIN_EXE=new Set(['msmpeng.exe','nissrv.exe','mpdefendercoreservice.exe','securityhealthservice.exe','securityhealthsystray.exe','smartscreen.exe','searchindexer.exe','searchhost.exe','searchprotocolhost.exe','searchfilterhost.exe']);
const SLATE=[84,92,106],WARM=[120,114,106];
/* grey keys: 'w:' Windows, 'k:' memory outside processes, 'r:' an “N more” tile, '?' — no info yet.
   Prefixes only: program names starting with w and k (WizTree, Windows Terminal, KeePass) are ordinary programs */
const greyKey=k=>k[0]==='?'||k.includes(':');
const COLOR_KEY='tm-map-colors2';
/* saved data: c — program → [color, when it was last big];
   broken and duplicate entries are dropped */
const COLORS=(()=>{let o={};try{o=JSON.parse(localStorage.getItem(COLOR_KEY)||'{}')||{};}catch(e){}
  const c={},seen=new Set();
  for(const [k,v] of Object.entries(o.c||{}).sort((p,q)=>((q[1]||[])[1]||0)-((p[1]||[])[1]||0))){
    if(!Array.isArray(v)||!Number.isInteger(v[0])||v[0]<0||v[0]>=EXE_PAL.length||seen.has(v[0])||greyKey(k))continue;
    seen.add(v[0]);c[k]=[v[0],+v[1]||0];}
  return c;})();
const SEEN=new Map();let colorsInit=false,colorsDirty=false,colorsSeq=-1,colorsAt=0;const W_EMA=new Map();
const saveColors=()=>{colorsDirty=false;try{localStorage.setItem(COLOR_KEY,JSON.stringify({c:COLORS}));}catch(e){}};
addEventListener('pagehide',()=>{if(colorsDirty)saveColors();});
setInterval(()=>{if(colorsDirty)saveColors();},30e3);
const hashN=s=>{let h=0;for(let i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))|0;return Math.abs(h);};
function updateExeColors(){
  if(colorsSeq===SEQ)return;colorsSeq=SEQ;
  const mem=new Map(),cpu=new Map();let mt=0,ct=0,changed=false;
  for(const n of NODES.values()){
    if(!alive(n)||!INFO.has(n.id))continue;const k=mapExe({node:n});if(greyKey(k))continue;
    mem.set(k,(mem.get(k)||0)+(n.mem||0));cpu.set(k,(cpu.get(k)||0)+(n.cpu||0));mt+=n.mem||0;ct+=n.cpu||0;
  }
  const now=Date.now(),a=colorsAt?1-Math.exp(-(now-colorsAt)/180e3):1;colorsAt=now;
  for(const k of mem.keys()){const w=(mt?mem.get(k)/mt:0)+cpu.get(k)/Math.max(ct,25),p=W_EMA.get(k);/* CPU relative to at least 25 % of the machine: when idle, 0.5 % of a background service does not weigh as much as gigabytes */W_EMA.set(k,p==null?(colorsInit?w*a:w):p+(w-p)*a);if(!SEEN.has(k))SEEN.set(k,colorsInit?now:0);}
  for(const k of SEEN.keys())if(!mem.has(k))SEEN.delete(k);colorsInit=true; // a new program gains weight gradually: a build spike does not steal colors
  for(const [k,p] of W_EMA)if(!mem.has(k)){const q=p*(1-a);if(q<1e-4)W_EMA.delete(k);else W_EMA.set(k,q);}
  const rank=[...W_EMA.keys()].sort((p,q)=>W_EMA.get(q)-W_EMA.get(p)),N=EXE_PAL.length,near=new Set(rank.slice(0,N));
  for(const k of near)if(COLORS[k]&&COLORS[k][1]<now-60e3){COLORS[k][1]=now;colorsDirty=true;} // time — saved later
  const liveE=new Set();for(const n of NODES.values())if(alive(n))liveE.add(n.exe.toLowerCase());
  rank.slice(0,N).forEach((k,r)=>{
    if(COLORS[k])return;
    const used=new Set(Object.values(COLORS).map(v=>v[0]));let idx=EXE_PAL.findIndex((c,i)=>!used.has(i));
    if(idx<0){/* the palette is full — take it from the one that has been out of the top 14 the longest, but not sooner than after 10 minutes.
       A big program (top half of the ranking) gets it right away, from the smallest outside the top 14: otherwise WizTree
       at a gigabyte stayed grey while Docker at 50 MB held the color */
      const out=Object.entries(COLORS).filter(([q])=>!near.has(q)&&(W_EMA.has(q)||!liveE.has(q))),wt=q=>W_EMA.get(q)||0;
      const old=r<N/2&&now-(SEEN.has(k)?SEEN.get(k):now)>120e3?out.sort((p,q)=>wt(p[0])-wt(q[0])||p[1][1]-q[1][1])[0]:out.filter(([,v])=>now-v[1]>600e3).sort((p,q)=>p[1][1]-q[1][1])[0];
      if(!old)return;idx=old[1][0];delete COLORS[old[0]];}
    COLORS[k]=[idx,now];changed=true;
  });
  if(changed)saveColors(); // a handed-out color is saved right away — otherwise it could change after a restart
}
/* role from the command line: “Renderer (tab or window)” → “Renderer” */
const roleKind=n=>{const i=INFO.get(n.id);return i&&i.role?i.role.replace(/\s*\(.*$/,'').trim():'';};
/* the map label is shorter than in the table: the explanation in parentheses does not fit and repeats on dozens of tiles */
const mapLabel=s=>s.replace(/\s*\([^)]*\)\s*$/,'')||s;
/* program key — the exe; Windows processes and components — 'w:' (a service’s conhost is grey, a terminal’s conhost has
   the program’s color), memory outside processes — 'k:', a process with no info yet (the first second) — '?' (grey for now) */
const mapExe=m=>{if(m.rest)return 'r:'+m.key;const n=m.node||m.rep;if(!n)return 'k:'+m.key;const e=n.exe.toLowerCase();if(!INFO.has(n.id))return '?'+e;
  return catOf(n)==='system'||WIN_EXE.has(e)?'w:'+e:e;};
const exeTitle=k=>k.replace(/\.exe$/,'');
function progRGB(m){
  const k=mapExe(m),d=hashN(m.key)%11-5;
  if(m.rest){const g=m.restOf&&progRGB(m.restOf);return g&&m.restOf.key!=='root'?g.map(v=>v*.62+30):WARM.map(v=>v+d);} // “N more” — a muted group color
  if(k.startsWith('w:')||k.startsWith('k:'))return SLATE.map(v=>v+d);
  const c=COLORS[k];if(!c||!EXE_PAL[c[0]])return WARM.map(v=>v+d);
  const rgb=hexRGB(EXE_PAL[c[0]]),n=m.node||m.rep,role=n?roleKind(n):'',f=role?ROLE_F[role]||ROLE_OTHER:1;
  return rgb.map(v=>f>1?v+(255-v)*(f-1)*1.4:v*f);
}
/* program sizes in the current view — for the legend */
function exeTotals(nodes){const tot=new Map(),add=m=>{if(m.rest)return m.items.forEach(add);const k=mapExe(m);tot.set(k,(tot.get(k)||0)+(m.raw||0));};
  for(const n of nodes)if(!n.head)add(n.m);MAP.exeTot=tot;}
const mapId=n=>n.key+(n.head?'#':'');
const heatRGB=c=>{const t=clamp(c/12,0,1);const a=[58,74,92],b=[201,162,39],d=[224,83,61];return t<.5?a.map((v,i)=>v+(b[i]-v)*t*2):b.map((v,i)=>v+(d[i]-v)*(t-.5)*2);};
const heat=c=>`rgb(${heatRGB(c).map(Math.round).join(',')})`;
const hexRGB=h=>{const n=parseInt(h.slice(1),16);return [n>>16,n>>8&255,n&255];};
/* Cushions (SequoiaView / WinDirStat), but every tile has its own soft one: the parents’ bulges
   do not add up — otherwise a big tile became a glowing ball with black corners,
   and small ones at the group edge drowned in shadow. The tile color holds up to the very edge. */
const CUSH={H:.3,IA:.34,BR:1.12,L:(()=>{const l=Math.hypot(-1,-1,10);return [-1/l,-1/l,10/l];})()};
function addRidge(r,s,h){const h4=4*h,wf=h4/r.w,hf=h4/r.h;s[2]+=wf*(r.x*2+r.w);s[0]-=wf;s[3]+=hf*(r.y*2+r.h);s[1]-=hf;}
/* The map is rebuilt on every sample, but calmly:
   - values are smoothed over time (τ ≈ 3 s) — a load spike does not reshuffle the layout;
   - a new tile grows from zero, and the tile of an exited process (a “ghost”) shrinks to zero —
     short-lived processes (git, cmd from Claude Code) do not yank their neighbours;
   - tile order is “sticky”: neighbours swap only when one gets 40 % ahead of the other;
   - the split into rows comes from the previous layout even if the set of tiles changed: leaving tiles
     are removed from their rows, new ones go to the end — before, any new small tile reshuffled the whole group;
   - the new layout flows from the old one over 0.45 s; shifts under 4 px are not redrawn.
   Cushions are computed per pixel into a separate canvas, and headers, labels and the selection frame
   are drawn on top — a click on a tile responds immediately, without recomputing pixels. */
const MAP={sig:'',seq:-1,at:0,sm:new Map(),ghost:new Map(),order:new Map(),nodes:null,from:null,t0:0,raf:0,last:0,off:document.createElement('canvas')};
const MAP_ANIM=450,MAP_TAU=3000,MAP_HDR=18,MAP_DEAD=4,MAP_GHOST_TAU=450,MAP_FADE=280;
const easeOut=t=>1-Math.pow(1-t,3);
function mapLayout(w,h){
  const root=mapTree(),now=performance.now(),first=!MAP.sm.size;
  /* load jumps more than memory — smooth it longer; an average over hours should not “breathe” every second at all */
  const tau=mapMetric()==='mem'?MAP_TAU:S.range.ms>SPARKN*1000?20000:2*MAP_TAU;
  const dt=first?0:Math.max(0,now-MAP.at),a=first?1:1-Math.exp(-dt/tau);MAP.at=now;
  /* the ghost of an exited process fades in 1–2 samples, not by the smoothing of live tiles: with τ 3–6 s
     a big tile shrank for ~15 s, its children dropped out of view one by one, and the layout jumped every second */
  const ag=1-Math.exp(-dt/MAP_GHOST_TAU);
  const sm=new Map(),byKey=new Map(),par=new Map();
  const smooth=(m,pk)=>{const p=MAP.sm.has(m.key)?MAP.sm.get(m.key):m.self?MAP.sm.get('p'+m.key.slice(1)):undefined;m.raw=m.v;m.v=p!=null?p+(m.v-p)*a:first?m.v:m.v*a;
    sm.set(m.key,m.v);byKey.set(m.key,m);if(pk)par.set(m.key,pk);if(m.kids)m.kids.forEach(k=>smooth(k,m.key));};
  smooth(root);
  /* ghosts: tiles no longer in the data shrink in their old place until they are below 0.1 % */
  const ghost=new Map(),floor=(root.v||1)*1e-3;
  for(const [k,g] of [...MAP.ghost,...[...(MAP.byKey||new Map())].filter(([k])=>!MAP.ghost.has(k))]){
    if(byKey.has(k)||k==='root')continue;const pk=g.pk||MAP.par&&MAP.par.get(k),parent=pk&&byKey.get(pk),p=MAP.sm.get(k);
    if(!parent||!parent.kids||p==null)continue;const v=p*(1-ag);if(v<floor)continue;
    const t=g.t||{key:k,label:g.label,node:g.node,rep:g.rep,cat:g.cat,self:g.self,raw:0};
    const item={...t,v,raw:0,ghost:1};parent.kids.push(item);sm.set(k,v);ghost.set(k,{t,pk});}
  MAP.sm=sm;MAP.ghost=ghost;MAP.byKey=new Map([...byKey].map(([k,m])=>[k,{label:m.label,node:m.node,rep:m.rep,cat:m.cat,self:m.self}]));MAP.par=par;
  const order=new Map();
  const sticky=(pk,kids)=>{
    const prev=MAP.order.get(pk),idx=new Map((prev||[]).map((k,i)=>[k,i]));
    const l=kids.filter(k=>k.v>0).sort((x,y)=>{const i=idx.get(x.key),j=idx.get(y.key);return i!=null&&j!=null?i-j:i!=null?-1:j!=null?1:y.v-x.v;});
    for(let i=1;i<l.length;i++)for(let j=i;j>0;j--){
      const known=idx.has(l[j].key)&&idx.has(l[j-1].key);
      if(l[j].ghost||l[j-1].ghost)break; // a shrinking “ghost” is not overtaken — otherwise the whole group was rearranged
      if(l[j].v>l[j-1].v*(known?(S.range.ms>SPARKN*1000&&mapMetric()!=="mem"?2:1.4):1)){ /* average over hours: neighbours swap only if one is twice as big */const t=l[j];l[j]=l[j-1];l[j-1]=t;}else break;
    }
    order.set(pk,l.map(k=>k.key));return l;
  };
  /* a tile appears from ~40 square pixels (≈6×6) and disappears only below ~16 (≈4×4) */
  const shown=new Set(),was=MAP.shown||new Set();
  const visible=(items,area)=>{const tot=items.reduce((s,k)=>s+k.v,0);if(!tot)return items;const f=area/tot;
    return items.filter(k=>{const a=k.v*f;return a>=40||(was.has(k.key)&&a>=16);});};
  /* small things that did not fit are collected into an “N more” tile (N ≥ 2; a single one is drawn itself) — otherwise
     the other tiles would stretch into its place and stop being proportional */
  const visibleRest=(m,items,area,drop)=>{const l=visible(items,area).filter(k=>!drop||!drop.has(k.key));if(l.length===items.length)return l;
    const ls=new Set(l),rest=items.filter(k=>!ls.has(k)),v=rest.reduce((s,k)=>s+k.v,0),raw=rest.reduce((s,k)=>s+(k.raw||0),0);
    const tot=items.reduce((s,k)=>s+k.v,0),big=!l.length||v*area/tot>=16;
    if(rest.length===1){if(big)l.push(rest[0]);}
    else if(big)l.push({key:m.key+'~rest',label:`${rest.length} more`,v,raw,cat:'other',rest:1,restOf:m,items:rest});
    return l;};
  /* the previous layout plan for a new set of tiles: leaving ones are removed from their rows, new ones go to the end */
  const adapt=(old,keys)=>{
    const ok=old.keys.split('\n'),set=new Set(keys),surv=ok.filter(k=>set.has(k));
    if(!surv.length)return null; // the order may have changed — the rows stay the same, just with different neighbours
    const plan=[];let i=0;for(const [c,hz] of old.plan){let s=0;for(let j=0;j<c;j++,i++)if(set.has(ok[i]))s++;if(s)plan.push([s,hz]);}
    return plan;};
  const plans=new Map(),oldPlans=MAP.plans||new Map();
  const aspect=q=>Math.max(q.w/Math.max(q.h,1e-9),q.h/Math.max(q.w,1e-9));
  const sq=(pk,items,x,y,W,H)=>{
    const ks=items.map(k=>k.key),keys=ks.join('\n'),old=oldPlans.get(pk);
    const plan=old?(old.keys===keys?old.plan:adapt(old,ks)):null;
    let out=plan?squarify(items,x,y,W,H,plan):null;
    /* the old plan is rejected only if it produced a very elongated tile (1:12) or a strip: re-laying from scratch moved the whole group by hundreds of pixels */
    if(!out||out.some(q=>aspect(q)>12&&q.w*q.h>400||(q.w<3||q.h<3)&&!q.rest))out=squarify(items,x,y,W,H);
    plans.set(pk,{keys,plan:out.plan||[]});return out;
  };
  /* a strip thinner than 3 px (sometimes under a pixel) gave a double grid line — such tiles go
     into “N more”; if that one also comes out as a strip — its neighbours split its place */
  const place=(pk,m,items,x,y,W,H)=>{
    let l=visibleRest(m,items,W*H),out=sq(pk,l,x,y,W,H);
    const thin=q=>{const t=q.self?6:3;return q.w<t||q.h<t;}; // “itself” thinner than 6 px (a cmd wrapper around java) — the group collapses into the child
    if(out.some(q=>thin(q)&&!q.rest)){l=visibleRest(m,items,W*H,new Set(out.filter(q=>thin(q)&&!q.rest).map(q=>q.key)));out=sq(pk,l,x,y,W,H);}
    if(out.some(thin)&&out.length>1){const d=new Set(out.filter(thin).map(q=>q.key));const l2=l.filter(k=>!d.has(k.key));if(l2.length)out=sq(pk,l2,x,y,W,H);}
    return out.filter(q=>q.w>=1&&q.h>=1);
  };
  const nodes=[];
  const lay=(m,r,path,depth,parent,pre)=>{
    if(r.w<1||r.h<1)return;
    const p=path?path+' › '+m.label:m.label,i=nodes.length;shown.add(m.key);
    /* a grid without gaps: every tile and header owns only its right and bottom line
       of 1 pixel — exactly one line between any neighbours. A header only if the children keep
       at least 60×24 px: above 15 px tall tiles it would be thicker than they are */
    const W=r.w,H=r.h-MAP_HDR,out=m.kids&&r.w>60&&r.h>MAP_HDR+24?place(m.key,m,sticky(m.key,m.kids),r.x,r.y+MAP_HDR,W,H):null;
    if(out&&out.length>1){
      nodes.push({key:m.key,r:{x:r.x,y:r.y,w:r.w,h:r.h},m,head:1,depth,parent,path:p});
      for(const q of out)lay(q,q,p,depth+1,i);
    }else if(out&&out.length===1&&!out[0].self&&!out[0].rest){
      /* a single child tile is visible — draw it (label, color, PID of the child): “winlogon 307 MB” was really dwm */
      lay(out[0],r,p,depth,parent,pre||(depth===0&&out[0].label!==m.label?m.label:'')); // label “Claude · GPU process”
    }else nodes.push({key:m.key,r:{x:r.x,y:r.y,w:r.w,h:r.h},m,depth,parent,path:p,pre});
  };
  /* a zoomed-in group fills the whole map without its own header — its name is already in the crumbs */
  const zr=S.map.root&&NODES.get(S.map.root),za=zr&&APPS.get(zr.appKey);
  const base=S.map.root?[...(za?[mapLabel(za.title)]:[]),...(zr?ancestors(zr).filter(x=>x.appKey===zr.appKey).map(x=>mapLabel(nameOf(x))):[]),root.label].filter((s,i,arr)=>!i||s!==arr[i-1]).join(' › '):'';
  if(root.kids){
    const top=sticky('root',root.kids);
    /* memory outside processes goes to the end (bottom right), not to the most visible top-left corner */
    if(!S.map.root){const i=top.findIndex(k=>k.key[0]==='m');if(i>=0)top.push(top.splice(i,1)[0]);}
    for(const q of place('root',root,top,1,1,w-1,h-1))lay(q,q,base,0,-1);
  }else lay(root,{x:1,y:1,w:w-1,h:h-1},base,0,-1);
  MAP.order=order;MAP.shown=shown;MAP.plans=plans;MAP.rootLabel=root.label;MAP.total=root.raw;
  return nodes;
}
/* the node’s rectangle now: during an animation — between the old and the new position */
function mapRectFn(nodes){
  if(!MAP.from)return i=>nodes[i].r;
  const e=easeOut(clamp((performance.now()-MAP.t0)/MAP_ANIM,0,1)),F=MAP.from;
  return i=>{const a=F[i],b=nodes[i].r;return {x:a.x+(b.x-a.x)*e,y:a.y+(b.y-a.y)*e,w:a.w+(b.w-a.w)*e,h:a.h+(b.h-a.h)*e};};
}
/* cushions — per pixel, into a separate canvas; scale < 1 — draft quality during an animation.
   The tile’s right and bottom pixel is a dark border: neighbouring tiles are separated by exactly one
   sharp line (like in WizTree), even if they have the same color. */
const MAP_LINE=0xff121212; // color of all grid lines (ABGR)
/* A tile’s cushion depends only on the point’s position inside it (u, v from 0 to 1), not on the size:
   normal nx = 4H·(2u−1), ny = 4H·(2v−1). So it is computed once into two 128×128 textures, and
   every tile is a color fill with the textures on top, stretched by the GPU: “multiply” by min(I, 1)
   darkens, “color-dodge” by 1 − 1/I adds brightness in the center where I > 1. Together that is
   exactly color × I clamped at 255 at the end, as in the old per-pixel computation.
   Before, every frame computed lighting for every map pixel: 12 ms at 0.4 Mpx, 40–50 ms on
   a big screen — the animation took the whole thread and the window dropped frames. */
const [CUSH_MUL,CUSH_DODGE]=(()=>{const N=128,mk=()=>{const c=document.createElement('canvas');c.width=c.height=N;return c;},M=mk(),D=mk();
  const xm=M.getContext('2d'),xd=D.getContext('2d'),im=xm.createImageData(N,N),id=xd.createImageData(N,N),[Lx,Ly,Lz]=CUSH.L,h4=4*CUSH.H;
  for(let j=0;j<N;j++){const ny=h4*(2*(j+.5)/N-1);for(let i=0;i<N;i++){const nx=h4*(2*(i+.5)/N-1);
    let ca=(nx*Lx+ny*Ly+Lz)/Math.sqrt(nx*nx+ny*ny+1);if(ca<0)ca=0;const I=(CUSH.IA+(1-CUSH.IA)*ca)*CUSH.BR,o=(j*N+i)*4;
    im.data[o]=im.data[o+1]=im.data[o+2]=Math.round(Math.min(I,1)*255);im.data[o+3]=255;
    id.data[o]=id.data[o+1]=id.data[o+2]=Math.round(Math.max(0,1-1/I)*255);id.data[o+3]=255;}}
  xm.putImageData(im,0,0);xd.putImageData(id,0,0);return [M,D];})();
function mapPaint(cv,nodes,rect){
  const w=cv.clientWidth,h=cv.clientHeight,k=devicePixelRatio||1;
  const PW=Math.max(1,Math.round(w*k)),PH=Math.max(1,Math.round(h*k)),off=MAP.off;
  if(off.width!==PW||off.height!==PH){off.width=PW;off.height=PH;}
  const x=off.getContext('2d');MAP.draft=false;
  x.setTransform(1,0,0,1,0,0);x.globalCompositeOperation='source-over';x.imageSmoothingEnabled=true;
  x.fillStyle='#121212';x.fillRect(0,0,PW,PH); // color of all grid lines
  const bw=Math.max(1,Math.round(k));
  const tiles=[];
  for(let i=0;i<nodes.length;i++){
    const n=nodes[i];if(n.head)continue;const r=rect(i);
    const x0=Math.max(0,Math.round(r.x*k)),x1=Math.min(PW,Math.round((r.x+r.w)*k)),y0=Math.max(0,Math.round(r.y*k)),y1=Math.min(PH,Math.round((r.y+r.h)*k));
    /* the tile’s right and bottom pixel is a grid line (per axis separately: a thin strip does not merge with its neighbour) */
    const xe=x1-x0>bw?x1-bw:x1,ye=y1-y0>bw?y1-bw:y1;if(xe<=x0||ye<=y0)continue;
    x.fillStyle=`rgb(${n.rgb[0]},${n.rgb[1]},${n.rgb[2]})`;x.fillRect(x0,y0,xe-x0,ye-y0);
    tiles.push(x0,y0,xe-x0,ye-y0);
  }
  x.globalCompositeOperation='multiply';
  for(let i=0;i<tiles.length;i+=4)x.drawImage(CUSH_MUL,tiles[i],tiles[i+1],tiles[i+2],tiles[i+3]);
  x.globalCompositeOperation='color-dodge';
  for(let i=0;i<tiles.length;i+=4)x.drawImage(CUSH_DODGE,tiles[i],tiles[i+1],tiles[i+2],tiles[i+3]);
  x.globalCompositeOperation='source-over';
}
const MAP_HEAD=['#262626','#323232','#3e3e3e','#4a4a4a']; // step of 12 — neighbouring levels are distinguishable by eye
/* text that does not fit the width gets an ellipsis instead of being cut mid-letter */
const FIT=new Map(); // fitted strings: label·width·font → text (otherwise thousands of measureText per animation frame)
function fitText(x,t,w){w=Math.floor(w/4)*4;const key=t+''+w+''+x.font,c=FIT.get(key);if(c!=null)return c;
  let r=t;if(x.measureText(t).width>w){const s=Array.from(t);let lo=0,hi=s.length; // by characters, not UTF-16: an emoji is not cut in half
    while(lo<hi){const mid=(lo+hi+1)>>1;if(x.measureText(s.slice(0,mid).join('')+'…').width<=w)lo=mid;else hi=mid-1;}
    r=lo?s.slice(0,lo).join('').trimEnd()+'…':'';}
  if(FIT.size>4000)FIT.clear();FIT.set(key,r);return r;}
/* white or near-black text — whichever contrasts more (WCAG) on this tile; brightness “by eye” got pink wrong */
const relLum=c=>c.reduce((s,v,i)=>{v/=255;v=v<=.03928?v/12.92:((v+.055)/1.055)**2.4;return s+v*[.2126,.7152,.0722][i];},0);
const darkText=c=>{const L=relLum(c.map(v=>Math.min(255,v*1.08)));return (L+.05)/.0556>1.05/(L+.05);};
/* on top of the cushions: group headers, labels, selection and hover frames.
   Everything is drawn in physical pixels with integer coordinates — lines do not blur into half-pixels. */
/* tile label: name and size. The size matters most: if the name does not fit, the name is shortened and the number stays.
   - Two lines (name, size below it) from 40×30, one line “name size” from 24×14.
   - A narrow tall tile (a column 30–60 px wide) gets the label along its long side, bottom to top, like on
     a book spine: across it only three letters and no number fit. */
function mapTileLabel(x,n,q,r,dpr,pad,L){
  const m=n.m,name=m.self?`${m.label} · itself`:n.pre?`${n.pre} · ${m.label}`:m.label,val=mapFmt(m.raw);
  const lines=(a,b)=>a>=40&&b>=30?2:a>=24&&b>=14?1:0;
  const lh=lines(r.w,r.h),lv=lines(r.h,r.w);
  let vert=lv>lh;
  if(!vert&&lv===lh&&lh&&r.h>r.w*1.6){const need=x.measureText(lh===2?name:name+' '+val).width;vert=need>q.w-2*pad-L&&q.h>q.w;}
  const lvl=vert?lv:lh;if(!lvl)return;
  const lt=darkText(n.rgb);
  x.save();
  let bx=q.x,by=q.y,bw=q.w,bh=q.h;
  if(vert){x.translate(q.x,q.y+q.h);x.rotate(-Math.PI/2);bx=0;by=0;bw=q.h;bh=q.w;}
  const mw=bw-2*pad-L,x0=bx+pad+L,vw=x.measureText(val).width,gap=Math.round(5*dpr);
  const main=lt?'#111':'#fff',second=lt?'rgba(0,0,0,.72)':'rgba(255,255,255,.85)';
  x.fillStyle=main;if(!lt&&!MAP.from){x.shadowColor='rgba(0,0,0,.85)';x.shadowBlur=3*dpr;} // no shadow in animation frames — too expensive
  if(lvl===2){
    x.fillText(fitText(x,name,mw),x0,by+Math.round(12*dpr));
    if(vw<=mw){x.fillStyle=second;x.fillText(val,x0,by+Math.round(27*dpr));}
  }else{
    const cy=by+bh/2;
    if(x.measureText(name).width+gap+vw<=mw){x.fillText(name,x0,cy);x.fillStyle=second;x.fillText(val,x0+x.measureText(name).width+gap,cy);}
    else{const nm=mw-vw-gap>=28*dpr?fitText(x,name,mw-vw-gap):'';
      if(nm){x.fillText(nm,x0,cy);x.fillStyle=second;x.fillText(val,x0+x.measureText(nm).width+gap,cy);}
      else if(vw<=mw)x.fillText(val,x0,cy); // very narrow — just the number: the name shows on hover
      else x.fillText(fitText(x,name,mw),x0,cy);}
  }
  x.restore();
}
/* cushions + headers + labels go into a separate MAP.base layer; hover redraws only the frames */
function mapCompose(cv,nodes,rect){
  const dpr=devicePixelRatio||1,w=cv.clientWidth,h=cv.clientHeight,PW=Math.round(w*dpr),PH=Math.round(h*dpr);
  const B=MAP.base||(MAP.base=document.createElement('canvas'));
  if(B.width!==PW||B.height!==PH){B.width=PW;B.height=PH;}
  const x=B.getContext('2d');
  x.setTransform(1,0,0,1,0,0);x.imageSmoothingEnabled=MAP.off.width!==PW;x.drawImage(MAP.off,0,0,PW,PH);
  const D=r=>{const x0=Math.round(r.x*dpr),y0=Math.round(r.y*dpr);return {x:x0,y:y0,w:Math.round((r.x+r.w)*dpr)-x0,h:Math.round((r.y+r.h)*dpr)-y0};};
  const HD=Math.round(MAP_HDR*dpr),L=Math.max(1,Math.round(dpr)),pad=Math.round(4*dpr);
  x.font=`${Math.round(12*dpr)}px "Segoe UI Variable Text","Segoe UI",sans-serif`;x.textBaseline='middle';
  for(let i=0;i<nodes.length;i++){
    const n=nodes[i],m=n.m;if(!n.head)continue;const r=rect(i),q=D(r);if(q.w<2||q.h<2)continue;
    /* the header ends where the children begin (at 125 % scale 18 px is not a whole number of pixels);
       like a tile, it leaves its right and bottom line to the background */
    const hb=Math.min(Math.round((r.y+MAP_HDR)*dpr)-q.y,q.h);
    /* nested levels are a shade lighter, so a stack of headers reads as nesting */
    x.fillStyle=MAP_HEAD[Math.min(n.depth,MAP_HEAD.length-1)];x.fillRect(q.x,q.y,q.w-L,hb-L);
    x.fillStyle='rgba(255,255,255,.9)';
    /* the group size is always visible: if the name does not fit, the name is shortened, not the number */
    const v=`(${mapFmt(m.raw)})`,vw=x.measureText(v).width,gap=Math.round(4*dpr),mw=q.w-2*pad,ty=q.y+(hb-L)/2+.5;
    const t1=`${m.label} ${v}`;
    if(x.measureText(t1).width<=mw)x.fillText(t1,q.x+pad,ty);
    else{const nm=mw-vw-gap>=24*dpr?fitText(x,m.label,mw-vw-gap):'';
      if(nm){x.fillText(nm,q.x+pad,ty);x.fillText(v,q.x+pad+x.measureText(nm).width+gap,ty);}
      else if(vw<=mw)x.fillText(v.slice(1,-1),q.x+pad,ty);}
  }
  for(let i=0;i<nodes.length;i++){
    const n=nodes[i];if(n.head)continue;const r=rect(i);if(Math.min(r.w,r.h)<14||Math.max(r.w,r.h)<24)continue;
    mapTileLabel(x,n,D(r),r,dpr,pad,L);
  }
  mapFrames(cv,nodes,rect);
}
/* selection and hover frames on top of the finished layer; the frame runs along the grid lines around the tile,
   not inside it (otherwise on the top-left it lay on the color and on the bottom-right on the line) */
function mapFrames(cv,nodes,rect){
  const B=MAP.base;if(!B)return;const dpr=devicePixelRatio||1,L=Math.max(1,Math.round(dpr));
  if(cv.width!==B.width||cv.height!==B.height){cv.width=B.width;cv.height=B.height;}
  const x=cv.getContext('2d');x.setTransform(1,0,0,1,0,0);x.drawImage(B,0,0);
  const D=r=>{const x0=Math.round(r.x*dpr),y0=Math.round(r.y*dpr),x1=Math.round((r.x+r.w)*dpr),y1=Math.round((r.y+r.h)*dpr);
    return {x:x0-L,y:y0-L,w:x1-x0+L,h:y1-y0+L};};
  const frame=(q,t,c)=>{x.fillStyle=c;x.fillRect(q.x,q.y,q.w,t);x.fillRect(q.x,q.y+q.h-t,q.w,t);x.fillRect(q.x,q.y,t,q.h);x.fillRect(q.x+q.w-t,q.y,t,q.h);};
  let sel=null,hov=null;
  for(let i=0;i<nodes.length;i++){const n=nodes[i],m=n.m;
    if(S.sel&&(m.node||m.rep)&&(m.node||m.rep).id===S.sel&&(!n.head||!sel))sel=D(rect(i));
    if(MAP.hover&&mapId(n)===MAP.hover)hov=D(rect(i)); // hovering a header outlines the whole group
    if(MAP.hl&&!n.head&&mapExe(m)!==MAP.hl){const q=D(rect(i));x.fillStyle='rgba(18,18,18,.62)';x.fillRect(q.x+L,q.y+L,q.w-L,q.h-L);}} // a program from the legend — the rest is dimmed
  if(sel)frame(sel,2*L,'#fff');
  if(hov)frame(hov,L,'rgba(255,255,255,.95)');
}
/* a tile appeared or disappeared — the structure is different, and geometry cannot be morphed (tiles would fly
   through each other with black holes). Before, the map jumped at this moment; now the old picture
   dissolves into the new one over 0.28 s */
function mapFadeStart(cv){
  const F=MAP.fadeCv||(MAP.fadeCv=document.createElement('canvas'));
  if(!cv.width||!cv.height)return;
  if(F.width!==cv.width||F.height!==cv.height){F.width=cv.width;F.height=cv.height;}
  const x=F.getContext('2d');x.setTransform(1,0,0,1,0,0);x.globalAlpha=1;x.drawImage(cv,0,0);MAP.fade=performance.now();
}
function mapFadeStep(){
  cancelAnimationFrame(MAP.fraf);
  const step=now=>{
    const el=PANEL_EL.map,nodes=MAP.nodes;if(!MAP.fade||!vis(el)||!nodes){MAP.fade=0;return;}
    const cv=$('canvas',el),t=(now-MAP.fade)/MAP_FADE;
    mapFrames(cv,nodes,i=>nodes[i].r);
    if(t>=1){MAP.fade=0;return;}
    const x=cv.getContext('2d'),F=MAP.fadeCv;
    if(F&&F.width===cv.width&&F.height===cv.height){x.globalAlpha=1-easeOut(clamp(t,0,1));x.drawImage(F,0,0);x.globalAlpha=1;}
    MAP.fraf=requestAnimationFrame(step);
  };
  MAP.fraf=requestAnimationFrame(step);
}
function mapAnimate(){
  cancelAnimationFrame(MAP.raf);
  const step=now=>{
    const el=PANEL_EL.map,nodes=MAP.nodes;if(!vis(el)||!nodes||!MAP.from){MAP.from=null;return;}
    const cv=$('canvas',el);
    if(now-MAP.t0>=MAP_ANIM){MAP.from=null;const r=i=>nodes[i].r;mapPaint(cv,nodes,r);mapCompose(cv,nodes,r);return;}
    /* frames have cushions, like the still map: flat frames for 0.45 s “switched off” the shadows on every shift
       (≈ 8 ms per frame at 1300×700) */
    {const r=mapRectFn(nodes);mapPaint(cv,nodes,r);mapCompose(cv,nodes,r);}
    MAP.raf=requestAnimationFrame(step);
  };
  MAP.raf=requestAnimationFrame(step);
}
/* header and legend come before measuring the canvas: their height must not change the map size after drawing */
/* legend items that did not fit become one “+N” with the full list in a tooltip */
function fitLegend(leg){
  if(leg._fitH===leg._h&&leg._fitW===leg.clientWidth)return;leg._fitH=leg._h;leg._fitW=leg.clientWidth;
  const old=leg.querySelector('.more');if(old)old.remove();const kids=[...leg.children];kids.forEach(k=>k.style.display='');
  const W=leg.clientWidth-parseFloat(getComputedStyle(leg).paddingRight),over=kids.filter(k=>k.offsetLeft+k.offsetWidth>W);if(!over.length)return;
  const room=W-70,hide=kids.filter(k=>k.offsetLeft+k.offsetWidth>room);hide.forEach(k=>k.style.display='none');
  const m=document.createElement('span');m.className='more';m.textContent=`+${hide.length}`;m.title=hide.map(k=>k.dataset.n||k.textContent).join('\n');leg.appendChild(m);}
function mapChrome(el){
  $('.m-color',el).querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.c===S.map.color));
  {const d=$('.m-desc',el),t=mapDesc();if(d.textContent!==t){d.textContent=t;d.title=t;}} // a long description gets an ellipsis — the full text is in the tooltip
  /* crumbs follow the map hierarchy: all › app › processes of this app */
  const zr=S.map.root&&/^\d/.test(S.map.root)&&NODES.get(S.map.root),r0=curRes(),crumb=(z,t,cur)=>`<span class="sep">›</span>${cur?`<span class="cur">${esc(t)}</span>`:`<a data-z="${esc(z)}">${esc(t)}</a>`}`;
  let cr='';
  if(zr){const app=APPS.get(zr.appKey),items=[];if(app)items.push(['a'+zr.appKey,mapLabel(app.title)]);
    for(const x of ancestors(zr).filter(x=>x.appKey===zr.appKey).concat([zr]))items.push([x.id,mapLabel(nameOf(x))]);
    const ded=items.filter((it,i)=>i===items.length-1||it[1]!==items[i+1][1]); // «Claude › Claude» → «Claude»
    cr=ded.map((it,i)=>crumb(it[0],it[1],i===ded.length-1)).join('');}
  else if(S.map.root)cr=crumb(S.map.root,MAP.rootLabel||'',true);
  setHTML($('.m-crumbs',el),`<a data-z="root">${esc(r0.name)} · all</a>`+cr);
  /* legend — all colored programs of this view by readable names (hover highlights their tiles)
     and the two greys separately; one line — the extra goes past the edge, the map height does not jump */
  const exeLeg=()=>{const t=MAP.exeTot||new Map(),rgb=c=>`rgb(${c.join(',')})`,nm=k=>(MAP.exeName&&MAP.exeName.get(k))||exeTitle(k);
    const top=[...t].filter(([k,v])=>COLORS[k]&&v>(MAP.total||0)*1e-3).sort((p,q)=>q[1]-p[1]),ks=[...t.keys()];
    const hasW=ks.some(k=>k.startsWith('w:')||k.startsWith('k:')),hasO=ks.some(k=>!/^[wkr]:/.test(k)&&!COLORS[k]);
    if(MAP.hl&&!t.has(MAP.hl))MAP.hl=null;
    return (hasW?`<span><i style="background:${rgb(SLATE)}"></i>Windows</span>`:'')+(hasO?`<span><i style="background:${rgb(WARM)}"></i>other programs</span>`:'')
      +top.map(([k,v])=>`<span class="lk" data-k="${esc(k)}" data-n="${esc(nm(k))} ${esc(mapFmt(v))}" title="${esc(k)} — all processes of the program, including in other groups"><i style="background:${EXE_PAL[COLORS[k][0]]}"></i>${esc(nm(k))} <span class="num">${mapFmt(v)}</span></span>`).join('');};
  setHTML($('.m-leg',el),S.map.color==='exe'?exeLeg():S.map.color==='cat'?Object.values(CATS).map(c=>`<span><i style="background:${c.c}"></i>${c.n}</span>`).join(''):
    `<span><i style="background:${heat(0)}"></i>idle</span><span><i style="background:${heat(6)}"></i>~6 % CPU</span><span><i style="background:${heat(12)}"></i>12 % and above</span><span><i style="background:rgb(${WARM.join(',')})"></i>not a process</span>`);
  fitLegend($('.m-leg',el));
}
/* force — the data changed without a new sample (the history for the period arrived) */
function renderMap(force){
  const el=PANEL_EL.map;if(!vis(el)||!SYS)return;
  if(S.map.root&&/^\d/.test(S.map.root)&&!alive(NODES.get(S.map.root)))S.map.root=null; // the zoomed-in process exited — straight back to the overall view
  mapChrome(el);
  const cv=$('canvas',el),w=cv.clientWidth,h=cv.clientHeight;if(!w||!h)return;
  /* the layout is reset only when the resource, zoom or period changes. A resize re-lays
     the tiles without animation, but keeps the order, the rows and the smoothing */
  const sigOf=()=>[S.res,S.map.root,S.range.ms].join('|'),geo=[w,h,devicePixelRatio].join('|');
  let fresh=sigOf()!==MAP.sig;
  if(MAP.color!==S.map.color){MAP.color=S.map.color;force=true;}
  const reset=()=>{MAP.sig=sigOf();MAP.hover=null;MAP.sm=new Map();MAP.ghost=new Map();MAP.byKey=null;MAP.order=new Map();MAP.shown=null;MAP.plans=null;MAP.nodes=null;MAP.from=null;cancelAnimationFrame(MAP.raf);};
  if(fresh)reset();
  if(geo!==MAP.geo){MAP.geo=geo;MAP.nodes=null;MAP.from=null;cancelAnimationFrame(MAP.raf);fresh=true;}
  if(fresh||force===true||MAP.seq!==SEQ){
    MAP.seq=SEQ;
    const root0=S.map.root;
    const psig=()=>[...(MAP.plans||[])].map(([k,v])=>k+':'+v.plan.join(';')).join('|'),ps0=psig();
    let prev=MAP.nodes,prevRect=prev&&mapRectFn(prev);
    let nodes=mapLayout(w,h);
    /* the zoomed-in group disappeared just now (mapTree reset the root) — one reset, not two in a row */
    if(S.map.root!==root0){reset();prev=null;nodes=mapLayout(w,h);}
    if(S.map.color==='exe'){updateExeColors();exeTotals(nodes);}
    const cpuOf=m=>m.ghost?0:m.rest?m.items.reduce((s,k)=>s+cpuOf(k),0):m.node&&alive(m.node)?(m.self?m.node.cpu:cur(m.node,'cpu',true)):m.kids?m.kids.reduce((s,k)=>s+cpuOf(k),0):0;
    /* memory outside processes in CPU mode is a neutral grey, not “idle”: it has no CPU at all */
    const baseRGB=m=>S.map.color==='exe'?progRGB(m):S.map.color==='cpu'?(m.key[0]==='m'?WARM:heatRGB(cpuOf(m))):hexRGB((CATS[m.cat]||CATS.other).c);
    for(const n of nodes)if(!n.head)n.rgb=baseRGB(n.m).map(Math.round);
    const id=n=>n.key+(n.head?'#':'');
    let move=Infinity,recolor=true,from=null,same=false;
    if(prev){
      const at=new Map(prev.map((n,i)=>[id(n),i]));
      from=nodes.map(n=>{const i=at.get(id(n));return i!=null?prevRect(i):{x:n.r.x+n.r.w/2,y:n.r.y+n.r.h/2,w:0,h:0};});
      move=0;recolor=false;same=nodes.length===prev.length;
      nodes.forEach((n,i)=>{const a=from[i],b=n.r,j=at.get(id(n));if(j==null){same=false;return;}
        move=Math.max(move,Math.abs(a.x-b.x),Math.abs(a.y-b.y),Math.abs(a.w-b.w),Math.abs(a.h-b.h));
        if(!n.head&&(j==null||String(prev[j].rgb)!==String(n.rgb)))recolor=true;});
    }
    /* animate only if the structure is the same: the same tiles in the same order and rows. Then the intermediate
       frames have no holes too; otherwise tiles flew through each other leaving black gaps — better to snap into place */
    const topo=ns=>ns.map(n=>id(n)+'<'+n.parent).join('|'),calm=same&&ps0===psig()&&topo(prev)===topo(nodes);
    let show=nodes;
    if(same&&move<MAP_DEAD){
      /* the layout is almost the same — geometry is left alone (no jitter), labels and colors are updated */
      const by=new Map(nodes.map(n=>[id(n),n]));
      for(const p of prev){const n=by.get(id(p));p.m=n.m;p.path=n.path;if(!p.head)p.rgb=n.rgb;}
      show=prev;
      if(!MAP.from){const r=i=>prev[i].r;if(recolor||MAP.draft)mapPaint(cv,prev,r);mapCompose(cv,prev,r);}
    }else{
      /* a tile appeared, disappeared or neighbours swapped — snap into place, no animation */
      MAP.nodes=nodes;MAP.from=calm&&move>=MAP_DEAD?from:null;
      const r=i=>nodes[i].r;
      if(MAP.from){MAP.fade=0;MAP.t0=performance.now();MAP.last=0;mapAnimate();}
      else{cancelAnimationFrame(MAP.raf);
        /* the structure changed on the same map (not a change of resource, zoom or size) — dissolve, not jump */
        const fade=prev&&!fresh&&cv.width>0;if(fade)mapFadeStart(cv);
        mapPaint(cv,nodes,r);mapCompose(cv,nodes,r);if(fade)mapFadeStep();}
    }
    /* double-click — zoom into the tile’s group (an app or a process with children) if there is more
       than one tile inside; otherwise “cannot zoom” (before, a single process opened as one tile over the whole map) */
    const real=g=>g.kids?g.kids.filter(x=>!x.ghost):[];
    const zOf=g=>{const k=real(g);return k.length>1||k.length===1&&real(k[0]).length>1?(g.zoomId||(g.node?g.node.id:null)):null;};
    const procs=m=>m.ghost?0:m.rest?m.items.reduce((s,k)=>s+procs(k),0):m.kids?m.kids.reduce((s,k)=>s+procs(k),0):m.node?1:0;
    const zoomOf=n=>{let z=zOf(n.m);if(z&&z!==S.map.root)return z;for(let p=n.parent;p>=0;p=show[p].parent){z=zOf(show[p].m);if(z&&z!==S.map.root)return z;}return null;};
    cv._rects=show.map(n=>{const m=n.m,q=n.r,z=zoomOf(n);return {id:mapId(n),x:q.x,y:q.y,w:q.w,h:n.head?MAP_HDR:q.h,node:m.node||m.rep||null,label:m.label,v:m.raw,path:n.path,
      self:m.self,own:!!m.node,procs:procs(m),cpu:cpuOf(m),rest:m.rest?m.items.map(k=>k.label):null,short:m.short||null,done:!!m.done,unseen:m.key==='mUNSEEN',zoom:z};});
    if(MAP.mouse){const h=hitMap(cv,MAP.mouse);mapHover(h&&h.id);}
    mapChrome(el); // crumbs and legend follow the new layout (zoomed-in name, program totals); their height is constant
    mapStatus();
  }else if(MAP.nodes&&!MAP.from){const r=i=>MAP.nodes[i].r;if(MAP.draft){mapPaint(cv,MAP.nodes,r);mapCompose(cv,MAP.nodes,r);}else mapFrames(cv,MAP.nodes,r);} // selection — frames only
}

/* =================================================================
   The load series of a process together with its children over the selected period:
   up to 5 minutes — per-second data of the processes themselves,
   longer — the history of the app the process belongs to.
   ================================================================= */
function nodeSeries(n,m){
  const R=S.range;
  if(R.ms<=SPARKN*1000){
    const keys=appDesc(n).map(x=>[x.pid,x.ct]);const pts=Math.round(R.ms/1000);
    const v=SP(keys,BY[m]==='io'?'io':BY[m],pts);if(!v)return null;
    const data=v[0].map(conv(m));return {t0:NOW-(data.length-1)*1000,step:1000,data,caption:appDesc(n).length>1?'with the app’s child processes':''};
  }
  /* interrupts and DPC have no long history, and the “whole Windows app” is not them: the last 5 minutes */
  if(PSEUDO[n.pid]){const data=rtail(m==='cpu'?n.rc:n.rio,SPARKN);return {t0:NOW-(data.length-1)*1000,step:1000,data,caption:'last 5 minutes'};}
  const a=appOf(n);if(!a)return {t0:NOW,step:1000,data:[],caption:''};
  const h=H('apps',BY[m],1,[a.key]);if(!h)return null;
  const s=h.series[0];const data=s?s.values.map(conv(m)):new Array(h.points).fill(0);
  return {t0:h.start_ms,step:h.step_ms,missing:h.missing,data,caption:`the whole app “${a.title}”`};
}

/* =================================================================
   Main area: a single-process tab (“open separately”)
   ================================================================= */
const PROC_TABS=new Map();
/* The process tab is like the properties window in System Informer: overview (charts, file, signature),
   modules, threads, handles, environment. Sections load on demand, threads every 2 s */
const PT_VIEWS=[['over','Overview'],['modules','Modules'],['threads','Threads'],['handles','Handles'],['env','Environment']];
const THREAD_STATE={running:'running',ready:'ready',waiting:'waiting',suspended:'suspended',standby:'standby',terminated:'terminated',other:'—'};
function mountProcTab(el,id){
  PROC_TABS.set(id,el);
  el._pt={view:'over',data:{},err:{},at:{},busy:{},q:'',qs:{},named:true,prevT:null,hov:false,tOrder:null};
  el.innerHTML=`<div class="pt-bar"><div class="seg pt-seg">${PT_VIEWS.map(([k,t])=>`<button data-v="${k}">${t}</button>`).join('')}</div>
    <input class="search pt-q" placeholder="Filter…" style="display:none"><span class="caption pt-cnt"></span><div class="spacer"></div>
    <label class="chk pt-named" style="display:none"><input type="checkbox" checked> named only</label><button class="btn subtle pt-ref" style="display:none">Refresh</button></div>
    <div class="scroll pt-body"></div>`;
  el.addEventListener('click',e=>{
    const j=e.target.closest('[data-go]');if(j)return select(j.dataset.go,true);
    const v=e.target.closest('.pt-seg [data-v]');if(v){if(el._pt.view==='threads'&&v.dataset.v!=='threads')el._pt.prevT=null; /* otherwise on return a thread’s CPU is the average over the whole time away */
      /* every section has its own filter: “ntdll” from modules must not empty the environment table */
      el._pt.qs[el._pt.view]=el._pt.q;el._pt.view=v.dataset.v;el._pt.q=el._pt.qs[el._pt.view]||'';$('.pt-q',el).value=el._pt.q;
      $('.pt-body',el)._m=0;renderProcTab(id,el,false);return;}
    if(e.target.closest('.pt-ref')){el._pt.at[el._pt.view]=0;ptLoad(id,el,el._pt.view);return;}
    const vt=e.target.closest('[data-vt]');if(vt){e.preventDefault();return openVirusTotal(vt.dataset.vt);}
  });
  $('.pt-q',el).addEventListener('input',e=>{el._pt.q=e.target.value.trim().toLowerCase();ptTable(id,el);});
  $('.pt-named input',el).addEventListener('change',e=>{el._pt.named=e.target.checked;ptTable(id,el);});
  /* threads are re-sorted every 2 s — while the cursor is over the table the order holds (as with processes) */
  const ptb=$('.pt-body',el);ptb.addEventListener('mouseenter',()=>{el._pt.hov=true;});ptb.addEventListener('mouseleave',()=>{el._pt.hov=false;});
  el.addEventListener('mousemove',e=>{const cv=e.target.closest('canvas');if(cv)chartHover(cv,cv.nextElementSibling,e);});
  el.addEventListener('mouseout',e=>{if(e.target.tagName==='CANVAS'){S.hoverT=null;e.target.nextElementSibling.style.display='none';renderCharts();}});
}
function ptLoad(id,el,what){
  const n=NODES.get(id),st=el._pt;if(!n||!n.alive||st.busy[what])return;
  st.busy[what]=true;
  /* the request may hang (a file with a pending operation) — after 20 s the button works again */
  const timeout=new Promise((_,rej)=>setTimeout(()=>rej(new Error('the engine did not answer within 20 s — try Refresh')),20000));
  Promise.race([rpc('inspect',{pid:n.pid,create_time:n.ct,what}),timeout]).then(d=>{
    if(what==='threads'){const now=performance.now(),prev=st.prevT;const m=new Map();
      for(const t of d.threads){const tot=t.kernel+t.user;const p=prev&&prev.m.get(t.tid);t.cpu=p!=null?Math.max(0,(tot-p)/((now-prev.t)*1e4*CPUS)*100):null;m.set(t.tid,tot);}
      st.prevT={t:now,m};}
    st.data[what]=d;st.err[what]=null;
  }).catch(e=>{st.err[what]=String(e.message||e);}).finally(()=>{st.busy[what]=false;st.at[what]=Date.now();if(st.view===what)ptTable(id,el);});
}
/* file signature: one request per path, the result is kept until the window restarts */
const SIGS=new Map();
const SIG_TXT={signed:['signed','ok'],unsigned:['unsigned','yel'],untrusted:['untrusted signature','red'],expired:['certificate expired','yel'],revoked:['certificate revoked','red'],bad_digest:['signature does not match the file — the file was modified','red'],distrusted:['signer is distrusted','red'],not_applicable:['not a program — such files are never signed','dim'],error:['signature cannot be checked','yel']};
/* the path currently on screen (the selected process or an open tab) */
function sigWanted(k){
  const has=n=>{if(!n)return false;const i=INFO.get(n.id)||{},p=(n.full&&n.full.path)||i.path;return !!p&&p.toLowerCase()===k;};
  if(has(NODES.get(S.sel)))return true;for(const id of PROC_TABS.keys())if(has(NODES.get(id)))return true;return false;
}
function sigOf(path){
  if(!path)return null;const k=path.toLowerCase(),c=SIGS.get(k);
  /* errors are retried after 30 s; a result is kept for 10 minutes (the file may have been updated) */
  const stale=c&&!c.busy&&!c.wait&&Date.now()-(c.at||0)>(c.error?30e3:600e3);
  if(!c||stale){
    if(SIGS.size>500)SIGS.clear();
    SIGS.set(k,{wait:true,at:Date.now()});
    /* when scrolling with the arrows each file is not hashed: the request goes out if it is still on screen after 0.4 s */
    setTimeout(()=>{
      if(!sigWanted(k)){SIGS.delete(k);return;}
      SIGS.set(k,{busy:true});
      rpc('signature',{path}).then(r=>SIGS.set(k,{...r,at:Date.now()})).catch(e=>SIGS.set(k,{error:String(e.message||e),at:Date.now()})).finally(()=>{renderDetailsSoft();renderProcTabs(true);});
    },400);
  }
  return SIGS.get(k);
}
function sigHTML(path){
  const s=sigOf(path);if(!s)return '';if(s.busy||s.wait)return '<span class="caption">checking…</span>';
  if(s.error)return `<span class="caption">${esc(s.error)}</span>`;
  const [t,c]=SIG_TXT[s.status]||SIG_TXT.error;
  return `<span class="sig ${c}">${t}</span>${s.signer?` · ${esc(s.signer)}`:''}${s.catalog?' <span class="caption">(Windows catalog)</span>':''}${s.sha256?` · <a class="lnk" href="#" role="button" data-vt="${s.sha256}" title="SHA-256 ${s.sha256}">check on VirusTotal</a>`:''}`;
}
function openVirusTotal(h){
  if(!/^[0-9a-f]{64}$/i.test(h))return;
  if(TAURI)rpc('web',{sha256:h}).catch(e=>toast(e.message||String(e),'red'));
  else window.open('https://www.virustotal.com/gui/file/'+h,'_blank','noopener');
}
/* the details on the right are redrawn only when the process changes — the signature is filled in in place */
function renderDetailsSoft(){const d=$('#details');const sg=d&&d.querySelector('.d-sig');const n=NODES.get(S.sel);if(sg&&n){const i=INFO.get(n.id)||{},p=(n.full&&n.full.path)||i.path;setHTML(sg,sigHTML(p));}}
function ptTable(id,el){
  const st=el._pt,body=$('.pt-body',el),v=st.view;if(v==='over')return;
  const d=st.data[v],q=st.q;
  if(st.err[v]&&!d){body.innerHTML=`<div class="empty">${esc(st.err[v])}${/administrator/.test(st.err[v])&&!isAdmin()?ADMIN_LINK:''}</div>`;$('.pt-cnt',el).textContent='';return;}
  if(!d){body.innerHTML='<div class="empty">Loading…</div>';return;}
  const has=s=>!q||String(s).toLowerCase().includes(q);
  let head,rows,cnt,note='',minW=0,empty='';
  if(v==='modules'){
    const l=d.modules.filter(m=>has(m.name+' '+m.path));cnt=`${l.length} of ${d.modules.length}`;
    head='<col style="width:190px"><col style="width:132px"><col style="width:84px"><col>|Module|Address|>Size|Path';minW=620;
    rows=l.map(m=>`<tr><td>${esc(m.name)}</td><td class="mono">0x${m.base.toString(16)}</td><td class="num">${fmtMem(m.size/MB)}</td><td class="mono" title="${esc(m.path)}">${esc(m.path)}</td></tr>`);
  }else if(v==='threads'){
    const l=d.threads.filter(t=>has(t.tid+' '+(t.start||'')+' '+t.state));cnt=`${l.length} of ${d.threads.length}`;
    const o=st.hov&&st.tOrder;
    if(o)l.sort((a,b)=>(o.has(a.tid)?o.get(a.tid):1e9)-(o.has(b.tid)?o.get(b.tid):1e9));
    else{l.sort((a,b)=>(b.cpu||0)-(a.cpu||0)||(b.kernel+b.user)-(a.kernel+a.user)||a.tid-b.tid);st.tOrder=new Map(l.map((t,i)=>[t.tid,i]));}
    head='<col style="width:70px"><col style="width:64px"><col style="width:84px"><col style="width:90px"><col style="width:60px"><col style="width:104px"><col>|>TID|>CPU|>CPU time|>Switches|>Prio.|State|Start address';minW=660;
    empty='No threads available';
    rows=l.map(t=>`<tr><td class="num">${t.tid}</td><td class="num">${t.cpu==null?'<span class="caption">…</span>':t.cpu<.05?'<span style="color:var(--text-4)">—</span>':fmtPct(t.cpu)}</td><td class="num">${agoStr((t.kernel+t.user)/1e7)}</td><td class="num">${t.switches.toLocaleString('en')}</td><td class="num">${t.priority}</td><td>${THREAD_STATE[t.state]||t.state}</td><td class="mono">${esc(t.start||'')}</td></tr>`);
    note='<p class="caption pt-note">Thread CPU is a share of the whole processor, as for processes. The start address is the module and offset of the function the thread started in.</p>';
  }else if(v==='handles'){
    const l=d.list.filter(h=>(!st.named||h.name)&&has(h.type+' '+h.name));cnt=`${l.length} of ${d.total}`;
    head='<col style="width:130px"><col><col style="width:80px"><col style="width:100px">|Type|Name|Handle|Access';minW=560;
    empty=st.named&&d.list.length?'No named handles — uncheck “named only”':'No handles';
    rows=l.slice(0,3000).map(h=>`<tr><td>${esc(h.type)}</td><td class="mono" title="${esc(h.name)}">${esc(h.name)||'<span style="color:var(--text-4)">—</span>'}</td><td class="mono">0x${h.handle.toString(16)}</td><td class="mono">0x${h.access.toString(16).padStart(8,'0')}</td></tr>`);
    note=`<p class="caption pt-note">${d.by_type.slice(0,12).map(([k,c])=>`${esc(k)} ${c}`).join(' · ')}${d.names?'':' — object names are not available: administrator rights needed'}${d.files_skipped?' — the name of one of the files did not answer (an operation is pending on it), names of the other files were not requested':''}${l.length>3000?' · first 3000 shown':''}</p>`;
  }else{
    const l=d.vars.filter(([k,x])=>has(k+'='+x));cnt=`${l.length} of ${d.vars.length}`;
    head='<col style="width:32%"><col>|Variable|Value';minW=480;empty='The environment is empty';
    rows=l.map(([k,x])=>`<tr><td class="mono">${esc(k)}</td><td class="mono" title="${esc(x)}">${esc(x)}</td></tr>`);
    note=`<p class="caption pt-note">Folder: <span class="mono">${esc(d.cwd)}</span> · the environment the process runs with right now; it may contain passwords and tokens.</p>`;
  }
  $('.pt-cnt',el).textContent=cnt+(st.err[v]?' · '+st.err[v]:'');
  const [cols,...ths]=head.split('|');
  const wrap=body.querySelector('.pt-tbl'),top=body.scrollTop;
  /* “>” in a header marks a numeric column, right-aligned together with the numbers */
  body.innerHTML=`${note}<table class="tbl left pt-tbl" style="min-width:${minW}px"><colgroup>${cols}</colgroup><thead><tr>${ths.map(t=>`<th style="cursor:default;text-align:${t[0]==='>'?'right':'left'}">${t.replace(/^>/,'')}</th>`).join('')}</tr></thead><tbody>${rows.join('')||`<tr><td colspan="${ths.length}" class="caption">${q?'Nothing found':empty||'Empty'}</td></tr>`}</tbody></table>`;
  if(wrap)body.scrollTop=top; /* a threads refresh does not reset the scroll */
}
function renderProcTab(id,el,chartsOnly){
  const st=el._pt,n=NODES.get(id),body=$('.pt-body',el);
  el.querySelectorAll('.pt-seg [data-v]').forEach(b=>b.classList.toggle('on',b.dataset.v===st.view));
  const tbl=st.view!=='over';
  /* display, not hidden: .btn and .chk have their own display that overrides the hidden attribute */
  const show=(sel,on)=>{$(sel,el).style.display=on?'':'none';};
  show('.pt-q',tbl);show('.pt-ref',tbl&&st.view!=='threads');show('.pt-named',st.view==='handles');if(!tbl)$('.pt-cnt',el).textContent='';
  show('.pt-seg',!(n&&PSEUDO[n.pid]));
  if(!n){body.innerHTML='<div class="empty">The process exited, no more data</div>';return;}
  if(tbl){
    if(!n.alive){if(!st.data[st.view])body.innerHTML='<div class="empty">The process exited</div>';return;}
    /* threads are live, every 2 s; the rest — with the Refresh button */
    const age=Date.now()-(st.at[st.view]||0);
    if((!st.data[st.view]&&!st.err[st.view])||(st.view==='threads'&&age>2000))ptLoad(id,el,st.view);
    if(body._m!==2){body._m=2;ptTable(id,el);}
    return;
  }
  if((!chartsOnly||body._m!==1)&&!(body._m===1&&selIn(body))){
    body._m=1;
    const i=INFO.get(n.id)||{},f=n.full||{},path=f.path||i.path;
    body.innerHTML=`<div class="dt-h">${ico(n,1)}<div><h3>${esc(nameOf(n))}</h3><div class="caption">${PSEUDO[n.pid]?'Windows kernel load, not a process':`PID ${n.pid} · ${esc(n.exe)} · ${n.alive?'running for '+agoStr((NOW-ctToMs(n.ct))/1000):'exited'}${desc(n).length?` · child processes: ${desc(n).length}`:''}`}</div></div></div>
      ${PSEUDO[n.pid]?'':`<div class="crumbs"><span class="caption" style="margin-right:4px">Started by:</span>${ancestors(n).map(a=>`<a data-go="${esc(a.id)}">${esc(nameOf(a))}</a>`).join('<span class="sep">›</span>')||'<span class="caption">system</span>'}</div>`}
      <div class="pt-grid">${(PSEUDO[n.pid]?[['cpu','CPU']]:[['cpu','CPU'],['mem','Memory'],['dsk','Disk']]).map(([m,t])=>`<div class="cell"><div class="caption"><span class="pt-cap" data-m="${m}">${t}</span></div><canvas data-m="${m}"></canvas><div class="pop"></div></div>`).join('')}</div>
      ${PSEUDO[n.pid]?'':`<dl class="kv pt-kv">
        <dt>File</dt><dd class="mono">${path?esc(path):'no access — administrator rights needed'}</dd>
        ${path?`<dt>Signature</dt><dd class="pt-sig">${sigHTML(path)}</dd>`:''}
        ${f.cmdline?`<dt>Command line</dt><dd class="mono">${esc(f.cmdline)}</dd>`:''}
        ${i.description?`<dt>Description</dt><dd>${esc(i.description)}</dd>`:''}${i.company?`<dt>Publisher</dt><dd>${esc(i.company)}</dd>`:''}
        <dt>Threads · handles</dt><dd>${n.threads} · ${(n.handles||0).toLocaleString('en')}</dd>
      </dl>`}`;
    if(!n.full&&n.alive&&!PSEUDO[n.pid])info(n,true).then(()=>{body._m=0;renderProcTab(id,el,false);});
  }
  const sg=body.querySelector('.pt-sig');if(sg){const i=INFO.get(n.id)||{},p=(n.full&&n.full.path)||i.path;setHTML(sg,sigHTML(p));}
  for(const cv of body.querySelectorAll('canvas')){const m=cv.dataset.m,c=COLS_ALL.find(c=>c.m===m);
    const s=nodeSeries(n,m);const cap=body.querySelector(`.pt-cap[data-m="${m}"]`);
    if(cap)cap.textContent=`${c.t}${s&&s.caption?' · '+s.caption:''} · ${S.range.label}`;
    if(!s){drawTS(cv,{series:[],t0:NOW,step:1000,fmt:c.fmt,empty:'Loading history…'});continue;}
    drawTS(cv,{series:[{name:c.t,color:PAL[{cpu:0,mem:2,dsk:4}[m]],data:s.data}],t0:s.t0,step:s.step,missing:s.missing,fmt:c.fmt,fill:true});}
}
function renderProcTabs(chartsOnly){
  for(const [id,el] of PROC_TABS){if(vis(el))renderProcTab(id,el,chartsOnly);}
}
function openProcTab(id){
  const n=NODES.get(id);if(!n)return;const pid='proc:'+id;
  const ex=dock.getPanel(pid);if(ex){ex.api.setActive();return;}
  dock.addPanel({id:pid,component:'proc',title:PSEUDO[n.pid]?nameOf(n):`${nameOf(n)} · ${n.pid}`,params:{id}});
  requestAnimationFrame(()=>{renderAll();flushNeeds();});
}

/* restart as administrator — from the header, the menu and links wherever something is hidden without rights */
const isAdmin=()=>!!(SYSINFO&&SYSINFO.elevated);
const ADMIN_LINK=' <a class="admin-link" data-admin>Restart as administrator</a>';
async function runAdmin(){if(!TAURI)return toast('Run the app, not the development mode','yel');
  toast('Confirm the launch in the Windows prompt — if you do not see it, click the flashing shield on the taskbar','info');
  try{await appCmd('admin');}catch(err){toast(err.message||String(err),'yel');}}
$('#adminBtn').addEventListener('click',runAdmin);
document.addEventListener('click',e=>{if(e.target.closest('[data-admin]')){e.preventDefault();runAdmin();}});
/* =================================================================
   Kernel pool: memory of drivers and kernel objects by tag — it does not show up in any process.
   The engine samples the pool once a minute and computes the growth; the panel asks only while it is visible.
   ================================================================= */
let POOL=null,poolBusy=false,poolAt=0,POOLA=[];
const PS={by:'size'};
function mountPool(el){
  el.innerHTML=`<div class="ph"><span class="caption pl-head">Reading the kernel pool…</span><div class="spacer"></div>
    <div class="seg pl-by"><button data-b="size">By size</button><button data-b="growth">By growth</button></div>
    <button class="btn pl-own" title="Look for the tags in the files of loaded drivers (10–30 s, in the background)">Find drivers</button></div>
    <div class="pl-alerts"></div>
    <div class="tbl-wrap"><table class="tbl" style="min-width:740px"><colgroup><col style="width:78px"><col><col style="width:88px"><col style="width:88px"><col style="width:96px"><col style="width:100px"><col style="width:124px"></colgroup>
    <thead><tr><th style="cursor:default">Tag</th><th style="cursor:default;text-align:left">What it is</th><th>Non-paged</th><th>Paged</th><th>Objects</th><th>Growth per hour</th><th style="cursor:default">Chart</th></tr></thead><tbody></tbody></table></div>
    <div class="caption pl-foot" style="padding:6px 14px 8px"></div>`;
  $('.pl-by',el).addEventListener('click',e=>{const b=e.target.closest('button');if(b){PS.by=b.dataset.b;poolAt=0;renderPool();}});
  $('.pl-own',el).addEventListener('click',async()=>{
    try{const st=await rpc('pool_owners');if(POOL)POOL.owners=st;}catch(err){toast(err.message||String(err),'red',6000);}
    poolAt=0;renderPool();
  });
}
function fetchPool(){
  const scanning=POOL&&POOL.owners&&POOL.owners.state==='running';
  if(poolBusy||Date.now()-poolAt<(scanning?1500:5000))return;
  poolBusy=true;
  rpc('pool',{n:30,by:PS.by}).then(d=>{POOL=d;}).catch(e=>{POOL={error:e.message||String(e),tags:[],alerts:[]};})
    .finally(()=>{poolBusy=false;poolAt=Date.now();renderPool(true);});
}
/* the series shape from minimum to maximum: growth from 190 to 192 MB is not visible otherwise */
function poolSpark(v){
  if(!v||v.length<2)return '<span style="color:var(--text-4)">—</span>';
  const lo=Math.min(...v),hi=Math.max(...v),w=100,h=18,span=Math.max(hi-lo,1);
  const pts=v.map((x,i)=>`${(i/(v.length-1)*w).toFixed(1)},${(h-1.5-(x-lo)/span*(h-3)).toFixed(1)}`).join(' ');
  const up=hi-lo>=65536&&v[v.length-1]>=hi-(hi-lo)*.1&&v[0]<=lo+(hi-lo)*.1;
  return `<svg width="${w}" height="${h}" style="vertical-align:middle;overflow:visible"><polyline points="${pts}" fill="none" stroke="${up?'var(--critical)':'var(--accent)'}" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
}
function renderPool(fromFetch){
  const el=PANEL_EL.pool;if(!vis(el))return;
  if(!fromFetch)fetchPool();
  $('.pl-by',el).querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.b===PS.by));
  if(!POOL)return;
  const head=$('.pl-head',el),tb=$('tbody',el),own=$('.pl-own',el);
  if(POOL.error){setHTML(head,'Kernel pool not available: '+esc(POOL.error));patchRows(tb,[]);return;}
  const cnt=v=>Math.round(v).toLocaleString('en');
  const watch=POOL.watching_ms>=600e3?` · watching for ${agoStr(POOL.watching_ms/1000)}`:'';
  const zomb=POOL.zombie_procs||POOL.zombie_threads?` · exited but not freed: ${cnt(POOL.zombie_procs)} processes, ${cnt(POOL.zombie_threads)} threads`:'';
  setHTML(head,`Non-paged ${fmtMem(POOL.nonpaged/MB)} · paged ${fmtMem(POOL.paged/MB)}${watch}${zomb}`);
  const o=POOL.owners||{};
  own.disabled=o.state==='running';
  own.textContent=o.state==='running'?`Searching… ${o.total?Math.round(o.scanned/o.total*100):0} %`:o.state==='done'?'Search again':'Find drivers';
  setHTML($('.pl-alerts',el),(POOL.alerts||[]).map(a=>`<div class="issue ${a.level}"><span class="dot ${a.level}"></span><span>${esc(a.text)}</span></div>`).join(''));
  const dash='<span style="color:var(--text-4)">—</span>';
  const rate=r=>r==null?dash:Math.abs(r)<65536?'0':`${r>0?'+':'−'}${fmtMem(Math.abs(r)/MB)}`;
  patchRows(tb,POOL.tags.map(t=>{
    const own=t.owners||[];
    const who=own.length?`<span class="n2">${esc(own.slice(0,3).join(', '))}${own.length>3?` and ${own.length-3} more`:''}</span>`:o.state==='done'&&!t.about?'<span class="n2">driver not found</span>':'';
    return {id:t.tag,cls:'',cells:[
      {h:`<div class="nm"><span class="n1 mono">${esc(t.tag)}</span>${t.alert?'<span class="dot red"></span>':''}</div>`},
      {h:`<div class="nm">${t.about?`<span class="n1">${esc(t.about)}</span>`:''}${who}</div>`,t:[t.about,own.length?'Found in: '+own.join(', '):''].filter(Boolean).join('\n')},
      {h:t.nonpaged?`<span class="cell-v">${fmtMem(t.nonpaged/MB)}</span>`:dash},
      {h:t.paged?`<span class="cell-v">${fmtMem(t.paged/MB)}</span>`:dash},
      {h:`<span class="cell-v">${cnt(t.count)}</span>`},
      {c:t.rate>=1048576?'act':'',h:`<span class="cell-v">${rate(t.rate)}</span>`,
       t:t.count_rate!=null?`objects ${t.count_rate>0?'+':''}${cnt(t.count_rate)} per hour · computed over ${agoStr(t.rate_window_ms/1000)}`:'growth shows up after 10 minutes of watching'},
      {h:poolSpark(t.spark),t:t.spark_step_ms?`last ${agoStr((t.spark.length-1)*t.spark_step_ms/1000)}, one point every ${t.spark_step_ms/60000} min`:''},
    ]};
  }));
  setHTML($('.pl-foot',el),(POOL.watching_ms<600e3?'Growth per hour shows up in 10 minutes: the engine samples the pool once a minute. ':'')+
    'A tag is four letters the kernel or a driver marks its memory with. If a tag grows without stopping, it is a leak: a reboot frees the memory, and updating or removing the culprit stops the growth.');
}

/* =================================================================
   Windows services: list, start and stop; which services live in which svchost
   ================================================================= */
let SVCS=null,svcBusy=false,svcAt=0,svcNamesAt=0;
const SV={q:'',all:false};
let SVC_BY_PID=new Map(); /* pid → services inside the process (names for svchost.exe) */
const SVC_STATE={running:'running',stopped:'stopped',start_pending:'starting',stop_pending:'stopping',paused:'paused',pause_pending:'pausing',continue_pending:'continuing'};
const SVC_START={auto:'Automatic',auto_delayed:'Automatic (delayed)',manual:'Manual',disabled:'Disabled',boot:'At boot',system:'At boot'};
function indexSvcs(list){const m=new Map();for(const s of list)if(s.pid){if(!m.has(s.pid))m.set(s.pid,[]);m.get(s.pid).push(s);}SVC_BY_PID=m;}
/* service names are needed even without the tab open: svchost.exe in the process list shows which services are inside */
function fetchSvcNames(){
  if(svcBusy||Date.now()-svcNamesAt<15000||Date.now()-svcAt<15000)return;
  svcNamesAt=Date.now();
  rpc('services',{details:false}).then(d=>indexSvcs(d.services)).catch(()=>{});
}
function fetchSvcs(force){
  if(svcBusy||(!force&&Date.now()-svcAt<3000))return;
  svcBusy=true;
  rpc('services',{details:true}).then(d=>{SVCS=d;indexSvcs(d.services);}).catch(e=>{SVCS={error:e.message||String(e),services:[]};})
    .finally(()=>{svcBusy=false;svcAt=Date.now();renderSvcs(true);});
}
/* PID → live node: a map for half a second instead of walking all nodes for every services and connections row */
let PIDM=null;
const nodeByPid=pid=>{const t=performance.now();if(!PIDM||t-PIDM.t>500){const m=new Map();for(const n of NODES.values())if(n.alive)m.set(n.pid,n);PIDM={t,m};}return PIDM.m.get(pid)||null;};
function mountSvcs(el){
  el.innerHTML=`<div class="ph"><input class="search sv-q" placeholder="Search services…">
      <label class="chk"><input type="checkbox" class="sv-all"> include stopped</label>
      <div class="spacer"></div><span class="caption sv-head">Reading the service list…</span></div>
    <div class="tbl-wrap"><table class="tbl left" style="min-width:540px"><colgroup><col><col style="width:108px"><col style="width:112px"><col style="width:136px"><col style="width:40px"></colgroup>
    <thead><tr><th style="cursor:default;text-align:left">Service</th><th style="cursor:default;text-align:left">State</th><th style="cursor:default;text-align:left">Startup</th><th style="cursor:default;text-align:left">Process</th><th style="cursor:default"></th></tr></thead><tbody></tbody></table></div>
    <div class="caption sv-foot" style="padding:6px 14px 8px"></div>`;
  $('.sv-q',el).addEventListener('input',e=>{SV.q=e.target.value.trim().toLowerCase();renderSvcs(true);});
  $('.sv-all',el).addEventListener('change',e=>{SV.all=e.target.checked;renderSvcs(true);});
  const open=(e,name)=>{
    const s=SVCS&&SVCS.services.find(x=>x.name===name);if(!s)return;
    const on=s.state==='running',off=s.state==='stopped';
    const it=[];
    /* without administrator rights Windows does not allow controlling services: the items are visible but disabled */
    const off2=SVCS.elevated?'':' off';
    if(!SVCS.elevated&&(off||(on&&s.can_stop)))it.push('<div class="mh">Administrator rights needed</div>');
    if(off)it.push(`<div class="mi${off2}" data-sva="start" data-name="${esc(s.name)}"><span>Start</span></div>`);
    if(on&&s.can_stop)it.push(`<div class="mi danger${off2}" data-sva="stop" data-name="${esc(s.name)}"><span>Stop</span></div>`,`<div class="mi danger${off2}" data-sva="restart" data-name="${esc(s.name)}"><span>Restart</span></div>`);
    if(!SVCS.elevated&&(off||(on&&s.can_stop))&&TAURI)it.push('<div class="mi" data-svadm="1"><span>Restart Taskscope as administrator…</span></div>');
    if(s.pid&&nodeByPid(s.pid))it.push('<div class="sep"></div>',`<div class="mi" data-svgo="${s.pid}"><span>Go to process</span></div>`);
    if(!it.length)it.push('<div class="mh">The service does not accept commands</div>');
    menuIds=null;
    menu.innerHTML=`<div class="mh">${esc(s.display)}${s.display!==s.name?' · '+esc(s.name):''}</div>`+it.join('');
    menu.style.display='block';const r=menu.getBoundingClientRect();
    menu.style.left=Math.min(e.clientX,innerWidth-r.width-8)+'px';menu.style.top=Math.max(8,Math.min(e.clientY,innerHeight-r.height-8))+'px';
  };
  el.addEventListener('click',e=>{
    const b=e.target.closest('[data-svm]');if(b)return open(e,b.dataset.svm);
    const g=e.target.closest('[data-go]');if(g){select(g.dataset.go,true);}
  });
  el.addEventListener('contextmenu',e=>{const tr=e.target.closest('tr[data-id]');if(!tr)return;e.preventDefault();open(e,tr.dataset.id);});
}
menu.addEventListener('click',async e=>{
  if(e.target.closest('[data-svadm]')){closeMenu();try{await runAdmin();}catch(err){toast(err.message||String(err),'red');}return;}
  const g=e.target.closest('[data-svgo]');
  if(g){closeMenu();const n=nodeByPid(+g.dataset.svgo);if(n){dock.getPanel('procs')?.api.setActive();select(n.id,true);}return;}
  const b=e.target.closest('[data-sva]');if(!b)return;closeMenu();
  svcAct(b.dataset.name,b.dataset.sva);
});
const SVC_VERB={start:'Start',stop:'Stop',restart:'Restart'};
async function svcAct(name,action){
  const s=SVCS&&SVCS.services.find(x=>x.name===name);if(!s)return;
  let force=false;
  if(action!=='start'){
    const users=(SVC_BY_PID.get(s.pid)||[]).filter(x=>x.name!==s.name);
    const body=`<p class="m-lead">${action==='stop'?'The service stops until it is started again or the computer restarts.':'The service stops and starts again right away.'}${s.description?' '+esc(s.description):''}</p>
      ${s.critical?`<div class="m-warn">${ICON_WARN}<span>A system service: without it Windows stops working properly (sign-in, starting programs, devices). Stop it only if you know exactly why.</span></div>`:''}
      ${users.length?`<p class="m-lead">Other services run in the same svchost process: ${esc(users.slice(0,6).map(x=>x.display).join(', '))}${users.length>6?` and ${users.length-6} more`:''} — they keep running.</p>`:''}`;
    const r=await dialog({title:`${SVC_VERB[action]} the “${s.display}” service?`,body,ok:SVC_VERB[action],danger:true});
    if(!r)return;
    force=s.critical;
  }
  try{
    const r=await rpc('service_act',{name,action,force});
    toast(`${s.display}: ${SVC_STATE[r.state]||r.state}`,'ok');
  }catch(err){
    const m=err.message||String(err);
    toast(m,'red',8000,/administrator/.test(m)&&TAURI&&!isAdmin()?{t:'Run as administrator',f:runAdmin}:null);
  }
  fetchSvcs(true);
}
function renderSvcs(fromFetch){
  const el=PANEL_EL.svcs;if(!vis(el))return;
  if(!fromFetch)fetchSvcs();
  if(!SVCS)return;
  const head=$('.sv-head',el),tb=$('tbody',el);
  if(SVCS.error){setHTML(head,'Service list not available: '+esc(SVCS.error));patchRows(tb,[]);return;}
  const all=SVCS.services,run=all.filter(s=>s.state==='running').length;
  setHTML(head,`${run} running · ${all.length} total${SVCS.elevated?'':' · start and stop need administrator rights'+ADMIN_LINK}`);
  const q=SV.q,list=all.filter(s=>(SV.all||q||s.state!=='stopped')&&(!q||s.name.toLowerCase().includes(q)||s.display.toLowerCase().includes(q)||(s.description||'').toLowerCase().includes(q)));
  const dot=st=>st==='running'?'background:var(--success)':st==='stopped'?'background:var(--text-4)':'background:var(--caution)';
  patchRows(tb,list.map(s=>{
    const n=s.pid?nodeByPid(s.pid):null;
    return {id:s.name,cls:s.state==='stopped'?'dim':'',cells:[
      {h:`<div class="nm"><span class="n1">${esc(s.display)}</span><span class="n2">${esc(s.name)}${s.critical?' · system':''}${s.shared?'':' · own process'}</span></div>`,t:s.description||''},
      {h:`<span class="sv-st"><span class="dot" style="${dot(s.state)}"></span>${SVC_STATE[s.state]||s.state}</span>`},
      {h:`<span class="caption">${SVC_START[s.start]||'—'}</span>`},
      {h:n?`<a data-go="${esc(n.id)}" class="sv-proc">${esc(n.exe)} · ${s.pid}</a>`:s.pid?`<span class="caption">PID ${s.pid}</span>`:'<span style="color:var(--text-4)">—</span>'},
      {h:`<button class="ib" data-svm="${esc(s.name)}" title="Actions">⋯</button>`,c:'stick'},
    ]};
  }));
  setHTML($('.sv-foot',el),list.length?`Shown: ${list.length}. Right-click or “⋯” — start, stop, restart.`:'Nothing found.');
}

/* =================================================================
   Connections and open ports (GetExtendedTcpTable / GetExtendedUdpTable)
   ================================================================= */
let CONNS=null,connBusy=false,connAt=0;
const CN={q:'',listen:false,closed:false};
const CONN_STATE={listen:'listening',established:'established',time_wait:'closing',close_wait:'closing',syn_sent:'connecting',syn_received:'connecting',fin_wait1:'closing',fin_wait2:'closing',closing:'closing',last_ack:'closing',closed:'closed'};
const hostPort=(a,p)=>a.includes(':')?`[${a}]:${p}`:`${a}:${p}`;
function fetchConns(){
  if(connBusy||Date.now()-connAt<2000)return;
  connBusy=true;
  rpc('connections').then(d=>{CONNS=d.connections;fetchConns.err=null;}).catch(e=>{CONNS=null;const m=e.message||String(e);if(fetchConns.err!==m){fetchConns.err=m;toast('Connections: '+m,'red');}})
    .finally(()=>{connBusy=false;connAt=Date.now();renderConns(true);});
}
function mountConns(el){
  el.innerHTML=`<div class="ph"><input class="search cn-q" placeholder="Search: process, address, port…">
      <label class="chk"><input type="checkbox" class="cn-l"> open ports only</label>
      <label class="chk" title="Connections in the TIME_WAIT state: the process has already closed them, Windows holds the address for a couple more minutes"><input type="checkbox" class="cn-cl"> <span class="cn-c">include closed</span></label>
      <div class="spacer"></div><span class="caption cn-head"></span></div>
    <div class="tbl-wrap"><table class="tbl left" style="min-width:640px"><colgroup><col><col style="width:52px"><col style="width:170px"><col style="width:190px"><col style="width:100px"></colgroup>
    <thead><tr><th style="cursor:default;text-align:left">Process</th><th style="cursor:default;text-align:left">Proto</th><th style="cursor:default;text-align:left">Local address</th><th style="cursor:default;text-align:left">Remote address</th><th style="cursor:default;text-align:left">State</th></tr></thead><tbody></tbody></table></div>
    <div class="caption cn-foot" style="padding:6px 14px 8px"></div>`;
  $('.cn-q',el).addEventListener('input',e=>{CN.q=e.target.value.trim().toLowerCase();renderConns(true);});
  $('.cn-l',el).addEventListener('change',e=>{CN.listen=e.target.checked;renderConns(true);});
  $('.cn-cl',el).addEventListener('change',e=>{CN.closed=e.target.checked;renderConns(true);});
  el.addEventListener('click',e=>{const g=e.target.closest('[data-go]');if(g)select(g.dataset.go,true);});
}
function renderConns(fromFetch){
  const el=PANEL_EL.conns;if(!vis(el))return;
  if(!fromFetch)fetchConns();
  if(!CONNS)return;
  const q=CN.q;
  /* PID 0 — closed connections in TIME_WAIT: they no longer have a process, hidden by default */
  const closed=CONNS.filter(c=>c.pid===0).length;
  const rows=dedupConns(CONNS.filter(c=>(CN.closed||c.pid!==0)&&(!CN.listen||c.state==='listen'||c.proto==='udp'))).map(x=>{const n=nodeByPid(x.c.pid);return {...x,nd:n,nm:n?nameOf(n):''};})
    .filter(({c,nd})=>!q||String(c.pid).includes(q)||c.local.includes(q)||c.remote.includes(q)||String(c.local_port)===q||String(c.remote_port)===q||(nd&&(nameOf(nd).toLowerCase().includes(q)||nd.exe.toLowerCase().includes(q))));
  const rank=({c,nd})=>c.pid===0?2:nd?0:1;
  rows.sort((a,b)=>rank(a)-rank(b)||a.nm.localeCompare(b.nm)||a.c.local_port-b.c.local_port);
  const live=CONNS.filter(c=>c.pid!==0),est=live.filter(c=>c.state==='established').length,lis=live.filter(c=>c.state==='listen').length;
  setHTML($('.cn-head',el),`${est} established · ${lis} open TCP ports · UDP ${live.filter(c=>c.proto==='udp').length}`);
  $('.cn-c',el).textContent=`include closed (${closed})`;
  patchRows($('tbody',el),rows.slice(0,800).map(({c,n,nd})=>({id:`${c.proto}|${c.local}|${c.local_port}|${c.remote}|${c.remote_port}|${c.state}|${c.pid}`,cls:c.pid===0?'dim':'',cells:[
    {h:nd?`<div class="nm">${ico(nd)}<a data-go="${esc(nd.id)}" class="n1">${esc(nameOf(nd))}</a><span class="n2">${c.pid}</span></div>`:`<span class="caption">${c.pid?'PID '+c.pid:'closed'}</span>`},
    {h:`<span class="caption">${c.proto.toUpperCase()}</span>`},
    {h:`<span class="mono">${esc(hostPort(c.local,c.local_port))}</span>`},
    {h:c.remote?`<span class="mono">${esc(hostPort(c.remote,c.remote_port))}</span>`:'<span style="color:var(--text-4)">—</span>'},
    {h:`<span class="caption">${c.proto==='udp'?'open':CONN_STATE[c.state]||c.state}${n>1?` ×${n}`:''}</span>`,t:n>1?`${n} identical sockets`:''},
  ]})));
  setHTML($('.cn-foot',el),!rows.length?'Nothing found.':rows.length>800?`Showing the first 800 of ${rows.length} — narrow the search.`:`Shown: ${rows.length}.`);
}

/* =================================================================
   Who holds a file: Restart Manager, like Windows installers use
   ================================================================= */
async function whoHolds(){
  if(DIALOG)return;
  const bg=document.createElement('div');bg.className='modal-bg top'; /* at the top: the input does not jump when the result height changes */
  bg.innerHTML=`<div class="modal" role="dialog" aria-modal="true" aria-labelledby="wh-t"><h3 id="wh-t">Who holds a file</h3>
    <p class="m-lead">The path of a file or folder that cannot be deleted, renamed or is “in use by another process”.</p>
    <div class="wh-row"><input class="search wh-p" placeholder="C:\\path\\to\\file or folder" spellcheck="false"><button class="btn primary wh-go">Find</button></div>
    <div class="m-body scroll wh-res"></div>
    <div class="m-acts"><button class="btn" data-r="0">Close</button></div></div>`;
  const prevFocus=document.activeElement;
  const close=()=>{bg.remove();DIALOG=null;document.removeEventListener('keydown',key,true);if(prevFocus&&prevFocus.focus)prevFocus.focus();};
  const key=e=>{e.stopImmediatePropagation();if(e.key==='Escape'){e.preventDefault();close();}else if(e.key==='Enter'&&e.target.matches('.wh-p')){e.preventDefault();go();}
    else if(e.key==='Tab'){const f=[...bg.querySelectorAll('button:not(:disabled),input')];const i=f.indexOf(document.activeElement);e.preventDefault();f[(i+(e.shiftKey?f.length-1:1))%f.length].focus();}};
  const res=$('.wh-res',bg);
  const go=async()=>{
    const path=$('.wh-p',bg).value.trim().replace(/^"|"$/g,'');if(!path)return;
    const btn=$('.wh-go',bg);if(btn.disabled)return;btn.disabled=true;
    res.innerHTML='<p class="caption">Searching… a big folder may take a few seconds.</p>';
    try{
      const r=await rpc('file_holders',{path});
      /* folder: open files of accessible processes are checked against the whole handle table;
         “partially” — only for inaccessible ones (services, programs running as administrator) */
      const note=(r.truncated?(r.scanned?`<p class="caption">Open files of your programs were checked across the whole folder. ${r.unscanned} ${plural(r.unscanned,'process','processes','processes')} (services, programs running as administrator) were checked without administrator rights only against ${r.files} top-level files and folders.${isAdmin()?'':ADMIN_LINK}</p>`
          :`<p class="caption">The folder is big: only ${r.files} top-level files and folders were checked — for an exact answer, give a subfolder or a file.</p>`):'')
        +(r.skipped?`<p class="caption">Files skipped without access: ${r.skipped}.${isAdmin()?'':ADMIN_LINK}</p>`:'');
      if(!r.holders.length){res.innerHTML=(r.truncated?'<p class="m-lead">Nobody holds files in the checked part of the folder.</p>':'<p class="m-lead">Nobody holds this path open. If it still cannot be deleted, the cause is permissions or the read-only attribute.</p>')+note;return;}
      res.innerHTML=note+`<div class="m-list">${r.holders.map(h=>{const n=NODES.get(h.pid+':'+h.create_time); /* exact match only: the PID may have gone to another process */
        const files=(h.files||[]).map(f=>`<div class="mono wh-f" title="${esc(f)}">${esc(f)}</div>`).join('')+(h.open>(h.files||[]).length?`<div class="caption wh-f">… open in the folder in total: ${h.open}</div>`:'');
        return `<div class="m-row wh-h">${n?ico(n):'<span class="m-ico"></span>'}<span class="m-n">${esc(n?nameOf(n):h.app)}${h.service?` <span class="caption">· service ${esc(h.service)}</span>`:''}${files}</span><span class="caption num">${h.pid}</span>${n?`<button class="btn danger wh-k" data-id="${esc(n.id)}">End</button>`:'<span></span>'}</div>`;}).join('')}</div>`;
    }catch(e){const m=String(e.message||e);res.innerHTML=`<p class="m-lead warn-t">${esc(m.charAt(0).toUpperCase()+m.slice(1))}</p>`;}
    finally{btn.disabled=false;}
  };
  bg.addEventListener('click',e=>{
    if(e.target.closest('[data-r="0"]')||e.target===bg)return close();
    if(e.target.closest('.wh-go'))return go();
    const k=e.target.closest('.wh-k');if(k){close();act('kill',[k.dataset.id]);}
  });
  document.addEventListener('keydown',key,true);
  document.body.appendChild(bg);DIALOG=bg;$('.wh-p',bg).focus();
}

/* =================================================================
   Process details: services inside and network connections
   ================================================================= */
let DCONN={at:0,list:null,busy:false};
/* identical sockets (a dozen UDP 5353 in a browser) — one row with “×N” */
function dedupConns(list){
  const m=new Map();
  for(const c of list){const k=`${c.proto}|${c.local}|${c.local_port}|${c.remote}|${c.remote_port}|${c.state}|${c.pid}`;const x=m.get(k);if(x)x.n++;else m.set(k,{c,n:1});}
  return [...m.values()];
}
/* Which files processes read and write: a trace of kernel file operations (administrator only).
   Requested only while the section in the details or the disk’s “More” is open: the first request starts
   watching, without requests it stops by itself after 2 minutes. One shared list for both places. */
let DFILES={at:0,d:null,err:'',busy:false};
function diskFiles(){
  if(!isAdmin())return null;
  if(!DFILES.busy&&Date.now()-DFILES.at>2000){DFILES.busy=true;
    rpc('disk_files',{limit:500}).then(d=>{DFILES={at:Date.now(),d,err:'',busy:false};renderDetails();renderCharts();})
      .catch(e=>{DFILES={at:Date.now(),d:null,err:String(e&&e.message||e),busy:false};renderDetails();renderCharts();});}
  return DFILES;
}
const fmtBytes=b=>b<1024?b+' B':b<MB?Math.round(b/1024)+' KB':b<1024*MB?nf(b/MB,b<10*MB?1:0)+' MB':nf(b/MB/1024,1)+' GB';
const dfBusy=f=>f.read_bps+f.write_bps>=1024;
/* “↓ 2 MB/s ↑ 40 KB/s” if it is going on now, otherwise the total since watching started */
function dfAmount(f){
  const bps=v=>v<100*1024?Math.max(1,Math.round(v/1024))+' KB/s':fmtMBs(v/MB);
  if(dfBusy(f))return [f.read_bps>=512?'↓ '+bps(f.read_bps):'',f.write_bps>=512?'↑ '+bps(f.write_bps):''].filter(Boolean).join(' ');
  return [f.read?'read '+fmtBytes(f.read):'',f.write?'written '+fmtBytes(f.write):''].filter(Boolean).join(' · ');
}
function dfName(f){
  if(!f.path)return {name:'files opened before watching started',dir:'Windows does not report their names — only bytes are visible',full:''};
  const i=f.path.lastIndexOf('\\');return {name:f.path.slice(i+1)||f.path,dir:i>0?f.path.slice(0,i):'',full:f.path};
}
const dfSince=d=>{const s=Math.round(d.since_s);return s<60?`${s} s`:`${Math.floor(s/60)} min ${s%60} s`;};
/* one file in several processes of an app — one row */
function dfMerge(list){
  const m=new Map();
  for(const f of list){const k=f.path.toLowerCase(),x=m.get(k);
    if(!x){m.set(k,{...f,pids:[f.pid]});continue;}
    for(const p of ['read','write','reads','writes','read_bps','write_bps'])x[p]+=f[p];x.idle_s=Math.min(x.idle_s,f.idle_s);x.pids.push(f.pid);}
  return [...m.values()].sort((a,b)=>(dfBusy(b)-dfBusy(a))||(dfBusy(a)?(b.read_bps+b.write_bps)-(a.read_bps+a.write_bps):(b.read+b.write)-(a.read+a.write)));
}
function detailFiles(tree,pids,secOpen){
  const open=secOpen('files');
  const head=`<details class="dsec" data-s="files" ${open}><summary>${CHEV}Files on disk<span class="caption">what the ${tree.length>1?'app reads':'process reads'} and writes</span></summary><div class="kids">`;
  if(!isAdmin())return head+`<div class="caption" style="padding:4px 8px">Windows reports which files processes read and write only to a program with administrator rights.${ADMIN_LINK}</div></div></details>`;
  if(!open)return head+'</div></details>';
  const D=diskFiles();
  if(DFILES.err&&!D.d)return head+`<div class="caption" style="padding:4px 8px">${esc(DFILES.err)}</div></div></details>`;
  if(!D.d)return head+'<div class="caption" style="padding:4px 8px">Starting to watch…</div></div></details>';
  const rows=dfMerge(D.d.files.filter(f=>pids.has(f.pid)));
  const who=f=>tree.length>1?` <span class="caption">· ${f.pids.slice(0,3).join(', ')}</span>`:'';
  return head+(rows.length?rows.slice(0,14).map(f=>{const x=dfName(f);
      return `<div class="kid2 df" title="${esc(x.full||x.dir)}"><span><span class="df-n">${esc(x.name)}${who(f)}</span><span class="caption df-d">${esc(x.dir)}</span></span><span class="caption num">${esc(dfAmount(f))}</span></div>`;}).join('')
    :`<div class="caption" style="padding:4px 8px">No reads or writes in ${dfSince(D.d)} of watching.</div>`)
    +`<div class="caption" style="padding:2px 8px">Watching for ${dfSince(D.d)}${rows.length>14?` · ${rows.length-14} more`:''} · reads and writes through the Windows cache count too: not all of it reached the disk itself</div></div></details>`;
}
/* the disk’s “More”: who writes what right now across the whole system */
function chartFiles(){
  if(!isAdmin())return `<div class="note">Which files processes read and write is visible only with administrator rights.${ADMIN_LINK}</div>`;
  const D=diskFiles();
  if(!D.d)return `<div class="note">${DFILES.err?esc(DFILES.err):'Starting to watch files…'}</div>`;
  const rows=D.d.files.slice(0,12);
  if(!rows.length)return `<div class="note">Files: no reads or writes in ${dfSince(D.d)} of watching.</div>`;
  return `<div class="dfs"><div class="dfs-h">Files · watching for ${dfSince(D.d)}</div>${rows.map(f=>{const x=dfName(f),n=nodeByPid(f.pid);
    return `<div class="dfs-r" ${n?`data-id="${esc(n.id)}"`:''} title="${esc(x.full||x.dir)}"><span class="dfs-p">${esc(n?nameOf(n):'PID '+f.pid)}</span><span class="dfs-f">${esc(x.name)} <span class="caption">${esc(x.dir)}</span></span><span class="num">${esc(dfAmount(f))}</span></div>`;}).join('')}</div>`;
}
/* Chromium browser tabs: the list is read the same way screen readers do (UI Automation).
   Which renderer serves which tab the browser does not expose — so the list belongs to the whole browser. */
const BROWSERS=new Set(['chrome.exe','msedge.exe','brave.exe','opera.exe','vivaldi.exe','browser.exe','chromium.exe','thorium.exe','arc.exe','comet.exe']);
let BTABS={pid:0,at:0,tabs:null,err:'',busy:false};
function browserTabs(pid){
  if(!BTABS.busy&&(BTABS.pid!==pid||Date.now()-BTABS.at>10000)){BTABS.busy=true;
    rpc('browser_tabs',{pid}).then(r=>{BTABS={pid,at:Date.now(),tabs:r.tabs,wins:r.windows||[],err:'',busy:false};renderDetails();})
      .catch(e=>{BTABS={pid,at:Date.now(),tabs:null,err:String(e&&e.message||e),busy:false};renderDetails();});}
  return BTABS.pid===pid?BTABS:null;
}
function detailTabs(n,secOpen){
  const a=appOf(n),root=a&&nodeByPid(a.rootPid);
  if(!root||!BROWSERS.has(root.exe.toLowerCase()))return '';
  /* what the browser says about this process; for a process without a label — how to get one */
  const bt=BTASKS.tasks.get(n.id),i=INFO.get(n.id),page=i&&i.role&&/^(Renderer|Extension)/.test(i.role);
  let own='';
  if(bt&&bt.length>1)own=`<details class="dsec" data-s="ptasks" open><summary>${CHEV}What is in this process<span class="caption">${bt.length}</span></summary><div class="kids">${bt.map(t=>`<div class="kid2" title="${esc(t)}"><span class="df-n">${esc(taskText(t))}</span><span></span></div>`).join('')}</div></details>`;
  else if(!bt&&page)own=`<div class="caption" style="padding:6px 12px">Which tab this is, the browser tells only in its own task manager: press <b>Shift+Esc</b> in it — the processes get labelled while that window is open${BTASKS.open?' (the window is open: scroll its list if this process is not visible there)':''}.</div>`;
  const open=secOpen('tabs'),T=open?browserTabs(root.pid):(BTABS.pid===root.pid?BTABS:null),list=T&&T.tabs;
  const cap=list?`${list.length} ${plural(list.length,'tab','tabs','tabs')}${list.some(t=>t.sleeping)?` · ${list.filter(t=>t.sleeping).length} unloaded`:''}`:'what is open';
  let h=own+`<details class="dsec" data-s="tabs" ${open}><summary>${CHEV}Browser tabs<span class="caption">${cap}</span></summary><div class="kids">`;
  if(!open)return h+'</div></details>';
  if(!T||(!list&&!T.err))return h+'<div class="caption" style="padding:4px 8px">Reading tabs…</div></div></details>';
  if(!list)return h+`<div class="caption" style="padding:4px 8px">${esc(T.err)}</div></div></details>`;
  /* by window; a fullscreen window hides its tab strip — only its open tab (the window title) is visible */
  const W=T.wins||[],nw=Math.max(W.length,...list.map(t=>t.window+1)),row=(title,st,dim)=>`<div class="kid2${dim?' dim':''}" title="${esc(title)}"><span class="df-n">${esc(title)}</span><span class="caption num">${esc(st)}</span></div>`;
  for(let i=0;i<nw;i++){
    const tabs=list.filter(t=>t.window===i);
    if(nw>1)h+=`<div class="caption" style="padding:6px 8px 2px">Window ${i+1}</div>`;
    if(!tabs.length){if(W[i])h+=row(W[i].replace(/\s+[-–—]\s+[^-–—]+$/,''),'open · other tabs of the window are not visible (fullscreen?)');continue;}
    for(const t of tabs)h+=row(t.title,[t.audio?'♪ audio':'',t.sleeping?'unloaded':'',t.mem_mb!=null?(t.sleeping?'freed ':'')+fmtMem(t.mem_mb):''].filter(Boolean).join(' · '),t.sleeping);
  }
  return h+'<div class="caption" style="padding:2px 8px">Memory as the browser itself reports it. Which process serves which tab the browser shows only in its own task manager (Shift+Esc): while it is open, the processes here get labelled.</div></div></details>';
}
function detailExtras(n,secOpen){
  const svcs=SVC_BY_PID.get(n.pid)||[];
  /* network — of the whole app: in a browser the connections are held by a child “network” process, not the main one */
  if(Date.now()-DCONN.at>3000&&!DCONN.busy){DCONN.busy=true;
    rpc('connections').then(d=>{DCONN={at:Date.now(),list:d.connections,busy:false};renderDetails();}).catch(()=>{DCONN={at:Date.now(),list:DCONN.list,busy:false};});}
  const tree=appDesc(n),pids=new Set(tree.map(x=>x.pid));
  const conns=DCONN.list?DCONN.list.filter(c=>pids.has(c.pid)):[];
  let h=detailTabs(n,secOpen)+detailFiles(tree,pids,secOpen);
  if(svcs.length)h+=`<details class="dsec" data-s="svcs" ${secOpen('svcs')}><summary>${CHEV}Services in the process<span class="caption">${svcs.length}</span></summary>
    <div class="kids">${svcs.slice(0,20).map(s=>`<div class="kid2"><span>${esc(s.display)}</span><span class="caption">${esc(s.name)}</span></div>`).join('')}${svcs.length>20?`<div class="caption" style="padding:2px 8px">and ${svcs.length-20} more</div>`:''}</div></details>`;
  if(conns.length){
    const lis=dedupConns(conns.filter(c=>c.state==='listen'||c.proto==='udp')),est=dedupConns(conns.filter(c=>c.state!=='listen'&&c.proto==='tcp'&&c.pid!==0));
    const ne=est.reduce((a,x)=>a+x.n,0),nl=lis.length;
    const who=x=>tree.length>1&&x.c.pid!==n.pid?` <span class="caption">· ${x.c.pid}</span>`:'';
    const times=x=>x.n>1?` ×${x.n}`:'';
    h+=`<details class="dsec" data-s="net" ${secOpen('net')}><summary>${CHEV}Network${tree.length>1?' of the app':''}<span class="caption">${ne} ${plural(ne,'connection','connections','connections')} · ${nl} ${plural(nl,'port','ports','ports')}</span></summary><div class="kids">
      ${lis.slice(0,8).map(x=>`<div class="kid2"><span class="mono">${x.c.proto.toUpperCase()} ${esc(hostPort(x.c.local,x.c.local_port))}${who(x)}</span><span class="caption">${x.c.proto==='udp'?'open':'listening'}${times(x)}</span></div>`).join('')}
      ${est.slice(0,12).map(x=>`<div class="kid2"><span class="mono">→ ${esc(hostPort(x.c.remote,x.c.remote_port))}${who(x)}</span><span class="caption">${CONN_STATE[x.c.state]||x.c.state}${times(x)}</span></div>`).join('')}
      ${lis.length>8||est.length>12?'<div class="caption" style="padding:2px 8px">the rest is in the Network tab</div>':''}</div></details>`;
  }
  return h;
}

/* =================================================================
   Right panel: Details
   ================================================================= */
const SEC={kids:true,info:true,svcs:true,net:true};
function renderDetails(){
  const body=$('#details');if(!rightOn()||!vis(body))return;
  const n=NODES.get(S.sel);
  if(!n||!SYS){body.innerHTML='<div class="empty">Select a process in the list, on the map or on the chart.</div>';body._id=null;return;}
  if(body._id===n.id&&selIn(body)){renderDetailChart();return;}
  body._id=n.id;
  const r=curRes(),dead=!n.alive,kids=aliveKids(n),iss=ISS.get(n.id)||[],f=n.full||{},i=INFO.get(n.id)||{};
  const secOpen=k=>SEC[k]?'open':'';
  const mm=r.m==='net'?'cpu':r.m,c=COLS_ALL.find(c=>c.m===mm);
  const kidsHTML=kids.slice().sort((a,b)=>cur(b,mm,true)-cur(a,mm,true)).slice(0,10).map(k=>`<div class="kid" data-go="${esc(k.id)}">${ico(k)}<span>${esc(nameOf(k))}${ISS.has(k.id)?` <span class="dot ${ISS.get(k.id).some(i=>i.lvl==='red')?'red':'yel'}"></span>`:''}</span><span class="v">${c.fmt(cur(k,mm,true))}</span><span class="v">${fmtMem(cur(k,'mem',true))}</span></div>`).join('');
  const started=ctToMs(n.ct);
  if(PSEUDO[n.pid]){
    /* not a process: no path, no start time, no actions — just an explanation and a chart */
    body.innerHTML=`<div class="dt-h">${ico(n,1)}<div style="min-width:0"><h3>${esc(nameOf(n))}</h3><div class="caption">Windows kernel load, not a process</div></div></div>
     <div class="dchart"><div class="caption"><span class="d-cap"></span><span><span class="num d-now"></span><button class="ib d-max"></button></span></div><canvas class="d-cv"></canvas><div class="pop"></div></div>
     <p class="caption" style="padding:0 16px;line-height:1.5">${n.pid===4294967293
       ?'Time the processors spend handling interrupts from devices: network, disks, USB, audio. More than 5–10 % for a long time is usually a device driver.'
       :'Deferred procedure calls (DPC): the second half of interrupt handling, driver work. A constantly high share is a sign of a problematic driver (often network, audio or the GPU).'}
     As in System Informer, this load is shown as a separate row instead of being attributed to the “System” process.</p>`;
    renderDetailChart();return;
  }
  body.innerHTML=`
   <div class="dt-h">${ico(n,1)}<div style="min-width:0"><h3>${esc(nameOf(n))}</h3><div class="caption">${esc(n.exe)} · PID ${n.pid}${i.company?' · '+esc(i.company):''}</div></div></div>
   ${dead?`<div class="dead-note">The process exited ${agoStr((NOW-n.deadAt)/1000)} ago.</div>`:''}
   ${iss.map(x=>`<div class="issue ${x.lvl}"><span class="dot ${x.lvl}"></span><span>${esc(x.txt)}</span></div>`).join('')}
   ${dead?'':`<div class="acts">
     <button class="btn danger" data-a="kill">End</button>
     ${kids.length?`<button class="btn" data-a="tree">With children (${desc(n).length})</button>`:''}
     <button class="btn" data-a="suspend">${n.susp?'Resume':'Suspend'}</button>
     <button class="btn subtle" data-a="open" title="Open the process history in a separate tab">Open separately</button>
     <button class="btn subtle" data-a="more" title="All actions">More…</button></div>`}
   ${ancestors(n).length?`<div class="crumbs"><span class="caption" style="margin-right:4px">Started by:</span>${ancestors(n).map(a=>`<a data-go="${esc(a.id)}">${esc(nameOf(a))}</a>`).join('<span class="sep">›</span>')}</div>`:''}
   <div class="dchart"><div class="caption"><span class="d-cap"></span><span><span class="num d-now"></span><button class="ib d-max"></button></span></div><canvas class="d-cv"></canvas><div class="pop"></div></div>
   ${kids.length?`<details class="dsec" data-s="kids" ${secOpen('kids')}><summary>${CHEV}Child processes<span class="caption">${kids.length}</span></summary><div class="kids">${kidsHTML}${kids.length>10?`<div class="caption" style="padding:2px 8px">and ${kids.length-10} more</div>`:''}</div></details>`:''}
   ${dead?'':detailExtras(n,secOpen)}
   <details class="dsec" data-s="info" ${secOpen('info')}><summary>${CHEV}Info</summary>
   <dl class="kv">
     <dt>PID</dt><dd class="num">${n.pid}</dd>
     <dt>Started</dt><dd>${agoStr(Math.max(0,NOW-started)/1000)} ago · ${new Date(started).toLocaleString('en-GB',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}</dd>
     ${i.description?`<dt>Description</dt><dd>${esc(i.description)}</dd>`:''}
     <dt>Path</dt><dd class="mono">${i.path?esc(i.path):`no access — administrator rights needed.${isAdmin()?'':ADMIN_LINK}`}</dd>
     ${i.path||f.path?`<dt>Signature</dt><dd class="d-sig">${sigHTML(f.path||i.path)}</dd>`:''}
     ${f.cmdline?`<dt>Command line</dt><dd class="mono">${esc(f.cmdline)}</dd>`:''}
     ${i.company?`<dt>Publisher</dt><dd>${esc(i.company)} <span class="caption">(from the file properties)</span></dd>`:''}
     <dt>Total CPU</dt><dd>${agoStr(n.cpuMs/1000)}</dd>
     <dt>Memory</dt><dd>${fmtMem(n.mem)} private working set · ${fmtMem(n.ws)} full working set · ${fmtMem(n.priv)} committed</dd>
     ${NETPP?`<dt>Network</dt><dd>↓ ${fmtMbit(n.nrx)} · ↑ ${fmtMbit(n.ntx)}${netSplit(n)}</dd>`:''}
     ${n.gpu>=.05||n.gmem>=1?`<dt>GPU</dt><dd>${fmtPct(n.gpu)} · video memory ${fmtMem(n.gmem)}${GK.length?'<br>'+GPUS.filter(g=>(n['g:'+g.key]||0)>=.05).map(g=>`${esc(gpuShort(g))}: ${fmtPct(n['g:'+g.key])}`).join(' · '):''}</dd>`:''}
     <dt>Threads</dt><dd class="num">${n.threads}</dd><dt>Handles</dt><dd class="num">${n.handles.toLocaleString('en')}</dd>
     <dt>Session</dt><dd class="num">${n.session}${n.session===0?' (services)':''}</dd>
     <dt>Priority</dt><dd>${PRIO_NAMES[n.prio]||'—'}</dd>
     ${appOf(n)?`<dt>App</dt><dd>${esc(appOf(n).title)} · processes: ${appOf(n).count}</dd>`:''}
   </dl></details>`;
  renderDetailChart();
}
function renderDetailChart(){
  const body=$('#details');if(!rightOn()||!vis(body))return;
  const cv=$('.d-cv',body),n=NODES.get(S.sel);if(!cv||!n)return;
  maxMark(cv.parentElement,'max',S.max==='detail',$('.d-max',body));
  const r=curRes(),mm=r.m==='net'?'cpu':r.m,c=COLS_ALL.find(c=>c.m===mm);
  $('.d-now',body).textContent=c.fmt(cur(n,mm,true));
  const s=nodeSeries(n,mm);
  $('.d-cap',body).textContent=`${c.t}${s&&s.caption?' · '+s.caption:''} · ${S.range.label}`;
  if(!s){drawTS(cv,{series:[],t0:NOW,step:1000,fmt:c.fmt,empty:'Loading history…'});return;}
  drawTS(cv,{series:[{name:c.t,color:PAL[r.m==='net'?0:r.col],data:s.data}],t0:s.t0,step:s.step,missing:s.missing,fmt:c.fmt,fill:true});
}
$('#details').addEventListener('click',e=>{
  if(e.target.closest('.d-max')){setMax('detail');return;}
  const vt=e.target.closest('[data-vt]');if(vt){e.preventDefault();openVirusTotal(vt.dataset.vt);return;}
  const a=e.target.closest('[data-a]');
  if(a){if(a.dataset.a==='more'){const r=a.getBoundingClientRect();openMenu(r.left,r.bottom+4,[S.sel]);}else if(a.dataset.a==='open')openProcTab(S.sel);else act(a.dataset.a,[S.sel]);return;}
  const j=e.target.closest('[data-go]');if(j)select(j.dataset.go,true);
});
$('#details').addEventListener('toggle',e=>{const d=e.target.closest('.dsec');if(d){SEC[d.dataset.s]=d.open;if(d.open&&(d.dataset.s==='files'||d.dataset.s==='tabs'))setTimeout(renderDetails);}},true);
$('#details').addEventListener('dblclick',e=>{if(e.target.closest('.d-cv'))setMax('detail');});
$('#details').addEventListener('mousemove',e=>{const cv=e.target.closest('canvas');if(cv)chartHover(cv,cv.nextElementSibling,e);});
$('#details').addEventListener('mouseout',e=>{if(e.target.tagName==='CANVAS'){S.hoverT=null;e.target.nextElementSibling.style.display='none';renderCharts();}});

/* =================================================================
   Layout: the main area on dockview + the bottom and right panels
   ================================================================= */
const DV=window['dockview-core'];
/* main tabs cannot be closed — only switched and dragged;
   only single-process tabs have a close button */
const FIXED=['procs','map','pool','svcs','conns'];
const dock=DV.createDockview($('#dock'),{
  theme:DV.themeDark,
  createTabComponent:o=>{
    if(o.name!=='fixed')return undefined;
    const el=document.createElement('div');el.className='dv-default-tab';
    const t=document.createElement('div');t.className='dv-default-tab-content';el.appendChild(t);
    let sub=null;
    return {element:el,init(p){t.textContent=p.title||(p.api&&p.api.title)||'';sub=p.api&&p.api.onDidTitleChange?p.api.onDidTitleChange(e=>{t.textContent=e.title;}):null;},dispose(){if(sub&&sub.dispose)sub.dispose();}};
  },
  createComponent:o=>{
    const el=document.createElement('div');el.className='pnl';
    if(o.name==='procs'){PANEL_EL.procs=el;mountProcs(el);}
    else if(o.name==='map'){PANEL_EL.map=el;mountMap(el);}
    else if(o.name==='pool'){PANEL_EL.pool=el;mountPool(el);}
    else if(o.name==='svcs'){PANEL_EL.svcs=el;mountSvcs(el);}
    else if(o.name==='conns'){PANEL_EL.conns=el;mountConns(el);}
    else if(o.name==='proc'){mountProcTab(el,String(o.id).slice(5));}
    new ResizeObserver(()=>{if(!DRAGGING&&vis(el)){renderAll();flushNeeds();}}).observe(el);
    return {element:el,init(){},dispose(){if(o.name==='proc')PROC_TABS.delete(String(o.id).slice(5));}};
  },
  /* floating windows are off: a detached main tab could not be closed */
  disableFloatingGroups:true,
});
const dockEl=$('#dock');
const relayout=()=>{if(dockEl.clientWidth)dock.layout(dockEl.clientWidth,dockEl.clientHeight);};
new ResizeObserver(relayout).observe(dockEl);
relayout();
function defaultLayout(){
  dock.clear();
  dock.addPanel({id:'procs',component:'procs',tabComponent:'fixed',title:'Processes'});
  dock.addPanel({id:'map',component:'map',tabComponent:'fixed',title:'Map',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'pool',component:'pool',tabComponent:'fixed',title:'Kernel pool',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'svcs',component:'svcs',tabComponent:'fixed',title:'Services',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'conns',component:'conns',tabComponent:'fixed',title:'Network',position:{referencePanel:'procs',direction:'within'},inactive:true});
}
const LAYOUT_KEY='tm-layout-3';
let restored=false;
try{const j=localStorage.getItem(LAYOUT_KEY);if(j){const L=JSON.parse(j);delete L.floatingGroups;delete L.popoutGroups;for(const k of FIXED)if(L.panels&&L.panels[k])L.panels[k].tabComponent='fixed';dock.fromJSON(L);for(const p of dock.panels.slice())if(p.id.startsWith('proc:')||p.id==='docker')p.api.close(); /* the Docker tab is gone — remove it from an old layout */restored=!!dock.getPanel('procs')||!!dock.getPanel('map');}}catch(e){restored=false;}
if(!restored)defaultLayout();
/* a main tab may have been left in a discarded floating window — return it to the common group */
function ensureFixed(){const ref=FIXED.map(k=>dock.getPanel(k)).find(Boolean);
  for(const [k,t] of [['procs','Processes'],['map','Map'],['pool','Kernel pool'],['svcs','Services'],['conns','Network']])if(!dock.getPanel(k))dock.addPanel({id:k,component:k,tabComponent:'fixed',title:t,inactive:!!ref,...(ref?{position:{referencePanel:ref.id,direction:'within'}}:{})});}
ensureFixed();
/* a saved layout remembers old tab titles */
for(const [k,t] of [['procs','Processes'],['map','Map'],['pool','Kernel pool'],['svcs','Services'],['conns','Network']]){const c=dock.getPanel(k);if(c&&c.title!==t)c.api.setTitle(t);}
const saveLayout=()=>{try{localStorage.setItem(LAYOUT_KEY,JSON.stringify(dock.toJSON()));}catch(e){}};
/* right after restoring: removed tabs (Docker) must not stay in the saved layout */
saveLayout();
dock.onDidLayoutChange(saveLayout);
dock.onDidActivePanelChange(()=>requestAnimationFrame(()=>{renderAll();flushNeeds();}));

/* Narrow window: Details (below 900 px) and the resources on the left (below 700 px) slide over the list instead of
   squeezing it to zero (at 420 px nothing was left of the center). Such a panel opens
   with a button or a shortcut and closes with Esc or a click outside; the saved “always show” settings
   are not touched — widen the window and everything is as it was. */
var DRAWER=null,NARROW_AT=''; /* var and function: select() and drawing may call them before execution reaches these lines */
function overlay(z){return innerWidth<(z==='rail'?700:900);}
function railOn(){return overlay('rail')?DRAWER==='rail':S.rail;}
function rightOn(){return overlay('right')?DRAWER==='right':S.right;}
/* ResizeObserver, not just resize: the window event does not always come (and sometimes comes before the width changes) */
function checkNarrow(){const k=`${overlay('rail')}${overlay('right')}`;if(k===NARROW_AT)return;NARROW_AT=k;if(DRAWER&&!overlay(DRAWER))DRAWER=null;applyShell();}
addEventListener('resize',checkNarrow);new ResizeObserver(checkNarrow).observe(document.documentElement);
/* a click outside a slid-out panel closes it */
document.addEventListener('pointerdown',e=>{if(!DRAWER||DIALOG)return;const z=$('#'+DRAWER);
  if(z.contains(e.target)||e.target.closest('#tglRail,#tglRight,.menu'))return;DRAWER=null;applyShell();},true);
/* sizes go right on the panel: an inherited CSS variable on #shell forced restyling every element */
function sizeZones(){$('#bottom').style.height=S.bh+'px';$('#right').style.width=S.rw+'px';}
function applyShell(){
  const sh=$('#shell');
  NARROW_AT=`${overlay('rail')}${overlay('right')}`;
  sh.classList.toggle('ov-rail',overlay('rail'));sh.classList.toggle('ov-right',overlay('right'));document.body.classList.toggle('narrow',overlay('rail'));
  sh.classList.toggle('no-rail',!railOn());sh.classList.toggle('no-main',!S.main);sh.classList.toggle('no-bottom',!S.bottom);sh.classList.toggle('no-right',!rightOn());
  sizeZones();
  $('#tglRail').classList.toggle('on',railOn());$('#tglMain').classList.toggle('on',S.main);$('#tglBottom').classList.toggle('on',S.bottom);$('#tglRight').classList.toggle('on',rightOn());
  $('#btabs').querySelectorAll('[data-t]').forEach(b=>b.classList.toggle('on',b.dataset.t===S.btab));
  $('#bChart').hidden=S.btab!=='chart';$('#bLog').hidden=S.btab!=='log';
  requestAnimationFrame(()=>{relayout();renderAll();flushNeeds();});
}
const toggleBottom=v=>{S.bottom=v==null?!S.bottom:v;if(!S.bottom)S.main=true;if(!S.bottom&&S.max==='bottom'){S.max=null;maxMark($('#shell'),'max-bottom',false,$('#maxBottom'));}saveUI();applyShell();};
/* the center is never empty: tabs hidden — show the bottom panel, and vice versa */
const toggleMain=v=>{S.main=v==null?!S.main:v;if(!S.main){S.bottom=true;if(S.max==='bottom'){S.max=null;maxMark($('#shell'),'max-bottom',false,$('#maxBottom'));}}saveUI();applyShell();};
const drawer=(z,v)=>{DRAWER=(v==null?DRAWER!==z:v)?z:DRAWER===z?null:DRAWER;applyShell();};
const toggleRail=v=>{if(overlay('rail'))return drawer('rail',v);S.rail=v==null?!S.rail:v;saveUI();applyShell();};
const toggleRight=v=>{if(overlay('right'))return drawer('right',v);S.right=v==null?!S.right:v;saveUI();applyShell();};
$('#tglRail').addEventListener('click',()=>toggleRail());$('#tglMain').addEventListener('click',()=>toggleMain());
$('#tglBottom').addEventListener('click',()=>toggleBottom());
$('#maxBottom').addEventListener('click',()=>setMax('bottom'));maxMark($('#shell'),'max-bottom',false,$('#maxBottom'));
$('#tglRight').addEventListener('click',()=>toggleRight());
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.dataset.close==='bottom'?toggleBottom(false):toggleRight(false)));
function sash(id,apply){
  const s=$(id);let start,base;
  let raf=0;
  s.addEventListener('pointerdown',e=>{if(e.button!==0)return;e.preventDefault();s.setPointerCapture(e.pointerId);s.classList.add('drag');start={x:e.clientX,y:e.clientY};base={bh:S.bh,rw:S.rw};DRAGGING=true;});
  /* the size changes right away on every move (that is ~2 ms), and the charts redraw once per frame —
     otherwise the stretched canvases jittered; data requests go out only after release */
  const move=e=>{apply(e.clientX-start.x,e.clientY-start.y,base);sizeZones();relayout();
    if(!raf)raf=requestAnimationFrame(()=>{raf=0;renderAll();});};
  s.addEventListener('pointermove',e=>{if(start)move(e);});
  const end=e=>{if(!start)return;if(e&&e.type==='pointerup')move(e);start=null;DRAGGING=false;s.classList.remove('drag');
    if(s.hasPointerCapture&&e&&s.hasPointerCapture(e.pointerId))s.releasePointerCapture(e.pointerId);saveUI();renderAll();flushNeeds();};
  s.addEventListener('pointerup',end);s.addEventListener('pointercancel',end);s.addEventListener('lostpointercapture',end);
}
sash('#sashB',(dx,dy,b)=>{S.bh=clamp(b.bh-dy,160,Math.max(160,innerHeight-260));});
sash('#sashR',(dx,dy,b)=>{S.rw=clamp(b.rw-dx,280,Math.max(280,Math.min(640,innerWidth-700)));});

/* top row */
function renderTop(){
  $('#range').innerHTML=RANGES.map(r=>`<button data-k="${r.key}" class="${S.range===r?'on':''}">${r.label}</button>`).join('');
  const all=[...ISS.entries()].map(([id,i])=>({n:NODES.get(id),lvl:i.some(z=>z.lvl==='red')?'red':'yel'})).filter(x=>alive(x.n));
  const red=all.filter(x=>x.lvl==='red').length,yel=all.length-red;
  $('#issues').innerHTML=all.length?`${red?`<span class="dot red"></span>${red} ${red===1?'problem':'problems'}`:''}${yel?`<span class="dot yel" style="margin-left:${red?8:0}px"></span>${yel} ${yel===1?'warning':'warnings'}`:''}`:'<span class="dot" style="background:var(--success)"></span>All quiet';
  $('#issues')._list=all;
  $('#host').innerHTML=SYSINFO?(SYSINFO.elevated?'<span class="chip adm">administrator</span>':'')+(TAURI?'':' <span class="chip">development mode</span>'):'';
}
$('#range').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;S.range=RANGES.find(r=>r.key===b.dataset.k);try{localStorage.setItem('tm-range',S.range.key);}catch(x){}renderAll();renderMap(true);flushNeeds();});
let issIdx=0;
$('#issues').addEventListener('click',()=>{const l=$('#issues')._list||[];if(!l.length)return;const s=l.slice().sort((a,b)=>(a.lvl==='red'?0:1)-(b.lvl==='red'?0:1));select(s[issIdx++%s.length].n.id,true);});
let paused=false,autostart=null;
$('#moreBtn').addEventListener('click',async e=>{
  const r=e.currentTarget.getBoundingClientRect();menuIds=null;
  if(TAURI&&autostart===null){try{autostart=await appCmd('autostart_get');}catch(x){}}
  menu.innerHTML=`<div class="mi" data-g="pause"><span>${paused?'Resume updates':'Pause updates'}</span></div>
    <div class="mi" data-g="reset"><span>Reset layout</span></div>
    <div class="sep"></div><div class="mh">Panels</div>
    <div class="mi" data-g="rail"><span><span class="ck">${railOn()?'✓':''}</span> Resources and charts (left)</span><kbd>Ctrl+B</kbd></div>
    <div class="mi" data-g="main"><span><span class="ck">${S.main?'✓':''}</span> Tabs: processes, map… (center)</span></div>
    <div class="mi" data-g="bottom"><span><span class="ck">${S.bottom?'✓':''}</span> Chart and log (bottom)</span><kbd>Ctrl+J</kbd></div>
    <div class="mi" data-g="right"><span><span class="ck">${rightOn()?'✓':''}</span> Details (right)</span><kbd>Ctrl+Alt+B</kbd></div><div class="sep"></div>
    ${SYSINFO&&SYSINFO.elevated?'':'<div class="mi" data-g="admin"><span>Restart as administrator</span></div>'}
    ${TAURI?`<div class="mi" data-g="autostart"><span>${autostart?'✓ ':''}Start with Windows</span></div><div class="mi" data-g="hide"><span>Minimize to tray</span><kbd>Esc</kbd></div><div class="sep"></div><div class="mi danger" data-g="quit"><span>Exit (history collection stops)</span></div>`:''}`;
  menu.style.display='block';menu.style.left=Math.min(r.right-280,innerWidth-290)+'px';menu.style.top=r.bottom+4+'px';
});
menu.addEventListener('click',async e=>{const mi=e.target.closest('[data-g]');if(!mi)return;const g=mi.dataset.g;closeMenu();
  try{
    if(g==='pause')paused=!paused;
    else if(g==='reset'){try{localStorage.removeItem(LAYOUT_KEY);}catch(x){}defaultLayout();Object.assign(S,{bh:300,rw:360,rail:true,bottom:true,right:true});saveUI();applyShell();}
    else if(g==='rail')toggleRail();
    else if(g==='main')toggleMain();
    else if(g==='bottom')toggleBottom();
    else if(g==='right')toggleRight();
    else if(g==='admin')await runAdmin();
    else if(g==='autostart'){autostart=await appCmd('autostart_set',!autostart);toast(autostart?'Taskscope will start with Windows (in the tray)':'Autostart turned off','info');}
    else if(g==='hide')await appCmd('hide');
    else if(g==='quit')await appCmd('quit');
  }catch(err){toast(err.message||String(err),'red');}
  requestAnimationFrame(renderAll);
});
document.addEventListener('keydown',e=>{
  if(e.ctrlKey&&!e.altKey&&e.code==='KeyJ'){e.preventDefault();toggleBottom();return;}
  if(e.ctrlKey&&e.altKey&&e.code==='KeyB'){e.preventDefault();toggleRight();return;}
  if(e.ctrlKey&&!e.altKey&&!e.shiftKey&&e.code==='KeyB'){e.preventDefault();toggleRail();return;}
  if(e.ctrlKey&&e.code==='KeyF'){const q=PANEL_EL.procs&&$('.p-q',PANEL_EL.procs);if(q){e.preventDefault();q.focus();q.select();}return;}
  if(e.target.matches('input'))return;
  if(e.key==='Delete'&&S.sel){act(e.shiftKey?'tree':'kill',[...(S.multi.size?S.multi:[S.sel])]);return;}
  if(!DIALOG&&menu.style.display!=='block'&&procKeys(e)){e.preventDefault();return;}
  if(e.key==='Escape'){if(menu.style.display==='block')closeMenu();else if(DRAWER){DRAWER=null;applyShell();}else if(S.max)setMax(S.max);else if(mapUp()){}else if(TAURI)appCmd('hide').catch(()=>{});}
});

function renderAll(){if(!SYS)return;RES=resList();renderTop();renderRail();renderChart();renderLog();renderProcs();renderMap();renderPool();renderSvcs();renderConns();fetchSvcNames();renderDetails();renderProcTabs();}

/* =================================================================
   Main loop: wait for the engine’s next sample (long polling).
   While the window is hidden (minimized to the tray) — no polling and no drawing.
   ================================================================= */
let BOOTING=true;
async function backfill(){
  /* after the window is shown: fill in the sparklines for the time the window was hidden */
  const list=[...NODES.values()].filter(alive);
  try{
    const [c,io]=await Promise.all([rpc('sparks',{groups:list.map(n=>[[n.pid,n.ct]]),metric:'cpu',points:SPARKN}),rpc('sparks',{groups:list.map(n=>[[n.pid,n.ct]]),metric:'io',points:SPARKN})]);
    list.forEach((n,i)=>{rfill(n.rc,c[i]);rfill(n.rio,io[i].map(v=>v/MB));});
  }catch(e){}
}
async function loop(){
  for(;;){
    const away=document.hidden||window.__tmHidden;
    if(away||paused){needBackfill=needBackfill||away;await sleep(400);continue;}
    try{
      const s=await rpc('tick',{after:SEQ,after_event:EVSEQ});
      if(s.seq!==SEQ){
        applySnap(s);
        if(BOOTING){
          SYSINFO=await rpc('sysinfo').catch(()=>null);
          $('#adminBtn').hidden=!SYSINFO||!!SYSINFO.elevated;
          if(!S.sel){const t=[...NODES.values()].filter(alive).sort((a,b)=>b.cpu-a.cpu)[0];}
          $('#boot').style.display='none';
        }
        await ensureInfos();
        if(needBackfill){needBackfill=false;await backfill();}
        renderAll();flushNeeds();
        BOOTING=false;
      }
    }catch(e){if(!BOOTING)showErr(e);await sleep(BOOTING?200:1000);}
  }
}
document.addEventListener('visibilitychange',()=>{if(!document.hidden){needBackfill=true;}});
applyShell();
loadSettings().then(()=>renderAll());
loop();
