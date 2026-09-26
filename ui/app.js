'use strict';
/* =================================================================
   Диспетчер задач — интерфейс.
   Данные: движок на Rust (Service::call). В приложении — через Tauri,
   в режиме разработки (`tm serve`) — через POST /rpc. Логика одна.
   ================================================================= */

/* ----- утилиты ----- */
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
const nf=(v,d=1)=>v.toFixed(d).replace('.',',');
const MB=1048576;
const fmtMem=mb=>mb>=1024?nf(mb/1024,mb>=10240?1:2)+' ГБ':mb>=10?Math.round(mb)+' МБ':nf(mb,1)+' МБ';
const fmtPct=v=>v<0.05?'0 %':v<10?nf(v)+' %':Math.round(v)+' %';
const fmtMBs=v=>v<0.005?'0':v<0.1?Math.round(v*1024)+' КБ/с':v<10?nf(v)+' МБ/с':Math.round(v)+' МБ/с';
const fmtMbit=v=>v<0.005?'0 Мбит/с':v<0.1?Math.round(v*1000)+' Кбит/с':v<10?nf(v)+' Мбит/с':Math.round(v)+' Мбит/с';
const hexA=(hex,a)=>{const n=parseInt(hex.slice(1),16);return `rgba(${n>>16},${n>>8&255},${n&255},${a})`;};
const agoStr=s=>s<60?Math.round(s)+' с':s<3600?Math.round(s/60)+' мин':s<86400?Math.floor(s/3600)+' ч '+Math.round(s%3600/60)+' мин':Math.floor(s/86400)+' д '+Math.floor(s%86400/3600)+' ч';
const CHEV='<svg width="10" height="10" viewBox="0 0 10 10"><path d="M3.5 1.5 7 5l-3.5 3.5" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICON_WARN='<svg width="16" height="16" viewBox="0 0 16 16"><path d="M8 1.8 15 14H1z" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M8 6.2v3.8M8 11.8v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
const ICON_INFO='<svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="6" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M7 6.2v3.6M7 4.2v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const ctToMs=ct=>(ct-116444736000000000)/10000;

/* ----- связь с движком ----- */
const TAURI=window.__TAURI__;
async function rpc(method,params={}){
  if(TAURI)return TAURI.core.invoke('rpc',{method,params});
  const r=await fetch('/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,params})});
  const j=await r.json();if(j.error)throw new Error(j.error);return j.result;
}
async function appCmd(cmd,arg=null){
  if(!TAURI)throw new Error('доступно только в приложении');
  return TAURI.core.invoke('app_cmd',{cmd,arg});
}

/* ----- палитры ----- */
const PAL=['#486de8','#e07f9d','#018977','#b088f5','#c55305','#8ea9ff','#ffb0c8','#40bfa9','#d6baff','#f89256'];
const OTHER='#5f6b7a';
const CATS={
  browser:{n:'Браузеры',c:'#3f7fd9'},
  dev:{n:'Разработка',c:'#8456ce'},
  ai:{n:'ИИ-инструменты',c:'#d9822b'},
  docker:{n:'Docker / WSL',c:'#1f9e89'},
  comm:{n:'Общение',c:'#c33d69'},
  media:{n:'Медиа и игры',c:'#b8a226'},
  vpn:{n:'Сеть и VPN',c:'#5aa33b'},
  security:{n:'Безопасность',c:'#9e4a2f'},
  system:{n:'Windows',c:'#6b7785'},
  other:{n:'Другое',c:'#7d746a'},
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
   Модель: живые процессы, дерево, приложения
   ================================================================= */
const SPARKN=300; // 5 минут посекундно — для мини-графиков и «карты» за короткий период
const ring=()=>({a:new Float32Array(SPARKN),i:0,n:0});
function rpush(r,v){r.a[r.i]=v;r.i=(r.i+1)%SPARKN;if(r.n<SPARKN)r.n++;}
function rtail(r,k){const out=new Array(k).fill(0);const m=Math.min(k,r.n);for(let j=0;j<m;j++)out[k-1-j]=r.a[(r.i-1-j+SPARKN)%SPARKN];return out;}
function rfill(r,vals){r.a.fill(0);r.i=0;r.n=0;for(const v of vals.slice(-SPARKN))rpush(r,v);}

const NODES=new Map();           // "pid:время создания" → узел
const INFO=new Map();            // id → {path, description, company, role}
const ICONS=new Map();           // путь в нижнем регистре → data URL | null
let APPS=new Map(), NETS=[], GPUS=[], NETPP=false, MEMD=null, ISS=new Map(), EVENTS=[];
const SHORT_R=new Map();const shortAvg=(k,n)=>{const r=SHORT_R.get(k);if(!r)return 0;const t=rtail(r,Math.min(n,r.n||1));return t.reduce((s,v)=>s+v,0)/Math.max(1,t.length);};
let SYS=null, SYSINFO=null, SEQ=0, EVSEQ=0, NOW=Date.now(), CPUS=1, TOTAL_MB=1;
let NEWKEYS=[], needBackfill=true;

function applySnap(s){
  SEQ=s.seq;const f=s.frame;SYS=f.system;NOW=f.at_ms;CPUS=SYS.logical_cpus;TOTAL_MB=SYS.memory.total/MB;
  const seen=new Set();
  for(const p of f.procs){
    if(p.pid===0)continue;
    const id=p.pid+':'+p.create_time;
    let n=NODES.get(id);
    if(!n){n={id,pid:p.pid,ct:p.create_time,exe:p.name,kids:[],parent:null,rc:ring(),rio:ring(),appKey:null};NODES.set(id,n);NEWKEYS.push(id);}
    n.alive=true;n.ppid=p.ppid;n.cpu=p.cpu;n.mem=p.mem/MB;n.rd=p.io_read_bps/MB;n.wr=p.io_write_bps/MB;n.dsk=n.rd+n.wr;
    n.threads=p.threads;n.handles=p.handles;n.session=p.session;n.susp=!!p.suspended;n.cpuMs=p.cpu_time_ms;n.ws=p.working_set/MB;n.priv=p.private_bytes/MB;n.bprio=p.base_priority;n.gpu=p.gpu||0;n.gmem=(p.gpu_mem||0)/MB;n.nrx=(p.net_rx_bps||0)*8/1e6;n.ntx=(p.net_tx_bps||0)*8/1e6;n.net=n.nrx+n.ntx;
    rpush(n.rc,n.cpu);rpush(n.rio,n.dsk);seen.add(id);
  }
  for(const n of NODES.values()){
    if(n.alive&&!seen.has(n.id)){n.alive=false;n.deadAt=NOW;n.cpu=0;n.dsk=0;n.rd=0;n.wr=0;n.kids=[];}
    // завершённые держим 2 минуты (или пока выбраны / открыты во вкладке)
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
  /* ЦП коротких процессов — посекундно по приложениям ('' — не отнесённое никому) */
  const shortSeen=new Set();
  for(const a of APPS.values())if(a.short>0||SHORT_R.has(a.key)){if(!SHORT_R.has(a.key))SHORT_R.set(a.key,ring());rpush(SHORT_R.get(a.key),a.short);shortSeen.add(a.key);}
  if(!SHORT_R.has(''))SHORT_R.set('',ring());rpush(SHORT_R.get(''),SYS.unseen_cpu||0);shortSeen.add('');
  for(const [k,r] of SHORT_R)if(!shortSeen.has(k)){rpush(r,0);if(rtail(r,SPARKN).every(v=>!v))SHORT_R.delete(k);}
  NETS=s.nets||[];GPUS=s.gpus||[];NETPP=!!s.net_per_process;MEMD=s.mem_detail||null;POOLA=s.pool_alerts||[];
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
/* из чего состоит занятая память вне частной памяти процессов (МБ) */
function memParts(){
  const rest=Math.max(0,SYS.memory.used/MB-privateMB());
  if(!MEMD)return [{label:'Ядро, драйверы и кэши Windows',v:rest}];
  const d={np:MEMD.pool_nonpaged/MB,pp:MEMD.pool_paged/MB,cache:MEMD.cache/MB,code:MEMD.kernel_code/MB,mod:MEMD.modified/MB};
  const known=d.np+d.pp+d.cache+d.code+d.mod;
  return [
    {label:'Невыгружаемый пул ядра (драйверы)',v:d.np,warn:d.np>1024},
    {label:'Выгружаемый пул ядра',v:d.pp},
    {label:'Файловый кэш',v:d.cache},
    {label:'Код ядра и драйверов',v:d.code},
    {label:'Ждёт записи на диск',v:d.mod},
    {label:'Общая память программ (DLL, общие буферы)',v:Math.max(0,rest-known)},
  ];
}
const aliveKids=n=>n.alive?n.kids:[];
function desc(n){const out=[];const st=[n];const seen=new Set();while(st.length){const x=st.pop();if(seen.has(x))continue;seen.add(x);out.push(x);if(x.alive)for(const k of x.kids)st.push(k);}return out;}
/* суммы по поддереву считаются один раз на замер — сортировка и таблица берут готовые */
let AGG=new Map(),AGG_SEQ=-1;
function agg(n){
  if(AGG_SEQ!==SEQ){AGG=new Map();AGG_SEQ=SEQ;}
  let a=AGG.get(n.id);if(a)return a;
  /* Σ — только процессы того же приложения. Программы, запущенные из процесса
     (из Проводника запускается почти всё), в его сумму не входят: они — отдельные приложения.
     all — сумма по всему поддереву, для подсказки «со всем, что запущено из него». */
  const own=()=>({cpu:n.cpu||0,mem:n.mem||0,dsk:n.dsk||0,rd:n.rd||0,wr:n.wr||0,gpu:n.gpu||0,net:n.net||0});
  a={...own(),all:own(),cnt:1,spark:null};AGG.set(n.id,a);
  if(n.alive)for(const k of n.kids){
    const b=agg(k),same=k.appKey===n.appKey;a.cnt+=b.cnt;
    for(const f of ['cpu','mem','dsk','rd','wr','gpu','net']){a.all[f]+=b.all[f];if(same)a[f]+=b[f];}
  }
  return a;
}
function cur(n,m,incl){return incl?agg(n)[m]||0:n[m]||0;}
const curAll=(n,m)=>agg(n).all[m]||0;
const sameApp=n=>n.alive?n.kids.filter(k=>k.appKey===n.appKey):[];
/* потомки того же приложения (для графиков «вместе с дочерними») */
function appDesc(n){const out=[],st=[n];while(st.length){const x=st.pop();out.push(x);st.push(...sameApp(x));}return out;}
function sparkSum(n){
  const a=agg(n);if(a.spark)return a.spark;
  const s=rtail(n.rc,120);for(const k of sameApp(n)){const t=sparkSum(k);for(let i=0;i<120;i++)s[i]+=t[i];}
  return a.spark=s;
}
function ancestors(n){const a=[];const seen=new Set([n]);for(let p=n.parent;p&&!seen.has(p);p=p.parent){seen.add(p);a.unshift(p);}return a;}
/* псевдопроцессы движка: время ЦП на прерывания и отложенные вызовы (DPC) — не программы */
const PSEUDO={4294967293:'Прерывания',4294967294:'Отложенные вызовы (DPC)'};
const procCount=()=>{let c=0;for(const n of NODES.values())if(n.alive&&!PSEUDO[n.pid])c++;return c;};
const appOf=n=>n&&n.appKey?APPS.get(n.appKey):null;
function catOf(n){const a=appOf(n);const i=INFO.get(n.id);return catOfExe(a?a.key:n.exe,i?i.path:(a&&a.path));}
function nameOf(n){
  if(PSEUDO[n.pid])return PSEUDO[n.pid];
  /* svchost.exe — по службам внутри, как в System Informer */
  const sv=n.exe==='svchost.exe'&&SVC_BY_PID.get(n.pid);
  if(sv&&sv.length)return sv.length===1?sv[0].display:`${sv[0].display} и ещё ${sv.length-1}`;
  const i=INFO.get(n.id),a=appOf(n);
  if(i&&i.role)return i.role;
  if(a&&a.rootPid===n.pid&&a.key!=='windows')return a.title;
  if(i&&i.description&&i.description.length<60)return i.description;
  return n.exe.replace(/\.exe$/i,'');
}
const label=n=>nameOf(n);

/* ----- проблемы (жёлтые / красные значки) — считает движок ----- */
function worstIn(n){let w=null;for(const x of appDesc(n)){if(x===n)continue;const i=ISS.get(x.id);if(i){if(i.some(z=>z.lvl==='red'))return 'red';w='yel';}}return w;}

/* =================================================================
   Состояние интерфейса
   ================================================================= */
const RANGES=[
  {key:'2m',label:'2 мин',ms:120e3},
  {key:'15m',label:'15 мин',ms:900e3},
  {key:'1h',label:'1 ч',ms:3600e3},
  {key:'3h',label:'3 ч',ms:3*3600e3},
  {key:'12h',label:'12 ч',ms:12*3600e3},
  {key:'24h',label:'24 ч',ms:86400e3},
];
const S={
  range:RANGES[0],res:'cpu',sel:null,multi:new Set(),hoverT:null,hl:null,
  procMode:'tree',incl:true,sort:'cpu',dir:-1,q:'',open:new Set(),freeze:false,order:null,
  map:{color:'exe',root:null},chartMode:'apps',rail:true,main:true,right:true,bottom:true,btab:'chart',more:false,bh:300,rw:360,
};
try{const r=RANGES.find(r=>r.key===localStorage.getItem('tm-range'));if(r)S.range=r;}catch(e){}
try{const u=JSON.parse(localStorage.getItem('tm-ui')||'{}');for(const k of ['chartMode','rail','main','right','bottom','btab','res','bh','rw','more','procMode','incl'])if(k in u)S[k]=u[k];}catch(e){}
const saveUI=()=>{try{localStorage.setItem('tm-ui',JSON.stringify({chartMode:S.chartMode,rail:S.rail,main:S.main,right:S.right,bottom:S.bottom,btab:S.btab,res:S.res,bh:S.bh,rw:S.rw,more:S.more,procMode:S.procMode,incl:S.incl}));}catch(e){}};
/* настройки общие с CLI и MCP (%LOCALAPPDATA%	msettings.json): защищённые процессы, подтверждение */
let SETTINGS={protected:[],confirm_kill:true};
const stem=x=>String(x).toLowerCase().replace(/\.exe$/,'');
const isProt=n=>SETTINGS.protected.some(p=>!/[\\/]/.test(p)&&stem(p)===stem(n.exe));
async function loadSettings(){
  try{SETTINGS={...SETTINGS,...await rpc('settings_get')};}catch(e){return;}
  /* перенос старого списка защищённых из localStorage окна */
  try{const old=JSON.parse(localStorage.getItem('tm-protect')||'[]');const add=old.filter(x=>!SETTINGS.protected.some(p=>stem(p)===stem(x)));
    if(add.length){SETTINGS.protected.push(...add);await saveSettings();}localStorage.removeItem('tm-protect');}catch(e){}
}
async function saveSettings(){try{await rpc('settings_set',SETTINGS);}catch(e){toast('Настройки не сохранены: '+(e.message||e),'red',6000);}}
let DRAGGING=false;
const vis=el=>!!el&&el.isConnected&&el.clientWidth>0&&el.clientHeight>0;
function openPath(n){for(let x=n;x.parent&&x.parent.appKey===x.appKey;x=x.parent)S.open.add(x.parent.id);}

/* =================================================================
   Данные истории: запросы копятся при отрисовке и уходят одной пачкой
   ================================================================= */
const HC=new Map();   // ключ запроса → {at, res}
const NEED=new Map(); // ключ → {method, params, ttl}
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
/* пересчёт единиц: память и ввод-вывод приходят в байтах */
const conv=m=>m==='mem'||m==='dsk'?(v=>v/MB):m==='net'?(v=>v*8/1e6):(v=>v);

/* =================================================================
   Действия
   ================================================================= */
function toast(txt,lvl='info',ms=4200,btn=null){const el=document.createElement('div');el.className='toast';el.innerHTML=`<span class="dot ${lvl==='red'?'red':lvl==='yel'?'yel':''}" style="${lvl==='ok'?'background:var(--success)':lvl==='info'?'background:var(--accent)':''}"></span><span>${esc(txt)}</span>`;if(btn){const b=document.createElement('button');b.className='btn';b.textContent=btn.t;b.onclick=()=>{el.remove();btn.f();};el.appendChild(b);}$('#toasts').appendChild(el);setTimeout(()=>el.remove(),ms);}
function showErr(e){const b=$('#errbar');b.textContent='Нет связи с движком: '+(e&&e.message||e);b.style.display='block';clearTimeout(showErr.t);showErr.t=setTimeout(()=>b.style.display='none',4000);}
const PRIO_NAMES={idle:'Низкий',below_normal:'Ниже среднего',normal:'Обычный',above_normal:'Выше среднего',high:'Высокий'};
async function doAct(action,nodes,opts={}){
  const targets=nodes.map(n=>[n.pid,n.ct]);
  try{return await rpc('act',{action,targets,tree:!!opts.tree,priority:opts.priority||null,dry_run:!!opts.dry,force:!!opts.force,confirmed:!!opts.confirmed});}
  catch(e){toast(e.message||String(e),'red',6000);return null;}
}
/* отказы и неудачи — одним сообщением; «не закрылся» — с кнопкой «принудительно» */
function reportBad(r,action,opts){
  const bad=r.results.filter(x=>!x.ok);if(!bad.length)return;
  const b=bad[0],who=b.name||('PID '+b.pid);
  const forceable=bad.filter(x=>x.can_force);
  if(forceable.length&&action==='kill'){
    const nodes=forceable.map(x=>NODES.get(x.pid+':'+x.create_time)).filter(alive);
    toast(`${who}: ${b.error}${bad.length>1?` (и ещё ${bad.length-1})`:''}`,'yel',12000,nodes.length?{t:'Завершить принудительно',f:()=>runAct('kill',nodes,{...opts,force:true,confirmed:true})}:null);
  }else if(bad.length>1&&!r.results.some(x=>x.ok))
    toast(`Не выполнено: ${who} — ${b.error}. Не затронуто процессов: ${bad.length}.`,'red',9000);
  else toast(`Не выполнено: ${who} — ${b.error}${bad.length>1?` (и ещё ${bad.length-1})`:''}`,'red',b.error.length>60?9000:6500);
}
const VERBS={kill:'Завершить',suspend:'Приостановить',resume:'Возобновить',restart:'Перезапустить'};
let DIALOG=null; /* одно окно подтверждения за раз */
/* окно подтверждения: цели и отказы — из пробного прогона ядра (dry_run), те же правила, что у tm kill */
function dialog({title,body,ok,danger,check}){
  return new Promise(res=>{
    const bg=document.createElement('div');bg.className='modal-bg';
    bg.innerHTML=`<div class="modal" role="dialog" aria-modal="true" aria-labelledby="m-title"><h3 id="m-title">${esc(title)}</h3><div class="m-body scroll">${body}</div>
      ${check?`<label class="m-check"><input type="checkbox"> ${esc(check)}</label>`:''}
      <div class="m-acts"><button class="btn" data-r="0">Отмена</button>${ok?`<button class="btn ${danger?'danger-fill':'primary'}" data-r="1">${esc(ok)}</button>`:''}</div></div>`;
    const prevFocus=document.activeElement;
    const done=v=>{const c=bg.querySelector('.m-check input');bg.remove();DIALOG=null;document.removeEventListener('keydown',key,true);if(prevFocus&&prevFocus.focus)prevFocus.focus();res(v?{check:!!(c&&c.checked)}:null);};
    const key=e=>{
      /* пока окно открыто, горячие клавиши списка (Delete и т.п.) не срабатывают */
      e.stopImmediatePropagation();
      if(e.repeat){e.preventDefault();return;} /* удержанный Enter не подтверждает действие */
      if(e.key==='Escape'){e.preventDefault();done(false);}
      else if(e.key==='Enter'&&!e.target.matches('input')){e.preventDefault();done(e.target.dataset.r==='1');}
      else if(e.key==='Tab'){const f=[...bg.querySelectorAll('button,input')];const i=f.indexOf(document.activeElement);e.preventDefault();f[(i+(e.shiftKey?f.length-1:1))%f.length].focus();}
    };
    bg.addEventListener('click',e=>{const b=e.target.closest('[data-r]');if(b)done(b.dataset.r==='1');else if(e.target===bg)done(false);});
    document.addEventListener('keydown',key,true);
    document.body.appendChild(bg);DIALOG=bg;
    const mb=bg.querySelector('.m-body');if(mb.scrollHeight>mb.clientHeight+1)mb.classList.add('over');
    /* для опасного действия фокус — на «Отмена»: Enter по привычке ничего не завершит */
    (danger||!ok?bg.querySelector('[data-r="0"]'):bg.querySelector('[data-r="1"]')).focus();
  });
}
function targetRows(rs,why){
  const shown=rs.slice(0,12);
  return shown.map(r=>{const n=NODES.get(r.pid+':'+r.create_time);
    return `<div class="m-row">${n?ico(n):'<span class="m-ico"></span>'}<span class="m-n">${esc(n?nameOf(n):r.name||('PID '+r.pid))}</span><span class="caption num">${r.pid}</span><span class="caption num m-mem">${n?fmtMem(cur(n,'mem',false)):''}</span></div>${why&&r.error?`<div class="m-why">${esc(r.error)}</div>`:''}${!why&&r.note?`<div class="m-why warn">${esc(r.note.replace(/^внимание: /,''))}</div>`:''}`;
  }).join('')+(rs.length>shown.length?`<div class="caption m-more">и ещё ${rs.length-shown.length}</div>`:'');
}
/* действие с подтверждением. Завершение и перезапуск спрашивают всегда (одиночное завершение — пока не
   выбрано «больше не спрашивать»); приостановка — если затронет несколько процессов или есть предупреждение */
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
      /* корни — первыми в списке, чтобы было видно, чьё это дерево */
      const roots=new Set(nodes.map(x=>x.pid+':'+x.ct));
      ok.sort((a,b)=>roots.has(b.pid+':'+b.create_time)-roots.has(a.pid+':'+a.create_time));
      const title=opts.tree?`${VERBS[action]} «${label(n)}» и дочерние (${ok.length})?`:ok.length>1?`${VERBS[action]} процессы: ${ok.length}?`:`${VERBS[action]} «${label(n)}»?`;
      const win=ok.filter(x=>x.window).length;
      const lead={
        kill:win===ok.length?'Программу сначала попросят закрыться, как при закрытии её окна, — она успеет сохранить данные.'
          :win?'Программам с окном сначала предложат закрыться самим — они успеют сохранить данные. Остальные процессы завершатся сразу.'
          :'Процесс завершится сразу; несохранённые данные в нём пропадут.',
        restart:'Процесс будет завершён и запущен заново с тем же файлом, командной строкой, папкой и правами. Несохранённые данные в нём пропадут.',
        suspend:'Приостановленный процесс не получает время процессора и не отвечает, пока его не возобновят. Окна и память остаются на месте.',
        resume:''}[action];
      const body=`${lead?`<p class="m-lead">${lead}</p>`:''}
        ${others.size?`<div class="m-warn">${ICON_WARN}<span>Вместе с ним завершатся программы, запущенные из него: ${esc([...others.values()].slice(0,8).join(', '))}${others.size>8?` и ещё ${others.size-8}`:''}.</span></div>`:''}
        <div class="m-list">${targetRows(ok,false)}</div>
        ${bad.length?`<div class="m-sub">Не будут затронуты</div><div class="m-list">${targetRows(bad,true)}</div>`:''}`;
      const r=await dialog({title,body,ok:VERBS[action],danger:action==='kill'||action==='restart',check:action==='kill'&&single&&!warn.length?'Больше не спрашивать при завершении одного процесса':null});
      if(!r)return;
      if(r.check){SETTINGS.confirm_kill=false;saveSettings();}
    }
    opts={...opts,confirmed:true};
  }
  const slow=action==='kill'&&!opts.force?setTimeout(()=>toast('Жду, пока программа закроется сама…','info',5000),700):0;
  const r=await doAct(action,nodes,opts);clearTimeout(slow);
  if(!r)return;
  reportBad(r,action,opts);
  const done=r.results.filter(x=>x.ok);if(!done.length)return renderAll();
  const more=done.length>1?` и ещё ${done.length-1}`:'';
  if(action==='kill'){
    toast(`Завершено: ${label(n)}${more} — освобождено ${fmtMem(r.freed/MB)}`,'ok');
    if(S.sel&&done.some(x=>x.pid+':'+x.create_time===S.sel)){const p=NODES.get(S.sel)?.parent;S.sel=p&&p.alive?p.id:null;}
  }else if(action==='suspend')toast(`${label(n)}${more}: приостановлен. ЦП = 0, окна и память на месте.`,'info');
  else if(action==='resume')toast(`${label(n)}${more}: возобновлён`,'info');
  else if(action==='restart')toast(`${label(n)} перезапущен${done[0].new_pid?` (новый PID ${done[0].new_pid})`:''}`,'ok');
  renderAll();
}
async function info(n,full){
  if(full){try{const r=await rpc('info',{pid:n.pid,create_time:n.ct});n.full=r.info;n.prio=r.priority;return r.info;}catch(e){return null;}}
  return INFO.get(n.id);
}
async function act(a,ids){
  /* прерывания и DPC — строки нагрузки ядра: действовать не над чем, кроме отдельной вкладки */
  if(a!=='open')ids=ids.filter(id=>!PSEUDO[(NODES.get(id)||{}).pid]);
  const nodes=ids.map(id=>NODES.get(id)).filter(alive);if(!nodes.length)return;
  const n=nodes[0];
  if(a==='kill')return runAct('kill',nodes);
  if(a==='tree')return runAct('kill',nodes,{tree:true});
  /* приостановка по умолчанию — только сам процесс; с дочерними — отдельный пункт */
  if(a==='suspend'||a==='suspend_tree'){
    const on=!nodes.every(x=>x.susp);
    return runAct(on?'suspend':'resume',nodes,{tree:a==='suspend_tree'||!on});
  }
  if(a==='restart')return runAct('restart',[n]);
  if(a.startsWith('prio:')){
    const p=a.slice(5);const r=await doAct('priority',nodes,{priority:p});
    if(r){reportBad(r,'priority',{});if(r.ok){nodes.forEach(x=>x.prio=p);toast(`${label(n)}: приоритет «${PRIO_NAMES[p]}»`,'info');}}
  }else if(a==='folder'){const i=INFO.get(n.id);if(!i||!i.path)return toast('Путь к файлу недоступен (нужны права администратора)','yel');rpc('reveal',{path:i.path}).catch(e=>toast(e.message,'red'));}
  else if(a==='web'){const i=INFO.get(n.id);rpc('web',{q:`${n.exe} ${i&&i.company?i.company+' ':''}что это за процесс`}).catch(e=>toast(e.message,'red'));}
  else if(a==='copycmd'){const f=await info(n,true);if(!f||!f.cmdline)return toast('Командная строка недоступна','yel');try{await navigator.clipboard.writeText(f.cmdline);toast('Командная строка скопирована','info');}catch(e){toast('Не удалось скопировать','red');}}
  else if(a==='protect'){
    const on=isProt(n);
    SETTINGS.protected=on?SETTINGS.protected.filter(p=>stem(p)!==stem(n.exe)):[...SETTINGS.protected,n.exe.toLowerCase()];
    await saveSettings();
    toast(on?`${n.exe}: защита снята`:`${n.exe}: защищён — его не завершат ни окно, ни tm kill, ни ИИ-агент`,'info');
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
    it.push({h:nameOf(n)},{t:'Открыть отдельной вкладкой',a:'open'});
  }else{
  it.push({h:many?`Выбрано: ${ids.length}`:`${nameOf(n)} · PID ${n.pid}`});
  it.push({t:many?'Завершить выбранные':'Завершить',a:'kill',k:'Del',d:1});
  if(hasKids)it.push({t:'Завершить вместе с дочерними',a:'tree',k:'Shift+Del',d:1});
  it.push('-',{t:sp?'Возобновить':'Приостановить',a:'suspend'});
  if(hasKids&&!sp)it.push({t:'Приостановить с дочерними',a:'suspend_tree'});
  it.push({t:'Перезапустить',a:'restart',d:1});
  it.push('-',{h:'Приоритет'},...['idle','below_normal','normal','above_normal','high'].map(p=>({t:PRIO_NAMES[p],a:'prio:'+p,c:n.prio===p})));
  it.push('-',{t:'Открыть отдельной вкладкой',a:'open'},{t:'Открыть расположение файла',a:'folder'},{t:'Копировать командную строку',a:'copycmd'},{t:'Что это за процесс?',a:'web'},{t:isProt(n)?'Снять защиту':'Защитить от завершения',a:'protect'});
  }
  menu.innerHTML=it.map(i=>i==='-'?'<div class="sep"></div>':i.h?`<div class="mh">${esc(i.h)}</div>`:`<div class="mi${i.d?' danger':''}" data-a="${i.a}"><span>${i.c?'✓ ':''}${esc(i.t)}</span>${i.k?`<kbd>${i.k}</kbd>`:''}</div>`).join('');
  menu.style.display='block';const r=menu.getBoundingClientRect();
  menu.style.left=Math.min(x,innerWidth-r.width-8)+'px';menu.style.top=Math.max(8,Math.min(y,innerHeight-r.height-8))+'px';
  if(!n.prio&&!PSEUDO[n.pid])info(n,true);
}
const closeMenu=()=>{menu.style.display='none';menuIds=null;};
document.addEventListener('pointerdown',e=>{if(!menu.contains(e.target))closeMenu();},true);
menu.addEventListener('click',e=>{const mi=e.target.closest('.mi[data-a]');if(!mi||!menuIds)return;const ids=menuIds;closeMenu();act(mi.dataset.a,ids);});
function select(id,reveal){S.sel=id;if(!S.right)toggleRight(true);S.multi=new Set([id]);const n=NODES.get(id);if(n){if(reveal)openPath(n);info(n,true).then(()=>renderDetails());}renderAll();if(reveal)requestAnimationFrame(()=>revealRow(id));}

/* =================================================================
   Графики (стиль CloudWatch / Cloudscape)
   ================================================================= */
function prep(cv){
  const r=devicePixelRatio||1,w=cv.clientWidth,h=cv.clientHeight;
  if(!w||!h)return [null,0,0];
  if(cv.width!==Math.round(w*r)||cv.height!==Math.round(h*r)){cv.width=Math.round(w*r);cv.height=Math.round(h*r);}
  const x=cv.getContext('2d');x.setTransform(r,0,0,r,0,0);x.clearRect(0,0,w,h);return [x,w,h];
}
function niceMax(v){if(v<=0)return 1;const p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;return (f<=1?1:f<=2?2:f<=2.5?2.5:f<=5?5:10)*p;}
function tLabel(ms,step){const d=new Date(ms);const hh=String(d.getHours()).padStart(2,'0'),mm=String(d.getMinutes()).padStart(2,'0');return step<5000?`${hh}:${mm}:${String(d.getSeconds()).padStart(2,'0')}`:`${hh}:${mm}`;}
const stepStr=ms=>ms<60e3?Math.round(ms/1000)+' с':Math.round(ms/60e3)+' мин';
/* o: {series:[{name,color,data,key?,nodeId?}], t0, step, stacked, fmt, max, fill, missing} */
function drawTS(cv,o){
  const [x,w,h]=prep(cv);if(!x)return;
  const n=Math.max(2,o.series.reduce((m,s)=>Math.max(m,s.data.length),0));
  let mx=0;
  for(let i=0;i<n;i++){let s=0;for(const se of o.series){const v=se.data[i]||0;s=o.stacked?s+v:Math.max(s,v);}mx=Math.max(mx,s);}
  const max=o.max||niceMax(mx*1.08||1);
  x.font='12px "Segoe UI Variable Text","Segoe UI",sans-serif';
  /* слева — по самой широкой подписи шкалы: «375 МБ/с» не влезала в фиксированные 52 px */
  const padL=Math.max(40,Math.ceil(Math.max(...[1,.75,.5,.25].map(k=>x.measureText(o.fmt(max*k)).width)))+12),padR=6,padT=6,padB=20,W=w-padL-padR,H=h-padT-padB;
  if(!o.series.length||(mx<1e-6&&!o.max)){x.fillStyle='rgba(255,255,255,.5442)';x.textAlign='center';x.textBaseline='middle';x.strokeStyle='#424650';x.beginPath();x.moveTo(padL,Math.round(padT+H)+.5);x.lineTo(padL+W,Math.round(padT+H)+.5);x.stroke();x.fillText(o.empty||'Нет активности за период',padL+W/2,padT+H/2);cv._g=null;return;}
  x.textBaseline='middle';x.strokeStyle='#424650';x.lineWidth=1;x.fillStyle='#c6c6cd';x.textAlign='right';
  const TK=H<90?2:4;for(let k=0;k<=TK;k++){const y=Math.round(padT+H-H*k/TK)+.5;x.beginPath();x.moveTo(padL,y);x.lineTo(padL+W,y);x.stroke();x.fillText(o.fmt(max*k/TK),padL-6,y);}
  x.textAlign='center';x.textBaseline='top';
  const X=i=>padL+W*i/(n-1);
  const XT=W<420?2:4;for(let k=0;k<=XT;k++){const i=Math.round(k*(n-1)/XT);x.fillText(tLabel(o.t0+i*o.step,o.step),clamp(X(i),padL+22,padL+W-22),padT+H+5);}
  const Y=v=>padT+H-clamp(v/max,0,1.02)*H;
  /* часть периода до запуска движка — данных нет */
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
  pop.innerHTML=`<div class="pt">${tLabel(S.hoverT,o.step)}${o.step>1000?` · среднее за ${stepStr(o.step)}`:''}${total!=null?` · всего <b>${o.fmt(total)}</b>`:''}</div>`+rows.map(r=>`<div class="pr"><i style="background:${r.se.color}"></i><span>${esc(r.se.name)}</span><b>${o.fmt(r.v)}</b></div>`).join('');
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

/* ----- иконки: настоящая из .exe, пока не загрузилась — буква на цвете категории ----- */
function ico(n,l){
  const i=INFO.get(n.id),a=appOf(n);const path=(i&&i.path)||(a&&a.rootPid===n.pid&&a.path)||'';
  const src=path&&ICONS.get(path.toLowerCase());
  if(src)return `<img class="ico${l?' l':''}" src="${src}" alt="">`;
  const c=CATS[catOf(n)]||CATS.other;const ch=(nameOf(n).replace(/^[^A-Za-zА-Яа-яЁё0-9]+/,'')[0]||'?');
  return `<span class="ico${l?' l':''}" style="background:${hexA(c.c,.55)};box-shadow:inset 0 0 0 1px ${hexA(c.c,.9)}">${esc(ch.toUpperCase())}</span>`;
}
let iconsBusy=false;
/* data:-адрес превращаем в короткий blob:-адрес: таблица перерисовывается каждую секунду,
   и длинный base64 в каждой строке заставлял бы браузер заново разбирать и декодировать картинки */
function blobUrl(d){try{const b=atob(d.slice(d.indexOf(',')+1)),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return URL.createObjectURL(new Blob([u],{type:'image/png'}));}catch(e){return d;}}
async function ensureInfos(){
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
   Ресурсы (левая полоса). Выбор ресурса переключает всё окно.
   ================================================================= */
function resList(){
  if(!SYS)return [];
  const m=SYS.memory,ioR=[...NODES.values()].reduce((s,n)=>s+(n.alive?n.rd:0),0),ioW=[...NODES.values()].reduce((s,n)=>s+(n.alive?n.wr:0),0);
  const out=[
    {id:'cpu',name:'Процессор',m:'cpu',col:0,max:100,fmt:fmtPct,sub:SYSINFO&&SYSINFO.cpu_name,hist:['system','cpu'],
     now:()=>SYS.cpu,line:v=>`${fmtPct(v)} · ${procCount()} процессов`,
     keys:v=>[`${CPUS} логических процессоров`,`${procCount()} процессов`,`потоков ${SYS.threads.toLocaleString('ru')}`],
     more:()=>[['Дескрипторы',SYS.handles.toLocaleString('ru')],['Прерывания',fmtPct(SYS.interrupt_cpu||0)],['Отложенные вызовы (DPC)',fmtPct(SYS.dpc_cpu||0)],['Время работы',agoStr(SYS.uptime_ms/1000)]],
     get note(){return SYS.by_cycles
       ?'Загрузка считается по тактам процессора, как в System Informer: точнее, чем по времени, и не теряет процессы, завершившиеся между замерами. Прерывания и DPC — отдельными строками в списке процессов.'
       :'Загрузка считается по времени процессора: счётчик тактов недоступен (виртуальная машина или больше 64 процессоров). Прерывания и DPC — отдельными строками в списке процессов.';}},
    {id:'mem',name:'Память',m:'mem',col:2,max:TOTAL_MB,fmt:fmtMem,sub:`${nf(TOTAL_MB/1024,1)} ГБ`,hist:['system','mem'],
     now:()=>m.used/MB,line:v=>`${nf(v/1024,1)} / ${nf(TOTAL_MB/1024,1)} ГБ (${m.load_pct} %)`,
     keys:v=>[`${m.load_pct} % занято`,`доступно ${fmtMem(m.available/MB)}`,`выделено ${nf(m.commit_used/MB/1024,1)} / ${nf(m.commit_limit/MB/1024,1)} ГБ`],
     more:()=>[['Занято',fmtMem(m.used/MB)],['Доступно',fmtMem(m.available/MB)],
       ...(MEMD&&MEMD.standby?[['· резерв (кэш)',fmtMem(MEMD.standby/MB)],['· свободно',fmtMem((MEMD.free||0)/MB)]]:[]),['Выделено (commit)',fmtMem(m.commit_used/MB)],['Предел выделения',fmtMem(m.commit_limit/MB)],['Процессы (частная)',fmtMem(privateMB())],
       ...memParts().map(p=>[p.label,fmtMem(p.v)+(p.warn?' — больше обычного':'')]),
       ...(MEMD&&MEMD.compressed?[['Сжатая память (входит в занятое)',fmtMem(MEMD.compressed/MB)]]:[]),
       ...POOLA.map(a=>['Тревога в ядре',a.text.split('. ')[0]+' — вкладка «Пул ядра»'])],
     note:'Доступно = резерв + свободно: резерв — файловый кэш из недавно прочитанных файлов, Windows отдаёт его программам по первому требованию. Сжатая память — страницы, которые Windows сжала вместо выгрузки на диск; она уже входит в «Занято». «Память» процесса — его частный рабочий набор, как в диспетчере Windows. Остальное занятое: пулы ядра (память драйверов), файловый кэш и общая память программ — библиотеки DLL и общие буферы, которыми пользуются сразу несколько процессов (особенно браузеры и Electron-приложения). Невыгружаемый пул больше 1 ГБ бывает при утечке памяти в драйвере — какой драйвер растёт, видно во вкладке «Пул ядра».'},
    ...GPUS.map(g=>{
      const short=g.name.replace(/\((TM|R)\)/g,'').replace(/^(NVIDIA GeForce|NVIDIA|AMD|Intel) /,'').trim();
      return {id:'gpu:'+g.key,name:GPUS.length>1?'Видеокарта · '+short:'Видеокарта',m:'gpu',gpu:g,col:3,max:100,fmt:fmtPct,sub:g.name,hist:['gpu','gpu','gpu:'+g.key],
        now:()=>g.util,line:v=>`${fmtPct(v)} · ${nf(g.mem_used/MB/1024,1)} / ${nf(g.mem_total/MB/1024,1)} ГБ`,
        keys:v=>[g.engine?`занят блок ${g.engine}`:'',`видеопамять ${fmtMem(g.mem_used/MB)} из ${fmtMem(g.mem_total/MB)}`,`общая ${fmtMem(g.shared_used/MB)}`].filter(Boolean),
        more:()=>[['Загрузка',fmtPct(g.util)],['Самый занятый блок',g.engine||'—'],['Выделенная видеопамять',`${fmtMem(g.mem_used/MB)} из ${fmtMem(g.mem_total/MB)}`],['Общая память',fmtMem(g.shared_used/MB)]],
        note:'Загрузка — самый занятый блок видеокарты (3D, видео, копирование, вычисления), как в диспетчере Windows. Процессу приписывается его самый занятый блок, поэтому сумма по процессам может быть больше загрузки карты. Разбивка по приложениям — общая для всех видеокарт.'};
    }),
    {id:'disk',name:'Диск',m:'dsk',col:4,fmt:fmtMBs,hist:['system','io'],
     now:()=>ioR+ioW,line:v=>`↓ ${fmtMBs(ioR)} ↑ ${fmtMBs(ioW)}`,
     keys:v=>[`чтение ${fmtMBs(ioR)}`,`запись ${fmtMBs(ioW)}`],
     more:()=>[['Чтение',fmtMBs(ioR)],['Запись',fmtMBs(ioW)]],
     note:'Сколько процессы читают и пишут на диск — по дисковым счётчикам ядра, как в System Informer: чтение из кэша, каналы и устройства сюда не входят. На старых Windows без этих счётчиков — весь ввод-вывод процесса.'},
  ];
  for(const a of NETS){
    const rx=a.rx_bps*8/1e6,tx=a.tx_bps*8/1e6,vpn=a.kind==='vpn';
    out.push({id:'net:'+a.key,name:'Сеть · '+a.name,m:'net',net:a,col:5,fmt:fmtMbit,sub:a.description,hist:['net','io',a.key],
      now:()=>rx,line:v=>`↓ ${fmtMbit(rx)} ↑ ${fmtMbit(tx)}`,
      keys:v=>[`↑ ${fmtMbit(tx)}`,vpn?'туннель VPN':a.kind==='wifi'?'Wi-Fi':'Ethernet',a.link_bps?`канал ${a.link_bps>=1e9?nf(a.link_bps/1e9,1)+' Гбит/с':Math.round(a.link_bps/1e6)+' Мбит/с'}`:''].filter(Boolean),
      more:()=>[['Приём',fmtMbit(rx)],['Отправка',fmtMbit(tx)],['Адаптер',a.description]],
      note:(vpn?'Весь трафик приложений идёт через этот туннель. ':'Трафик через адаптер. Если включён VPN, здесь уже зашифрованный трафик туннеля. ')+(NETPP?'Трафик отдельных процессов — в колонке «Сеть» таблицы и на карте.':'Трафик по процессам Windows показывает только программам с правами администратора.')});
  }
  return out;
}
let RES=[];
const curRes=()=>RES.find(r=>r.id===S.res)||RES[0];
const SORT_OF=r=>r.m==='mem'?'mem':r.m==='dsk'?'dsk':r.m==='gpu'?'gpu':r.m==='net'&&NETPP?'net':'cpu';
function setRes(id){S.res=id;const r=curRes();if(r)S.sort=SORT_OF(r);S.dir=-1;S.order=null;S.hl=null;saveUI();renderAll();}
function resStatus(r,v){
  if(r.id==='cpu')return v>90?'red':v>60?'yel':null;
  if(r.id==='mem')return SYS.memory.load_pct>90?'red':SYS.memory.load_pct>80?'yel':null;
  return null;
}
const R2={key:'2m',label:'2 мин',ms:120e3};
function railData(r){
  const [scope,by,key]=r.hist;const h=H(scope,by,key?20:0,key?[key]:[],R2);
  if(!h)return null;const s=key?h.series.find(x=>x.key===key):h.total;
  return s?s.values.map(conv(r.m)):null;
}
function renderRail(){
  const el=$('#rail');if(!SYS||!S.rail||selIn(el))return;
  el.innerHTML='<div class="rh"><span>Ресурсы</span><button class="ib" data-close="rail" title="Скрыть · Ctrl+B"><svg width="12" height="12" viewBox="0 0 12 12"><path d="M2.5 2.5l7 7m0-7l-7 7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg></button></div>'+RES.map(r=>{
    const v=r.now(),st=resStatus(r,v),col=PAL[r.col];
    const data=railData(r)||[v,v];
    const max=r.max||niceMax(Math.max(...data)*1.2||1);
    const pts=data.map((d,i)=>`${(i*100/(data.length-1)).toFixed(2)},${(29-clamp(d/max,0,1)*27).toFixed(2)}`).join(' ');
    return `<div class="ri${S.res===r.id?' on':''}" data-r="${esc(r.id)}"><div class="rn">${esc(r.name)}${st?`<span class="dot ${st}"></span>`:''}</div><div class="rv">${esc(r.line(v))}</div>
      <svg viewBox="0 0 100 30" preserveAspectRatio="none"><polygon points="0,30 ${pts} 100,30" fill="${hexA(col,.16)}"/><polyline points="${pts}" fill="none" stroke="${col}" stroke-width="1.2" vector-effect="non-scaling-stroke"/></svg></div>`;
  }).join('')+'<div class="rfoot">Выбор ресурса переключает всё окно: график, сортировку процессов и карту.</div>';
}
$('#rail').addEventListener('click',e=>{if(e.target.closest('[data-close]'))return toggleRail(false);const it=e.target.closest('.ri');if(it)setRes(it.dataset.r);});

/* =================================================================
   Нижняя панель: один график + «Всего / По приложениям / По процессам»
   ================================================================= */
function histMeta(h){return {t0:h.start_ms,step:h.step_ms,missing:h.missing||0};}
function totalSeries(r){
  if(r.m==='net'){
    const k=r.net.key,a=H('net','read',20,[k]),b=H('net','write',20,[k]);
    if(!a||!b)return null;const sa=a.series[0],sb=b.series[0],n=a.points;
    return {meta:histMeta(a),series:[{name:'Приём',color:PAL[5],data:sa?sa.values.map(conv('net')):new Array(n).fill(0)},{name:'Отправка',color:PAL[4],data:sb?sb.values.map(conv('net')):new Array(n).fill(0)}]};
  }
  if(r.m==='gpu'){
    const k=r.hist[2],h=H('gpu','gpu',20,[k]);if(!h)return null;const s=h.series[0];
    const out={meta:histMeta(h),series:[{name:'Загрузка',color:PAL[3],data:s?s.values:new Array(h.points).fill(0)}]};
    return out;
  }
  if(r.m==='dsk'){
    const a=H('system','read',0),b=H('system','write',0);if(!a||!b)return null;
    return {meta:histMeta(a),series:[{name:'Чтение',color:PAL[0],data:a.total.values.map(conv('dsk'))},{name:'Запись',color:PAL[4],data:b.total.values.map(conv('dsk'))}]};
  }
  const h=H('system',BY[r.m],0);if(!h)return null;
  return {meta:histMeta(h),series:[{name:r.m==='cpu'?'Загрузка ЦП':'Используется',color:PAL[r.col],data:h.total.values.map(conv(r.m))}]};
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
    /* всё, что не попало в шестёрку, — одной полосой, но с расшифровкой в подсказке */
    const data=new Array(h.points).fill(0);
    for(const s of rest)s.values.forEach((v,i)=>data[i]+=cv(v));
    if(h.other)h.other.values.forEach((v,i)=>data[i]+=cv(v));
    const more=h.other?+((h.other.title.match(/\d+/)||[0])[0]):0,count=rest.length+more;
    const last=s=>cv(s.values[s.values.length-1]||0);
    const list=rest.slice().sort((a,b)=>last(b)-last(a)).slice(0,15).map(s=>`${s.title} — ${r.fmt(last(s))}`);
    const tip=`Что входит (сейчас):\n${list.join('\n')}${count>15?`\nи ещё ${count-15} поменьше`:''}`;
    series.push({key:'__o',name:`Остальные (${count})`,color:OTHER,data,tip});
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
  setHTML($('.c-val',el),esc(r.m==='net'?'↓ '+fmtMbit(v):r.m==='mem'?`${nf(v/1024,1)} ГБ`:r.fmt(v)));
  setHTML($('.c-keys',el),r.keys(v).map(k=>`<span>${esc(k)}</span>`).join(''));
  const modes=r.m==='net'?[['total','Всего']]:[['total','Всего'],['apps','По приложениям'],['procs','По процессам']];
  let mode=S.chartMode;if(!modes.some(m=>m[0]===mode))mode='total';
  const seg=$('.c-mode',el);if(seg._r!==r.id){seg.innerHTML=modes.map(([k,t])=>`<button data-m="${k}">${t}</button>`).join('');seg._r=r.id;}
  seg.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.m===mode));
  $('.c-more-t',el).textContent=S.more?'Скрыть подробности':'Подробнее';
  const more=$('.c-more',el);more.hidden=!S.more;
  if(S.more)setHTML(more,[...(r.sub?[['Устройство',r.sub]]:[]),...r.more(v)].map(([a,b])=>`<div><span>${esc(a)}</span><b>${esc(String(b))}</b></div>`).join('')+(r.note?`<div class="note">${esc(r.note)}${r.m==='net'&&!NETPP&&!isAdmin()?ADMIN_LINK:''}</div>`:''));
  const d=mode==='total'?totalSeries(r):breakdown(r,mode);
  const cv=$('.c-cv',el);
  if(!d){drawTS(cv,{series:[],t0:NOW,step:1000,fmt:r.fmt,empty:'Загружаю историю…'});return;}
  const stacked=mode!=='total';
  drawTS(cv,{...d.meta,series:d.series,stacked,fmt:r.fmt,max:r.m==='cpu'||r.m==='gpu'?100:undefined,fill:!stacked});
  const n=d.series[0]?d.series[0].data.length:0;
  const hi=S.hoverT!=null?clamp(Math.round((S.hoverT-d.meta.t0)/d.meta.step),0,n-1):n-1;
  setHTML($('.c-leg',el),d.series.length<2?'':d.series.map(s=>`<span class="lg" data-k="${esc(s.key||s.name)}" ${s.nodeId?`data-id="${esc(s.nodeId)}"`:''} ${s.tip?`title="${esc(s.tip)}"`:''}><i style="background:${s.color}"></i>${esc(s.name)} <b class="num">${r.fmt(s.data[hi]||0)}</b></span>`).join(''));
}
/* «Развернуть»: нижняя панель или график процесса занимают всё окно; Esc / повторный клик — обратно */
const IC_MAX='<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><path d="M7 1.5h3.5V5M5 10.5H1.5V7M10.5 1.5L7 5M1.5 10.5L5 7"/></svg>';
const IC_RESTORE='<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><path d="M10.5 5H7V1.5M1.5 7H5v3.5M7 5l3.5-3.5M5 7l-3.5 3.5"/></svg>';
function maxMark(el,cls,on,btn){el.classList.toggle(cls,on);if(btn&&btn._on!==on){btn._on=on;btn.innerHTML=on?IC_RESTORE:IC_MAX;btn.title=on?'Свернуть обратно · Esc':'Развернуть на всё окно · двойной клик по графику';}}
function setMax(v){S.max=S.max===v?null:v;if(S.max==='bottom'&&!S.bottom)S.bottom=true;
  maxMark($('#shell'),'max-bottom',S.max==='bottom',$('#maxBottom'));applyShell();requestAnimationFrame(()=>requestAnimationFrame(renderCharts));}
function renderCharts(){renderChart();renderDetailChart();renderProcTabs(true);}

/* журнал */
function renderLog(){
  const el=$('#bLog');if(!S.bottom||S.btab!=='log'||!vis(el)||selIn(el))return;
  if(!EVENTS.length){el.innerHTML='<div class="empty">Журнал пуст. Сюда попадают зависшие процессы, утечки памяти, перегрузки системы и ваши действия.</div>';return;}
  el.innerHTML='<div class="evs">'+EVENTS.slice().reverse().map(e=>{
    const id=e.pid!=null?e.pid+':'+e.create_time:null,n=id&&NODES.get(id);
    const lvl=e.level==='red'?'red':e.level==='yel'?'yel':'';
    const st=e.level==='ok'?'background:var(--success)':e.level==='info'?'background:var(--text-4)':'';
    return `<div class="ev" ${n?`data-id="${esc(n.id)}"`:''}><span class="t">${new Date(e.at_ms).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}</span><span class="dot ${lvl}" style="${st}"></span><span>${esc(e.text)}${n?`<br><span class="who">${esc(ancestors(n).slice(-2).map(nameOf).concat(nameOf(n)).join(' › '))}</span>`:''}</span></div>`;
  }).join('')+'</div>';
}
$('#bLog').addEventListener('click',e=>{const it=e.target.closest('.ev');if(it&&it.dataset.id)select(it.dataset.id,true);});
$('#btabs').addEventListener('click',e=>{const b=e.target.closest('[data-t]');if(!b)return;S.btab=b.dataset.t;saveUI();applyShell();});

/* =================================================================
   Главная зона: «Процессы»
   ================================================================= */
const COLS_ALL=[
  {k:'cpu',t:'ЦП',m:'cpu',fmt:fmtPct,bar:100,w:76},
  {k:'mem',t:'Память',m:'mem',fmt:fmtMem,bar:4096,w:88},
  {k:'dsk',t:'Диск',m:'dsk',fmt:fmtMBs,bar:50,w:84},
  {k:'net',t:'Сеть',m:'net',fmt:fmtMbit,bar:100,w:96},
  {k:'gpu',t:'ГП',m:'gpu',fmt:fmtPct,bar:100,w:64},
];
/* колонка «Сеть» — только когда движок видит трафик процессов (запуск от администратора) */
let COLS=COLS_ALL.filter(c=>c.k!=='net');
const PANEL_EL={};
function mountProcs(el){
  el.innerHTML=`<div class="ph">
      <input class="search p-q" placeholder="Поиск: имя, описание, PID…  (Ctrl+F)">
      <div class="seg p-mode"><button data-m="tree">Дерево</button><button data-m="apps">Приложения</button></div>
      <label class="chk" title="Для родителя показывать сумму вместе с дочерними процессами того же приложения. Программы, запущенные из него (например, из Проводника), считаются отдельно — наведите на число, чтобы увидеть общую сумму."><input type="checkbox" class="p-incl"> Σ по приложению</label>
      <div class="spacer"></div><span class="caption p-frz" style="visibility:hidden">порядок заморожен, пока курсор над списком</span>
      <button class="btn subtle p-who" title="Какие процессы держат файл или папку открытыми (не удаляется, «занят другим процессом»)">Кто держит файл…</button>
    </div>
    <div class="p-short" hidden></div>
    <div class="tbl-wrap"><table class="tbl"><colgroup></colgroup><thead></thead><tbody></tbody></table></div>
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
  $('thead',el).addEventListener('click',e=>{const th=e.target.closest('th[data-k]');if(!th||th.dataset.k==='name')return;const k=th.dataset.k;if(S.sort===k)S.dir*=-1;else{S.sort=k;S.dir=-1;}S.order=null;renderProcs();});
  const tb=$('tbody',el);
  tb.addEventListener('pointerdown',e=>{
    if(e.button!==0)return;const tr=e.target.closest('tr');if(!tr)return;const id=tr.dataset.id;
    if(e.target.closest('.tw')){S.open.has(id)?S.open.delete(id):S.open.add(id);S.order=null;renderProcs();return;}
    if(e.ctrlKey){S.multi.has(id)?S.multi.delete(id):S.multi.add(id);S.sel=id;renderAll();return;}
    select(id);
  });
  tb.addEventListener('dblclick',e=>{const tr=e.target.closest('tr');if(!tr)return;const id=tr.dataset.id;S.open.has(id)?S.open.delete(id):S.open.add(id);S.order=null;renderProcs();});
  tb.addEventListener('contextmenu',e=>{const tr=e.target.closest('tr');if(!tr)return;e.preventDefault();const id=tr.dataset.id;if(!S.multi.has(id)){S.sel=id;S.multi=new Set([id]);renderAll();}openMenu(e.clientX,e.clientY,[...S.multi]);});
}
function matchQ(n){if(!S.q)return true;const i=INFO.get(n.id);return (nameOf(n)+' '+n.exe+' '+n.pid+' '+(i&&i.description||'')+' '+(i&&i.path||'')).toLowerCase().includes(S.q);}
/* в Σ у верхней строки приложения — и ЦП его коротких процессов: иначе «Claude 12 %» стоял ниже
   антивируса, хотя вместе с запущенными им git и grep занимал треть процессора */
const shortOf=(n,m)=>{if(m!=='cpu'||!n.appKey)return 0;const a=APPS.get(n.appKey);return a&&a.rootPid===n.pid?shortAvg(n.appKey,5):0;};
function sortNodes(list){
  const m=COLS.find(c=>c.k===S.sort).m,v=n=>cur(n,m,S.incl)+(S.incl?shortOf(n,m):0);
  if(S.freeze&&S.order){const idx=S.order;return list.sort((a,b)=>(idx.has(a.id)?idx.get(a.id):1e9)-(idx.has(b.id)?idx.get(b.id):1e9));}
  return list.sort((a,b)=>S.dir*(v(a)-v(b))||a.pid-b.pid);
}
/* Внутри строки — только процессы того же приложения (как и в Σ). Программа, запущенная
   из другой (тесты Java из IntelliJ, всё из Проводника), — отдельная строка верхнего уровня
   с пометкой «из …»: иначе тяжёлый процесс прятался в свёрнутой ветке лёгкого родителя. */
const foreignRoot=n=>!n.parent||n.parent.appKey!==n.appKey;
/* обычные «запускатели» — пометка «из Проводник» у половины списка ничего не говорит */
const LAUNCHERS=new Set(['windows','explorer.exe','svchost.exe','services.exe','wininit.exe','winlogon.exe','userinit.exe','sihost.exe','smss.exe','csrss.exe','system','sihost','explorer']);
function walkRows(roots){
  const out=[],keep=n=>!S.q||appDesc(n).some(matchQ);
  const walk=(n,d)=>{if(!keep(n))return;out.push({n,d});if(S.open.has(n.id)||S.q)sortNodes(sameApp(n).slice()).forEach(k=>walk(k,d+1));};
  sortNodes(roots).forEach(r=>walk(r,0));return out;
}
function procRows(){
  const live=[...NODES.values()].filter(alive);
  if(S.procMode==='tree')return walkRows(live.filter(foreignRoot));
  const m=COLS.find(c=>c.k===S.sort).m,out=[];
  const groups=new Map();
  for(const n of live){const k=n.appKey||n.exe;if(!groups.has(k))groups.set(k,[]);if(!n.parent||n.parent.appKey!==n.appKey)groups.get(k).push(n);}
  const apps=[...groups.entries()].map(([k,tops])=>({k,tops})).filter(a=>a.tops.length);
  const tot=a=>a.tops.reduce((s,n)=>s+cur(n,m,true),0);
  apps.sort((a,b)=>S.dir*(tot(a)-tot(b)));
  for(const a of apps)out.push(...walkRows(a.tops));
  return out;
}
let sparkReq=0;
const ROW_H=32,ROW_BUF=12;
/* строка может быть не нарисована (вне видимой части) — прокручиваем к ней по номеру */
function revealRow(id){
  const el=PANEL_EL.procs;if(!vis(el))return;const wrap=$('.tbl-wrap',el);
  const r=el.querySelector(`tr[data-id="${CSS.escape(id)}"]`);if(r){r.scrollIntoView({block:'nearest'});return;}
  const i=procRows().findIndex(x=>x.n.id===id);if(i<0)return;
  wrap.scrollTop=($('thead',el).offsetHeight||33)+i*ROW_H-wrap.clientHeight/2;renderProcs();
}
/* Короткие процессы (git, grep, sh из скриптов) живут меньше секунды и в список не попадают, но могут
   занимать процессор целиком: «ЦП 100 %», а в таблице сверху 8 %. Здесь — сколько их и кто запускает */
function renderShort(el){
  const box=$('.p-short',el),sec=5,list=[...APPS.values()].map(a=>({a,v:shortAvg(a.key,sec)})).filter(x=>x.v>=1).sort((p,q)=>q.v-p.v);
  const un=shortAvg('',sec),tot=list.reduce((s,x)=>s+x.v,0);
  if(tot+un<5){box.hidden=true;return;}box.hidden=false;
  const who=list.slice(0,3).map(({a,v})=>`<a data-app="${esc(a.key)}" title="Показать ${esc(a.title)} в списке">${esc(mapLabel(a.title))}</a> — ${fmtPct(v)}${a.spawnNames.length?` <span class="n2">(${esc(a.spawnNames.join(', '))})</span>`:''}`).join(' · ');
  setHTML(box,`${ICON_INFO}<span>${tot>=1?`<b>${fmtPct(tot)} ЦП — короткие процессы</b>, которых нет в списке: каждый живёт меньше секунды, но их запускают десятками в секунду. Запускает ${who}.`:''}${un>=5?` ${tot>=1?'Ещё':'<b>'}${fmtPct(un)} ЦП${tot>=1?'':'</b>'} не удалось отнести ни к одному процессу — прерывания, драйверы или процессы, завершившиеся до замера.`:''}</span>`);
}
function renderProcs(){
  const el=PANEL_EL.procs;if(!vis(el)||!SYS)return;
  $('.p-mode',el).querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.m===S.procMode));
  $('.p-incl',el).checked=S.incl;
  const want=COLS_ALL.filter(c=>c.k!=='net'||NETPP);
  if(want.length!==COLS.length){COLS=want;const tb=$('tbody',el);tb._rows=null;tb.innerHTML='';if(!COLS.some(c=>c.k===S.sort))S.sort='cpu';}
  setHTML($('colgroup',el),'<col>'+COLS.map(c=>`<col style="width:${c.w}px">`).join('')+'<col style="width:88px">');
  /* имени — не меньше 180 px: в узкой панели таблица прокручивается вбок, а не сжимает имена до значка */
  $('table',el).style.minWidth=180+COLS.reduce((a,c)=>a+c.w,0)+88+'px';
  const act=SORT_OF(curRes());
  setHTML($('thead',el),`<tr><th data-k="name" style="cursor:default">Имя</th>${COLS.map(c=>`<th data-k="${c.k}" class="${c.k===act?'act':''} ${S.sort===c.k?'on':''}">${c.t}${S.sort===c.k?(S.dir<0?' ↓':' ↑'):''}</th>`).join('')}<th style="cursor:default">ЦП · 2 мин</th></tr>`);
  const rows=procRows();
  if(!S.freeze||!S.order)S.order=new Map(rows.map((r,i)=>[r.n.id,i]));
  const core=100/CPUS;
  /* рисуем только видимые строки (плюс запас): все ~400 строк делали каждый кадр
     перетаскивания границ и каждое обновление заметно тяжелее */
  const wrap=$('.tbl-wrap',el),hd=$('thead',el).offsetHeight||33;
  const i0=Math.max(0,Math.floor((wrap.scrollTop-hd)/ROW_H)-ROW_BUF),i1=Math.min(rows.length,Math.ceil((wrap.scrollTop+wrap.clientHeight)/ROW_H)+ROW_BUF);
  patchRows($('tbody',el),rows.slice(i0,i1).map(({n,d})=>{
    const kids=sameApp(n),iss=ISS.get(n.id),w=kids.length&&!S.open.has(n.id)?worstIn(n):null,sp=n.susp;
    const from=n.parent&&n.parent.appKey!==n.appKey&&!LAUNCHERS.has(n.parent.appKey)&&!LAUNCHERS.has(n.parent.exe.toLowerCase())?(APPS.get(n.parent.appKey)||{}).title||nameOf(n.parent):null;
    const lvl=iss?(iss.some(i=>i.lvl==='red')?'red':'yel'):null;
    const cells=COLS.map(c=>{const sh=S.incl?shortOf(n,c.m):0,vi=cur(n,c.m,S.incl&&kids.length>0)+sh,vo=cur(n,c.m,false),bw=clamp(vi/c.bar,0,1)*100;
      const other=aliveKids(n).length>kids.length;
      return {c:c.k===act?'act':'',t:kids.length||other?`Сам процесс: ${c.fmt(vo)}${kids.length?`\nС дочерними процессами приложения: ${c.fmt(cur(n,c.m,true))}`:''}${other?`\nСо всем, что запущено из него (другие приложения — отдельными строками): ${c.fmt(curAll(n,c.m))}`:''}${sh>=.05?`\nКороткие процессы, которые оно запускает (в списке не видны): ${c.fmt(sh)}`:''}`:'',
        h:`<span class="cell-bar" style="width:${bw.toFixed(1)}%"></span><span class="cell-v">${(vi<.05&&c.k!=='mem')||(PSEUDO[n.pid]&&c.k==='mem')?'<span style="color:var(--text-4)">—</span>':c.fmt(vi)}</span>`};});
    const sd=S.incl&&kids.length?sparkSum(n):rtail(n.rc,120);
    const spk=sparkSVG(sd,Math.max(core*1.2,5),PAL[0]);
    const nm=nameOf(n),showExe=nm.toLowerCase()!==n.exe.toLowerCase().replace(/\.exe$/,'');
    const name=`<div class="nm" style="padding-left:${d*18}px"><span class="tw${S.open.has(n.id)?' open':''}" style="${kids.length?'':'visibility:hidden'}">${CHEV}</span>${ico(n)}
        <span class="n1">${esc(nm)}</span>${lvl?`<span class="dot ${lvl}" title="${esc(iss.map(i=>i.txt).join('\n'))}"></span>`:w?`<span class="dot ring ${w}" title="Внутри есть проблема — раскройте"></span>`:''}
        <span class="n2">${PSEUDO[n.pid]?'нагрузка ядра, не процесс':(showExe?esc(n.exe)+' · ':'')+n.pid}${kids.length&&!S.open.has(n.id)?` · ${appDesc(n).length-1} доч.`:''}${from&&S.procMode==='tree'?` · из ${esc(from)}`:''}</span>
        ${sp?'<span class="chip">приостановлен</span>':''}${isProt(n)?'<span class="chip">защищён</span>':''}${n.prio==='idle'||n.prio==='below_normal'?'<span class="chip">низкий приоритет</span>':''}</div>`;
    return {id:n.id,cls:`${S.sel===n.id||S.multi.has(n.id)?'sel':''}${sp?' susp':''}`,cells:[{h:name},...cells,{h:spk}]};
  }),{top:i0*ROW_H,bot:(rows.length-i1)*ROW_H,cols:COLS.length+2});
  renderShort(el);
  const apps=new Set();for(const n of NODES.values())if(n.alive&&n.appKey)apps.add(n.appKey);
  setHTML($('.p-foot',el),`<span>Процессов: ${procCount()}</span><span>Приложений: ${apps.size}</span><div class="spacer"></div><span><span class="kbd">Del</span> завершить · <span class="kbd">Shift+Del</span> с дочерними · <span class="kbd">Ctrl+клик</span> несколько · <span class="kbd">ПКМ</span> меню</span>`);
}
/* Таблица обновляется точечно: строки переиспользуются по ключу процесса, а ячейка
   перерисовывается, только если её содержимое изменилось. Полная пересборка стоила ~10 мс в секунду. */
function setHTML(el,h){if(el._h!==h&&!selIn(el)){el.innerHTML=h;el._h=h;}}
/* Пока в блоке выделен текст, блок не перерисовывается: замена содержимого сбрасывает
   выделение, и скопировать путь или командную строку было невозможно. */
function selIn(el){
  const s=getSelection();if(!el||!s||s.isCollapsed||!s.rangeCount)return false;
  const r=s.getRangeAt(0);return el.contains(r.startContainer)||el.contains(r.endContainer);
}
function patchRows(tb,list,pad){
  if(selIn(tb))return; // перестановка строк тоже сбросила бы выделение
  const map=tb._rows||(tb._rows=new Map()),keep=new Set();let prev=null;
  /* pad — высота невидимых строк сверху и снизу (распорки вместо них) */
  /* colspan — ровно по числу колонок: лишние колонки сжимали «Имя» почти до нуля */
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
   Главная зона: «Карта» — по выбранному ресурсу.
   Память — сколько занято сейчас. ЦП и ввод-вывод — в среднем за период,
   иначе плитки прыгали бы каждую секунду.
   ================================================================= */
const mapMetric=()=>{const r=curRes();return r.m==='net'?(NETPP?'net':'cpu'):r.m;};
const mapSecs=()=>Math.min(SPARKN,Math.round(S.range.ms/1000));
function mapDesc(){
  const m=mapMetric(),p=S.range.label;
  if(m==='mem')return 'размер — занятая память сейчас';
  if(m==='net')return 'размер — сетевой трафик процессов сейчас, все адаптеры вместе';
  if(curRes().m==='net')return 'трафик по процессам виден только с правами администратора (кнопка вверху) — показана загрузка ЦП';
  if(m==='gpu')return S.range.ms>SPARKN*1000?`размер — средняя загрузка видеокарты за ${p}`:'размер — загрузка видеокарты сейчас';
  const h=H('system',BY[m],0);const avg=h?h.total.avg:0;
  return m==='cpu'?`размер — средняя загрузка ЦП за ${p} · простой ${fmtPct(Math.max(0,100-avg))}`:`размер — средний ввод-вывод за ${p}`;
}
/* среднее процесса за период: короткие периоды — посекундные данные процесса,
   длинные — история приложения, распределённая по его процессам пропорционально последним 5 минутам */
function ownAvg(n,m){
  const r=m==='cpu'?n.rc:n.rio,k=mapSecs(),t=rtail(r,k);let s=0,c=0;for(const v of t){s+=v;c++;}return c?s/c:0;
}
function mapFmt(v){const m=mapMetric();return m==='net'?fmtMbit(v):m==='mem'?fmtMem(v):m==='dsk'?fmtMBs(v):fmtPct(v);}
function mountMap(el){
  el.innerHTML=`<div class="ph"><div class="crumbs m-crumbs" style="padding:0"></div><span class="caption m-desc"></span><div class="spacer"></div>
     <div class="m-cw"><span class="lbl">Цвет</span><div class="seg m-color"><button data-c="exe">По программе</button><button data-c="cat">По типу</button><button data-c="cpu">По нагрузке ЦП</button></div></div></div>
    <div class="map-wrap"><canvas></canvas></div><div class="mapstat m-stat"></div><div class="maplegend m-leg"></div>`;
  const cv=$('canvas',el);
  $('.m-color',el).addEventListener('click',e=>{const b=e.target.closest('button');if(b){S.map.color=b.dataset.c;renderMap(true);}});
  $('.m-crumbs',el).addEventListener('click',e=>{const a=e.target.closest('[data-z]');if(a){S.map.root=a.dataset.z==='root'?null:a.dataset.z;renderMap(true);}});
  /* как в WizTree: путь и размер плитки под курсором — строкой под картой, плитка обведена */
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
const plural=(n,a,b,c)=>{const t=n%100,u=n%10;return t>10&&t<20?c:u===1?a:u>1&&u<5?b:c;}; // 1 процесс, 3 процесса, 12 процессов
/* строка под картой — по плитке под курсором; обновляется и на каждом замере, даже если мышь стоит */
/* на уровень вверх — как предпоследняя «крошка» */
function mapUp(){const el=PANEL_EL.map;if(!S.map.root||!vis(el))return false;const a=[...el.querySelectorAll('.m-crumbs a[data-z]')].pop();if(!a)return false;a.click();return true;}
function mapStatus(){
  const el=PANEL_EL.map;if(!el)return;const st=$('.m-stat',el),cv=$('canvas',el),h=MAP.hover&&(cv._rects||[]).find(q=>q.id===MAP.hover);
  if(!h){st.textContent=MAP_HINT;return;}const n=h.node,c=h.cpu;
  const path=h.path.split(' › ').filter((s,i,a)=>!i||s!==a[i-1]).join(' › '); // «WizTree › WizTree» → «WizTree»
  const pv=MAP.total>0?h.v/MAP.total*100:null;
  const pct=pv!=null?` · ${pv<.1?'<0,1 %':fmtPct(pv)} ${S.map.root?`от «${esc(MAP.rootLabel)}»`:'от всего'}`:'';
  /* плитка «ещё N» — что в ней; плитка-группа — что PID только у главного процесса, размер — вместе с дочерними */
  const cnt=h.rest&&[...h.rest.reduce((m,s)=>m.set(s,(m.get(s)||0)+1),new Map())].map(([s,c])=>c>1?`${s} ×${c}`:s); // «svchost ×12», а не двенадцать раз
  const what=h.short?` · запускает ${esc(h.short.join(', ')||'процессы')} — каждый живёт меньше секунды, поэтому в списке их нет`
    :h.done?' · процессы этого приложения, которые за период уже завершились, и короткие запуски'
    :h.unseen?' · прерывания, драйверы и процессы, завершившиеся до замера':h.rest?` · ${esc(cnt.slice(0,6).join(', '))}${cnt.length>6?'…':''}`
    :h.procs>1?(h.own?` · ${esc(n.exe)} · PID ${n.pid} и ещё ${h.procs-1} ${plural(h.procs-1,'дочерний','дочерних','дочерних')}`:` · ${h.procs} ${plural(h.procs,'процесс','процесса','процессов')}`)
    :n?` · ${esc(n.exe)} · PID ${n.pid}`:'';
  setHTML(st,`<b>${esc(path)}${h.self?' · сам процесс, без дочерних':''}</b> — ${mapFmt(h.v)}${pct}${n&&!h.rest&&mapMetric()!=='cpu'?` · ЦП ${fmtPct(c)}`:''}${what}`);
}
const MAP_HINT='Наведите на плитку — здесь будет путь и размер · клик — выбрать · двойной клик — приблизить';
function mapHl(k){if(MAP.hl===k)return;MAP.hl=k;const el=PANEL_EL.map;if(el&&MAP.nodes&&!MAP.from)mapFrames($('canvas',el),MAP.nodes,i=>MAP.nodes[i].r);}
function mapHover(id){if(MAP.hover===id)return;MAP.hover=id;const el=PANEL_EL.map;if(el&&MAP.nodes&&!MAP.from)mapFrames($('canvas',el),MAP.nodes,i=>MAP.nodes[i].r);}
function hitMap(cv,e){const r=cv.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;const L=cv._rects||[];for(let i=L.length-1;i>=0;i--){const q=L[i];if(x>=q.x&&x<q.x+q.w&&y>=q.y&&y<q.y+q.h)return q;}return null;}
/* plan — разбиение на ряды из прошлой раскладки: [[сколько плиток, вдоль ли ширины], …].
   С ним небольшое изменение значений только слегка меняет размеры, а не перекидывает плитки
   из ряда в ряд. Итоговое разбиение возвращается в out.plan. */
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
  const long=m!=='mem'&&m!=='net'&&S.range.ms>SPARKN*1000;
  /* для длинных периодов — сколько приложение потратило за период (из истории) */
  let appAvg=null;
  if(long){const h=H('apps',BY[m],1000);if(h){appAvg=new Map();for(const s of h.series)appAvg.set(s.key,conv(m)(s.avg));}}
  /* ЦП процесса за длинный период — сколько времени процессора он потратил за это время: запущенный
     минуту назад java — это минута работы, а не «последние 5 минут × 3 часа» (раньше свежий процесс
     сразу раздувался на полприложения, а его завершение перекраивало всю группу) */
  const rangeS=S.range.ms/1000;
  /* процесс старше периода — его средняя за всю жизнь (время ЦП / возраст): точная и не дёргается,
     в отличие от последних 5 минут (после запуска движка там ещё пусто) */
  const rangeCpu=n=>{const age=Math.max(1,(NOW-(n.ct/1e4-11644473600000))/1000);return (n.cpuMs||0)/10/(Math.min(age,rangeS)*CPUS)*(age<=rangeS?Math.min(age,rangeS)/rangeS:1);};
  const own=n=>m==='mem'?n.mem:m==='gpu'?n.gpu:m==='net'?n.net:m==='cpu'&&long&&!PSEUDO[n.pid]?rangeCpu(n):ownAvg(n,m); /* у прерываний и DPC нет времени создания и накопленного ЦП — только история */
  /* приблизить можно процесс (id «pid:время») или группу-приложение («a…», «mWIN»). Внутри —
     ровно то, что было в группе на общей карте: процессы того же приложения. Программы, запущенные
     из него, — свои группы (раньше «Проводник» 100 МБ приближался в дерево на 3 ГБ из чужих программ) */
  const procRoot=S.map.root&&/^\d/.test(S.map.root);
  const mk=n=>{
    const kids=aliveKids(n).filter(k=>k.appKey===n.appKey).map(mk).filter(k=>k.v>eps);
    const o=own(n),lbl=mapLabel(nameOf(n));
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
      /* ЦП: что приложение потратило за период сверх живых процессов — уже завершившиеся и короткие
         процессы, своей плиткой. Растягивать на это живые процессы — значит врать об их доле */
      if(m==='cpu'&&v<=target)gone=target-v;
      else if(v>0){const f=target/v;kids.forEach(x=>scaleTree(x,f));}else if(target>0&&kids.length){kids.forEach(x=>scaleTree(x,0));kids[0].v=target;}v=target;}
    const flat=kids.filter(x=>x.v>eps);
    if(gone>eps)flat.push({key:'z'+k,label:'завершившиеся и короткие процессы',v:gone,rep:root,cat:root?catOf(root):'other',done:1});
    if(m==='cpu'&&!long){const sv=shortAvg(k,mapSecs());if(sv>eps){const sa=APPS.get(k);flat.push({key:'x'+k,label:'короткие процессы',v:sv,rep:root,cat:root?catOf(root):'other',short:sa?sa.spawnNames:[]});v+=sv;}}
    return {key:'a'+k,label:mapLabel(a?a.title:k),v,kids:flat,node:flat.length===1?flat[0].node:null,rep:root,cat:root?catOf(root):'other',zoomId:'a'+k};
  });
  /* приближенное приложение не выкидывает к общему виду, когда оно затихло (в режиме ЦП) */
  if(S.map.root&&!procRoot){const g=apps.find(a=>a.key===S.map.root);if(g&&g.kids&&g.kids.length)return g;}
  apps=apps.filter(a=>a.v>eps);
  if(m==='cpu'&&!long){const un=shortAvg('',mapSecs());if(un>eps)apps.push({key:'mUNSEEN',label:'Не отнесено к процессам',v:un,cat:'system'});}
  if(m==='mem'){
    /* занятое, но не принадлежащее ни одному процессу лично — по частям, а не одной серой плиткой */
    const parts=memParts().filter(p=>p.v>=1).map(p=>({key:'m'+p.label,label:p.label,v:p.v,cat:'system'}));
    const v=parts.reduce((s,p)=>s+p.v,0);
    if(v>0)apps.push(parts.length>1?{key:'mWIN',label:'Windows вне процессов',v,cat:'system',kids:parts,zoomId:'mWIN'}:{...parts[0],label:'Ядро, драйверы и кэши Windows'});
  }
  if(S.map.root){const g=apps.find(a=>a.key===S.map.root);if(g&&g.kids)return g;S.map.root=null;}
  /* ключ программы → понятное имя для легенды («IntelliJ IDEA», а не «idea64») */
  MAP.exeName=new Map();
  for(const [k,tops] of groups){const a=APPS.get(k);if(!a)continue;const r=tops.find(t=>t.pid===a.rootPid)||tops[0];
    if(r&&INFO.has(r.id)){const e=mapExe({node:r});if(!MAP.exeName.has(e))MAP.exeName.set(e,mapLabel(a.title));}}
  for(const n of live)if(INFO.has(n.id)){const e=mapExe({node:n});if(!MAP.exeName.has(e))MAP.exeName.set(e,mapLabel(nameOf(n)));} // как на плитках: «OpenJDK Platform binary», а не «java»
  return {key:'root',label:'Всё',v:apps.reduce((s,a)=>s+a.v,0),kids:apps};
}
/* «По программе» — как типы файлов в WizTree: у каждой программы свой цвет.
   - Цвет — у программы (exe). Роли одной программы (рендерер, GPU-процесс, Claude Code) — тот же
     цвет светлее или темнее: Brave не съедает пять цветов, а внутри приложения роли различимы.
   - Палитра — 14 цветов с близкой светлотой (не «проваливаются» на тёмном и не слепят),
     любые два отличаются заметно (ΔE ≥ 22; прежняя палитра имела пары с ΔE 14).
   - Цвет закреплён за программой и хранится между запусками: приближение, смена ресурса, уход
     с вкладки и перезапуск его не меняют. Раздаётся по сглаженному за минуты весу программы во всей
     системе (доля памяти + доля ЦП) — мгновенный ЦП перетасовывал места в рейтинге каждую секунду.
     Забирается только у программы, которая больше 10 минут не входит в первые 14, и только для новой крупной.
   - Процессы и компоненты Windows и память вне процессов — холодный серый, программы, которым
     не хватило цвета, — тёплый серый: два «серых» не путаются. */
const EXE_PAL=['#fb7188','#d15228','#e98b11','#9d7b0b','#a3af0f','#3c9729','#28c091','#129390','#2bb6d6','#1687cd','#819ffc','#8966d9','#d37de5','#c44d95'];
/* светлота ролей постоянная: рендерер (их у браузера десятки) — заметно светлее, GPU — заметно темнее,
   прочие служебные — чуть темнее; сам процесс — основной цвет */
const ROLE_F={'Рендерер':1.3,'Расширение':1.15,'GPU-процесс':.72,'Node.js':.78},ROLE_OTHER=.92;
const WIN_EXE=new Set(['msmpeng.exe','nissrv.exe','mpdefendercoreservice.exe','securityhealthservice.exe','securityhealthsystray.exe','smartscreen.exe','searchindexer.exe','searchhost.exe','searchprotocolhost.exe','searchfilterhost.exe']);
const SLATE=[84,92,106],WARM=[120,114,106];
/* серые ключи: 'w:' Windows, 'k:' память вне процессов, 'r:' плитка «ещё N», '?' — ещё без сведений.
   Только префиксы: имена программ на w и k (WizTree, Windows Terminal, KeePass) — обычные программы */
const greyKey=k=>k[0]==='?'||k.includes(':');
const COLOR_KEY='tm-map-colors2';
/* сохранённое: c — программа → [цвет, когда последний раз была крупной];
   испорченные и повторяющиеся записи отбрасываем */
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
  for(const k of mem.keys()){const w=(mt?mem.get(k)/mt:0)+cpu.get(k)/Math.max(ct,25),p=W_EMA.get(k);/* ЦП — от не меньше 25 % машины: на простое 0,5 % фоновой службы не весят как гигабайты */W_EMA.set(k,p==null?(colorsInit?w*a:w):p+(w-p)*a);if(!SEEN.has(k))SEEN.set(k,colorsInit?now:0);}
  for(const k of SEEN.keys())if(!mem.has(k))SEEN.delete(k);colorsInit=true; // новая программа набирает вес постепенно: всплеск сборки не отбирает цвета
  for(const [k,p] of W_EMA)if(!mem.has(k)){const q=p*(1-a);if(q<1e-4)W_EMA.delete(k);else W_EMA.set(k,q);}
  const rank=[...W_EMA.keys()].sort((p,q)=>W_EMA.get(q)-W_EMA.get(p)),N=EXE_PAL.length,near=new Set(rank.slice(0,N));
  for(const k of near)if(COLORS[k]&&COLORS[k][1]<now-60e3){COLORS[k][1]=now;colorsDirty=true;} // время — сохраним позже
  const liveE=new Set();for(const n of NODES.values())if(alive(n))liveE.add(n.exe.toLowerCase());
  rank.slice(0,N).forEach((k,r)=>{
    if(COLORS[k])return;
    const used=new Set(Object.values(COLORS).map(v=>v[0]));let idx=EXE_PAL.findIndex((c,i)=>!used.has(i));
    if(idx<0){/* палитра занята — забираем у той, что дольше всех не входила в первые 14, но не раньше чем через 10 минут.
       Крупной программе (первая половина рейтинга) — сразу, у самой мелкой вне первых 14: иначе WizTree
       на гигабайт оставался серым, пока цвет держал Docker на 50 МБ */
      const out=Object.entries(COLORS).filter(([q])=>!near.has(q)&&(W_EMA.has(q)||!liveE.has(q))),wt=q=>W_EMA.get(q)||0;
      const old=r<N/2&&now-(SEEN.has(k)?SEEN.get(k):now)>120e3?out.sort((p,q)=>wt(p[0])-wt(q[0])||p[1][1]-q[1][1])[0]:out.filter(([,v])=>now-v[1]>600e3).sort((p,q)=>p[1][1]-q[1][1])[0];
      if(!old)return;idx=old[1][0];delete COLORS[old[0]];}
    COLORS[k]=[idx,now];changed=true;
  });
  if(changed)saveColors(); // выданный цвет сохраняем сразу — иначе после перезапуска он мог стать другим
}
/* роль из командной строки: «Рендерер (вкладка или окно)» → «Рендерер» */
const roleKind=n=>{const i=INFO.get(n.id);return i&&i.role?i.role.replace(/\s*\(.*$/,'').trim():'';};
/* подпись на карте короче, чем в таблице: пояснение в скобках не помещается и повторяется у десятков плиток */
const mapLabel=s=>s.replace(/\s*\([^)]*\)\s*$/,'')||s;
/* ключ программы — exe; процессы и компоненты Windows — 'w:' (conhost службы серый, а conhost терминала —
   цвет программы), память вне процессов — 'k:', процесс без сведений (первая секунда) — '?' (временно серый) */
const mapExe=m=>{if(m.rest)return 'r:'+m.key;const n=m.node||m.rep;if(!n)return 'k:'+m.key;const e=n.exe.toLowerCase();if(!INFO.has(n.id))return '?'+e;
  return catOf(n)==='system'||WIN_EXE.has(e)?'w:'+e:e;};
const exeTitle=k=>k.replace(/\.exe$/,'');
function progRGB(m){
  const k=mapExe(m),d=hashN(m.key)%11-5;
  if(m.rest){const g=m.restOf&&progRGB(m.restOf);return g&&m.restOf.key!=='root'?g.map(v=>v*.62+30):WARM.map(v=>v+d);} // «ещё N» — приглушённый цвет группы
  if(k.startsWith('w:')||k.startsWith('k:'))return SLATE.map(v=>v+d);
  const c=COLORS[k];if(!c||!EXE_PAL[c[0]])return WARM.map(v=>v+d);
  const rgb=hexRGB(EXE_PAL[c[0]]),n=m.node||m.rep,role=n?roleKind(n):'',f=role?ROLE_F[role]||ROLE_OTHER:1;
  return rgb.map(v=>f>1?v+(255-v)*(f-1)*1.4:v*f);
}
/* размеры программ в текущем виде — для легенды */
function exeTotals(nodes){const tot=new Map(),add=m=>{if(m.rest)return m.items.forEach(add);const k=mapExe(m);tot.set(k,(tot.get(k)||0)+(m.raw||0));};
  for(const n of nodes)if(!n.head)add(n.m);MAP.exeTot=tot;}
const mapId=n=>n.key+(n.head?'#':'');
const heatRGB=c=>{const t=clamp(c/12,0,1);const a=[58,74,92],b=[201,162,39],d=[224,83,61];return t<.5?a.map((v,i)=>v+(b[i]-v)*t*2):b.map((v,i)=>v+(d[i]-v)*(t-.5)*2);};
const heat=c=>`rgb(${heatRGB(c).map(Math.round).join(',')})`;
const hexRGB=h=>{const n=parseInt(h.slice(1),16);return [n>>16,n>>8&255,n&255];};
/* Подушки (SequoiaView / WinDirStat), но у каждой плитки своя и мягкая: выпуклости родителей
   не складываются — иначе крупная плитка становилась светящимся шаром с чёрными углами,
   а мелкие у края группы тонули в тени. Цвет плитки сохраняется до самого края. */
const CUSH={H:.3,IA:.34,BR:1.12,L:(()=>{const l=Math.hypot(-1,-1,10);return [-1/l,-1/l,10/l];})()};
function addRidge(r,s,h){const h4=4*h,wf=h4/r.w,hf=h4/r.h;s[2]+=wf*(r.x*2+r.w);s[0]-=wf;s[3]+=hf*(r.y*2+r.h);s[1]-=hf;}
/* Карта перестраивается на каждом замере, но спокойно:
   - значения сглажены по времени (τ ≈ 3 с) — всплеск нагрузки не перекраивает раскладку;
   - новая плитка вырастает из нуля, а плитка завершившегося процесса («призрак») сжимается до нуля —
     короткие процессы (git, cmd у Claude Code) не выдёргивают соседей рывком;
   - порядок плиток «липкий»: соседи меняются местами, только когда один обогнал другого на 40 %;
   - разбиение на ряды берётся из прошлой раскладки, даже если набор плиток изменился: выбывшие
     убираются из своих рядов, новые идут в конец — раньше любая новая мелкая плитка перекраивала всю группу;
   - новая раскладка перетекает из старой за 0,45 с; сдвиги меньше 4 px не перерисовываются.
   Подушки считаются попиксельно в отдельный холст, а заголовки, подписи и рамка выделения
   рисуются поверх — клик по плитке отзывается сразу, без пересчёта пикселей. */
const MAP={sig:'',seq:-1,at:0,sm:new Map(),ghost:new Map(),order:new Map(),nodes:null,from:null,t0:0,raf:0,last:0,off:document.createElement('canvas')};
const MAP_ANIM=450,MAP_TAU=3000,MAP_HDR=18,MAP_DEAD=4;
const easeOut=t=>1-Math.pow(1-t,3);
function mapLayout(w,h){
  const root=mapTree(),now=performance.now(),first=!MAP.sm.size;
  /* нагрузка скачет сильнее памяти — сглаживаем дольше; средняя за часы и вовсе не должна «дышать» каждую секунду */
  const tau=mapMetric()==='mem'?MAP_TAU:S.range.ms>SPARKN*1000?20000:2*MAP_TAU;
  const a=first?1:1-Math.exp(-Math.max(0,now-MAP.at)/tau);MAP.at=now;
  const sm=new Map(),byKey=new Map(),par=new Map();
  const smooth=(m,pk)=>{const p=MAP.sm.has(m.key)?MAP.sm.get(m.key):m.self?MAP.sm.get('p'+m.key.slice(1)):undefined;m.raw=m.v;m.v=p!=null?p+(m.v-p)*a:first?m.v:m.v*a;
    sm.set(m.key,m.v);byKey.set(m.key,m);if(pk)par.set(m.key,pk);if(m.kids)m.kids.forEach(k=>smooth(k,m.key));};
  smooth(root);
  /* призраки: плитки, которых больше нет в данных, сжимаются на прежнем месте, пока не станут меньше 0,1 % */
  const ghost=new Map(),floor=(root.v||1)*1e-3;
  for(const [k,g] of [...MAP.ghost,...[...(MAP.byKey||new Map())].filter(([k])=>!MAP.ghost.has(k))]){
    if(byKey.has(k)||k==='root')continue;const pk=g.pk||MAP.par&&MAP.par.get(k),parent=pk&&byKey.get(pk),p=MAP.sm.get(k);
    if(!parent||!parent.kids||p==null)continue;const v=p*(1-a);if(v<floor)continue;
    const t=g.t||{key:k,label:g.label,node:g.node,rep:g.rep,cat:g.cat,self:g.self,raw:0};
    const item={...t,v,raw:0,ghost:1};parent.kids.push(item);sm.set(k,v);ghost.set(k,{t,pk});}
  MAP.sm=sm;MAP.ghost=ghost;MAP.byKey=new Map([...byKey].map(([k,m])=>[k,{label:m.label,node:m.node,rep:m.rep,cat:m.cat,self:m.self}]));MAP.par=par;
  const order=new Map();
  const sticky=(pk,kids)=>{
    const prev=MAP.order.get(pk),idx=new Map((prev||[]).map((k,i)=>[k,i]));
    const l=kids.filter(k=>k.v>0).sort((x,y)=>{const i=idx.get(x.key),j=idx.get(y.key);return i!=null&&j!=null?i-j:i!=null?-1:j!=null?1:y.v-x.v;});
    for(let i=1;i<l.length;i++)for(let j=i;j>0;j--){
      const known=idx.has(l[j].key)&&idx.has(l[j-1].key);
      if(l[j].ghost||l[j-1].ghost)break; // сжимающийся «призрак» не обгоняют — иначе перекладывалась вся группа
      if(l[j].v>l[j-1].v*(known?(S.range.ms>SPARKN*1000&&mapMetric()!=="mem"?2:1.4):1)){ /* средняя за часы: соседи меняются местами, только если один вдвое больше */const t=l[j];l[j]=l[j-1];l[j-1]=t;}else break;
    }
    order.set(pk,l.map(k=>k.key));return l;
  };
  /* плитка появляется от ~40 кв. пикселей (≈6×6), а пропадает, только став меньше ~16 (≈4×4) */
  const shown=new Set(),was=MAP.shown||new Set();
  const visible=(items,area)=>{const tot=items.reduce((s,k)=>s+k.v,0);if(!tot)return items;const f=area/tot;
    return items.filter(k=>{const a=k.v*f;return a>=40||(was.has(k.key)&&a>=16);});};
  /* мелочь, которая не поместилась, собирается в плитку «ещё N» (N ≥ 2; одна — рисуется сама) — иначе
     остальные плитки растягивались бы на её место и переставали быть пропорциональными */
  const visibleRest=(m,items,area,drop)=>{const l=visible(items,area).filter(k=>!drop||!drop.has(k.key));if(l.length===items.length)return l;
    const ls=new Set(l),rest=items.filter(k=>!ls.has(k)),v=rest.reduce((s,k)=>s+k.v,0),raw=rest.reduce((s,k)=>s+(k.raw||0),0);
    const tot=items.reduce((s,k)=>s+k.v,0),big=!l.length||v*area/tot>=16;
    if(rest.length===1){if(big)l.push(rest[0]);}
    else if(big)l.push({key:m.key+'~rest',label:`ещё ${rest.length}`,v,raw,cat:'other',rest:1,restOf:m,items:rest});
    return l;};
  /* план прошлой раскладки для нового набора плиток: выбывшие убираются из своих рядов, новые — в конец */
  const adapt=(old,keys)=>{
    const ok=old.keys.split('\n'),set=new Set(keys),surv=ok.filter(k=>set.has(k));
    if(!surv.length)return null; // порядок мог смениться — ряды остаются теми же, в них просто другие соседи
    const plan=[];let i=0;for(const [c,hz] of old.plan){let s=0;for(let j=0;j<c;j++,i++)if(set.has(ok[i]))s++;if(s)plan.push([s,hz]);}
    return plan;};
  const plans=new Map(),oldPlans=MAP.plans||new Map();
  const aspect=q=>Math.max(q.w/Math.max(q.h,1e-9),q.h/Math.max(q.w,1e-9));
  const sq=(pk,items,x,y,W,H)=>{
    const ks=items.map(k=>k.key),keys=ks.join('\n'),old=oldPlans.get(pk);
    const plan=old?(old.keys===keys?old.plan:adapt(old,ks)):null;
    let out=plan?squarify(items,x,y,W,H,plan):null;
    /* старый план не годится, только если дал очень вытянутую плитку (1:12) или полоску: перекладка с нуля двигала всю группу на сотни пикселей */
    if(!out||out.some(q=>aspect(q)>12&&q.w*q.h>400||(q.w<3||q.h<3)&&!q.rest))out=squarify(items,x,y,W,H);
    plans.set(pk,{keys,plan:out.plan||[]});return out;
  };
  /* полоска тоньше 3 px (иногда меньше пикселя) давала двойную линию сетки — такие плитки уходят
     в «ещё N»; если и она вышла полоской — её место делят соседи */
  const place=(pk,m,items,x,y,W,H)=>{
    let l=visibleRest(m,items,W*H),out=sq(pk,l,x,y,W,H);
    const thin=q=>{const t=q.self?6:3;return q.w<t||q.h<t;}; // «сам» тоньше 6 px (обёртка cmd над java) — группа сворачивается в ребёнка
    if(out.some(q=>thin(q)&&!q.rest)){l=visibleRest(m,items,W*H,new Set(out.filter(q=>thin(q)&&!q.rest).map(q=>q.key)));out=sq(pk,l,x,y,W,H);}
    if(out.some(thin)&&out.length>1){const d=new Set(out.filter(thin).map(q=>q.key));const l2=l.filter(k=>!d.has(k.key));if(l2.length)out=sq(pk,l2,x,y,W,H);}
    return out.filter(q=>q.w>=1&&q.h>=1);
  };
  const nodes=[];
  const lay=(m,r,path,depth,parent,pre)=>{
    if(r.w<1||r.h<1)return;
    const p=path?path+' › '+m.label:m.label,i=nodes.length;shown.add(m.key);
    /* сетка без отступов: каждая плитка и заголовок владеют только своей правой и нижней линией
       в 1 пиксель — между любыми соседями ровно одна линия. Заголовок — только если детям остаётся
       хотя бы 60×24 px: над плитками высотой 15 px он был бы толще их самих */
    const W=r.w,H=r.h-MAP_HDR,out=m.kids&&r.w>60&&r.h>MAP_HDR+24?place(m.key,m,sticky(m.key,m.kids),r.x,r.y+MAP_HDR,W,H):null;
    if(out&&out.length>1){
      nodes.push({key:m.key,r:{x:r.x,y:r.y,w:r.w,h:r.h},m,head:1,depth,parent,path:p});
      for(const q of out)lay(q,q,p,depth+1,i);
    }else if(out&&out.length===1&&!out[0].self&&!out[0].rest){
      /* видна одна плитка-ребёнок — рисуем её (подпись, цвет, PID — ребёнка): «winlogon 307 МБ» на деле был dwm */
      lay(out[0],r,p,depth,parent,pre||(depth===0&&out[0].label!==m.label?m.label:'')); // подпись «Claude · GPU-процесс»
    }else nodes.push({key:m.key,r:{x:r.x,y:r.y,w:r.w,h:r.h},m,depth,parent,path:p,pre});
  };
  /* приближенная группа занимает всю карту без своего заголовка — её имя уже в «хлебных крошках» */
  const zr=S.map.root&&NODES.get(S.map.root),za=zr&&APPS.get(zr.appKey);
  const base=S.map.root?[...(za?[mapLabel(za.title)]:[]),...(zr?ancestors(zr).filter(x=>x.appKey===zr.appKey).map(x=>mapLabel(nameOf(x))):[]),root.label].filter((s,i,arr)=>!i||s!==arr[i-1]).join(' › '):'';
  if(root.kids){
    const top=sticky('root',root.kids);
    /* память вне процессов — в конец (справа внизу), а не в самый заметный левый верхний угол */
    if(!S.map.root){const i=top.findIndex(k=>k.key[0]==='m');if(i>=0)top.push(top.splice(i,1)[0]);}
    for(const q of place('root',root,top,1,1,w-1,h-1))lay(q,q,base,0,-1);
  }else lay(root,{x:1,y:1,w:w-1,h:h-1},base,0,-1);
  MAP.order=order;MAP.shown=shown;MAP.plans=plans;MAP.rootLabel=root.label;MAP.total=root.raw;
  return nodes;
}
/* прямоугольник узла сейчас: во время анимации — между старым и новым положением */
function mapRectFn(nodes){
  if(!MAP.from)return i=>nodes[i].r;
  const e=easeOut(clamp((performance.now()-MAP.t0)/MAP_ANIM,0,1)),F=MAP.from;
  return i=>{const a=F[i],b=nodes[i].r;return {x:a.x+(b.x-a.x)*e,y:a.y+(b.y-a.y)*e,w:a.w+(b.w-a.w)*e,h:a.h+(b.h-a.h)*e};};
}
/* подушки — попиксельно, в отдельный холст; scale < 1 — черновое качество во время анимации.
   Правый и нижний пиксель плитки — тёмная граница: соседние плитки разделены ровно одной
   чёткой линией (как в WizTree), даже если они одного цвета. */
const MAP_LINE=0xff121212; // цвет всех линий сетки (ABGR)
/* flat — кадры анимации: плитки ровным цветом, но в полном разрешении (половинное размывало сетку
   до 2 px и давало тёмные дыры); подушки дорисовываются в последнем кадре */
function mapPaint(cv,nodes,rect,scale,flat){
  const w=cv.clientWidth,h=cv.clientHeight,k=(devicePixelRatio||1)*scale;
  const PW=Math.max(1,Math.round(w*k)),PH=Math.max(1,Math.round(h*k)),off=MAP.off;
  if(off.width!==PW||off.height!==PH){off.width=PW;off.height=PH;}
  const ox=off.getContext('2d'),[Lx,Ly,Lz]=CUSH.L;
  if(!MAP.img||MAP.img.width!==PW||MAP.img.height!==PH)MAP.img=ox.createImageData(PW,PH);
  const img=MAP.img,d=new Uint32Array(img.data.buffer);MAP.draft=scale<1||!!flat;
  d.fill(MAP_LINE);
  const IA=CUSH.IA,BR=CUSH.BR,bw=Math.max(1,Math.round(k)),px8=(r,g,b)=>(0xff000000|(b>255?255:b|0)<<16|(g>255?255:g|0)<<8|(r>255?255:r|0))>>>0;
  for(let i=0;i<nodes.length;i++){
    const n=nodes[i];if(n.head)continue;const r=rect(i);
    const x0=Math.max(0,Math.round(r.x*k)),x1=Math.min(PW,Math.round((r.x+r.w)*k)),y0=Math.max(0,Math.round(r.y*k)),y1=Math.min(PH,Math.round((r.y+r.h)*k));
    if(x1<=x0||y1<=y0)continue;
    const s=[0,0,0,0];addRidge({x:r.x,y:r.y,w:Math.max(r.w,.5),h:Math.max(r.h,.5)},s,CUSH.H);
    const R=n.rgb[0],G=n.rgb[1],B=n.rgb[2],s0=2*s[0],s1=2*s[1],s2=s[2],s3=s[3];
    const xe=x1-x0>bw?x1-bw:x1,ye=y1-y0>bw?y1-bw:y1,line=MAP_LINE; // линия по каждой оси отдельно — тонкая полоска не сливается с соседом
    for(let py=y0;py<y1;py++){
      let o=py*PW+x0;
      if(py>=ye){d.fill(line,o,o+(x1-x0));continue;}
      if(flat){d.fill(px8(R*.97,G*.97,B*.97),o,o+(xe-x0));o+=xe-x0;if(xe<x1)d.fill(line,o,o+(x1-xe));continue;}
      const ny=-(s1*(py+.5)/k+s3),ny2=ny*ny+1,cy=ny*Ly+Lz;
      for(let px=x0;px<xe;px++,o++){
        const nx=-(s0*(px+.5)/k+s2);
        let ca=(nx*Lx+cy)/Math.sqrt(nx*nx+ny2);if(ca<0)ca=0;
        const I=(IA+(1-IA)*ca)*BR;
        d[o]=px8(R*I,G*I,B*I);
      }
      if(xe<x1)d.fill(line,o,o+(x1-xe));
    }
  }
  ox.putImageData(img,0,0);
}
const MAP_HEAD=['#262626','#323232','#3e3e3e','#4a4a4a']; // шаг 12 — соседние уровни различимы на глаз
/* текст, не влезающий по ширине, — с многоточием, а не обрезанный посреди буквы */
const FIT=new Map(); // подобранные строки: подпись·ширина·шрифт → текст (иначе в кадре анимации тысячи measureText)
function fitText(x,t,w){w=Math.floor(w/4)*4;const key=t+''+w+''+x.font,c=FIT.get(key);if(c!=null)return c;
  let r=t;if(x.measureText(t).width>w){const s=Array.from(t);let lo=0,hi=s.length; // по символам, а не по UTF-16: эмодзи не режется пополам
    while(lo<hi){const mid=(lo+hi+1)>>1;if(x.measureText(s.slice(0,mid).join('')+'…').width<=w)lo=mid;else hi=mid-1;}
    r=lo?s.slice(0,lo).join('').trimEnd()+'…':'';}
  if(FIT.size>4000)FIT.clear();FIT.set(key,r);return r;}
/* белый или почти чёрный текст — какой контрастнее (WCAG) на этой плитке; яркость «на глаз» ошибалась на розовом */
const relLum=c=>c.reduce((s,v,i)=>{v/=255;v=v<=.03928?v/12.92:((v+.055)/1.055)**2.4;return s+v*[.2126,.7152,.0722][i];},0);
const darkText=c=>{const L=relLum(c.map(v=>Math.min(255,v*1.08)));return (L+.05)/.0556>1.05/(L+.05);};
/* поверх подушек: заголовки групп, подписи, рамки выделения и наведения.
   Всё рисуется в физических пикселях с целыми координатами — линии не размываются в полупиксель. */
/* подушки + заголовки + подписи — в отдельный слой MAP.base; наведение перерисовывает только рамки */
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
    /* заголовок кончается там, где начинаются дети (при масштабе 125 % 18 px — не целое число пикселей);
       как и плитка, он оставляет правую и нижнюю линию фону */
    const hb=Math.min(Math.round((r.y+MAP_HDR)*dpr)-q.y,q.h);
    /* вложенные уровни — на тон светлее, чтобы стопка заголовков читалась как вложенность */
    x.fillStyle=MAP_HEAD[Math.min(n.depth,MAP_HEAD.length-1)];x.fillRect(q.x,q.y,q.w-L,hb-L);
    x.fillStyle='rgba(255,255,255,.9)';
    const t1=`${m.label} (${mapFmt(m.raw)})`,mw=q.w-2*pad;x.fillText(x.measureText(t1).width<=mw?t1:fitText(x,m.label,mw),q.x+pad,q.y+(hb-L)/2+.5);
  }
  for(let i=0;i<nodes.length;i++){
    const n=nodes[i],m=n.m,r=rect(i);
    /* подпись: имя и размер от 70×32, только имя — от 40×16 */
    const two=r.w>70&&r.h>32;if(n.head||!(two||r.w>40&&r.h>16))continue;
    const q=D(r),lt=darkText(n.rgb),mw=q.w-2*pad-L;
    x.save();x.fillStyle=lt?'#111':'#fff';if(!lt&&!MAP.draft){x.shadowColor='rgba(0,0,0,.85)';x.shadowBlur=3*dpr;} // в кадрах анимации без тени — дорого
    x.fillText(fitText(x,m.self?`${m.label} · сам`:n.pre?`${n.pre} · ${m.label}`:m.label,mw),q.x+pad+L,two?q.y+Math.round(12*dpr):q.y+q.h/2);
    if(two){x.fillStyle=lt?'rgba(0,0,0,.72)':'rgba(255,255,255,.85)';x.fillText(fitText(x,mapFmt(m.raw),mw),q.x+pad+L,q.y+Math.round(27*dpr));}x.restore();
  }
  mapFrames(cv,nodes,rect);
}
/* рамки выделения и наведения — поверх готового слоя; рамка идёт по линиям сетки вокруг плитки,
   а не внутри неё (иначе слева-сверху она лежала на цвете, а справа-снизу — на линии) */
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
    if(MAP.hover&&mapId(n)===MAP.hover)hov=D(rect(i)); // наведение на заголовок обводит всю группу
    if(MAP.hl&&!n.head&&mapExe(m)!==MAP.hl){const q=D(rect(i));x.fillStyle='rgba(18,18,18,.62)';x.fillRect(q.x+L,q.y+L,q.w-L,q.h-L);}} // программа из легенды — остальные притушены
  if(sel)frame(sel,2*L,'#fff');
  if(hov)frame(hov,L,'rgba(255,255,255,.95)');
}
function mapAnimate(){
  cancelAnimationFrame(MAP.raf);
  const step=now=>{
    const el=PANEL_EL.map,nodes=MAP.nodes;if(!vis(el)||!nodes||!MAP.from){MAP.from=null;return;}
    const cv=$('canvas',el);
    if(now-MAP.t0>=MAP_ANIM){MAP.from=null;const r=i=>nodes[i].r;mapPaint(cv,nodes,r,1);mapCompose(cv,nodes,r);return;}
    /* кадры — с подушками, как и неподвижная карта: плоские кадры на 0,45 с «гасили» тени при каждом сдвиге
       (≈ 8 мс на кадр при 1300×700) */
    if(now-MAP.last>=30){MAP.last=now;const r=mapRectFn(nodes);mapPaint(cv,nodes,r,1);mapCompose(cv,nodes,r);}
    MAP.raf=requestAnimationFrame(step);
  };
  MAP.raf=requestAnimationFrame(step);
}
/* шапка и легенда — до замера холста: их высота не должна менять размер карты уже после отрисовки */
/* не поместившиеся пункты легенды — одним «+N» с полным списком во всплывающей подсказке */
function fitLegend(leg){
  if(leg._fitH===leg._h&&leg._fitW===leg.clientWidth)return;leg._fitH=leg._h;leg._fitW=leg.clientWidth;
  const old=leg.querySelector('.more');if(old)old.remove();const kids=[...leg.children];kids.forEach(k=>k.style.display='');
  const W=leg.clientWidth-parseFloat(getComputedStyle(leg).paddingRight),over=kids.filter(k=>k.offsetLeft+k.offsetWidth>W);if(!over.length)return;
  const room=W-70,hide=kids.filter(k=>k.offsetLeft+k.offsetWidth>room);hide.forEach(k=>k.style.display='none');
  const m=document.createElement('span');m.className='more';m.textContent=`+${hide.length}`;m.title=hide.map(k=>k.dataset.n||k.textContent).join('\n');leg.appendChild(m);}
function mapChrome(el){
  $('.m-color',el).querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.c===S.map.color));
  {const d=$('.m-desc',el),t=mapDesc();if(d.textContent!==t){d.textContent=t;d.title=t;}} // длинное описание обрезается многоточием — целиком в подсказке
  /* «хлебные крошки» — по иерархии карты: всё › приложение › процессы этого приложения */
  const zr=S.map.root&&/^\d/.test(S.map.root)&&NODES.get(S.map.root),r0=curRes(),crumb=(z,t,cur)=>`<span class="sep">›</span>${cur?`<span class="cur">${esc(t)}</span>`:`<a data-z="${esc(z)}">${esc(t)}</a>`}`;
  let cr='';
  if(zr){const app=APPS.get(zr.appKey),items=[];if(app)items.push(['a'+zr.appKey,mapLabel(app.title)]);
    for(const x of ancestors(zr).filter(x=>x.appKey===zr.appKey).concat([zr]))items.push([x.id,mapLabel(nameOf(x))]);
    const ded=items.filter((it,i)=>i===items.length-1||it[1]!==items[i+1][1]); // «Claude › Claude» → «Claude»
    cr=ded.map((it,i)=>crumb(it[0],it[1],i===ded.length-1)).join('');}
  else if(S.map.root)cr=crumb(S.map.root,MAP.rootLabel||'',true);
  setHTML($('.m-crumbs',el),`<a data-z="root">${esc(r0.name)} · всё</a>`+cr);
  /* легенда — все цветные программы этого вида понятными именами (наведение подсвечивает их плитки)
     и два серых отдельно; одна строка — лишнее уходит за край, высота карты не прыгает */
  const exeLeg=()=>{const t=MAP.exeTot||new Map(),rgb=c=>`rgb(${c.join(',')})`,nm=k=>(MAP.exeName&&MAP.exeName.get(k))||exeTitle(k);
    const top=[...t].filter(([k,v])=>COLORS[k]&&v>(MAP.total||0)*1e-3).sort((p,q)=>q[1]-p[1]),ks=[...t.keys()];
    const hasW=ks.some(k=>k.startsWith('w:')||k.startsWith('k:')),hasO=ks.some(k=>!/^[wkr]:/.test(k)&&!COLORS[k]);
    if(MAP.hl&&!t.has(MAP.hl))MAP.hl=null;
    return (hasW?`<span><i style="background:${rgb(SLATE)}"></i>Windows</span>`:'')+(hasO?`<span><i style="background:${rgb(WARM)}"></i>прочие программы</span>`:'')
      +top.map(([k,v])=>`<span class="lk" data-k="${esc(k)}" data-n="${esc(nm(k))} ${esc(mapFmt(v))}" title="${esc(k)} — все процессы программы, в том числе в других группах"><i style="background:${EXE_PAL[COLORS[k][0]]}"></i>${esc(nm(k))} <span class="num">${mapFmt(v)}</span></span>`).join('');};
  setHTML($('.m-leg',el),S.map.color==='exe'?exeLeg():S.map.color==='cat'?Object.values(CATS).map(c=>`<span><i style="background:${c.c}"></i>${c.n}</span>`).join(''):
    `<span><i style="background:${heat(0)}"></i>простаивает</span><span><i style="background:${heat(6)}"></i>~6 % ЦП</span><span><i style="background:${heat(12)}"></i>12 % и выше</span><span><i style="background:rgb(${WARM.join(',')})"></i>не процесс</span>`);
  fitLegend($('.m-leg',el));
}
/* force — данные изменились без нового замера (пришла история за период) */
function renderMap(force){
  const el=PANEL_EL.map;if(!vis(el)||!SYS)return;
  if(S.map.root&&/^\d/.test(S.map.root)&&!alive(NODES.get(S.map.root)))S.map.root=null; // приближенный процесс завершился — сразу к общему виду
  mapChrome(el);
  const cv=$('canvas',el),w=cv.clientWidth,h=cv.clientHeight;if(!w||!h)return;
  /* сброс раскладки — только при смене ресурса, приближения, периода. Смена размера перекладывает
     плитки без анимации, но сохраняет порядок, ряды и сглаживание */
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
    /* приближенная группа исчезла прямо сейчас (mapTree сбросил корень) — один сброс, а не два подряд */
    if(S.map.root!==root0){reset();prev=null;nodes=mapLayout(w,h);}
    if(S.map.color==='exe'){updateExeColors();exeTotals(nodes);}
    const cpuOf=m=>m.ghost?0:m.rest?m.items.reduce((s,k)=>s+cpuOf(k),0):m.node&&alive(m.node)?(m.self?m.node.cpu:cur(m.node,'cpu',true)):m.kids?m.kids.reduce((s,k)=>s+cpuOf(k),0):0;
    /* память вне процессов в режиме ЦП — нейтральный серый, а не «простаивает»: у неё нет ЦП вовсе */
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
    /* анимация — только если строение то же: те же плитки в том же порядке и рядах. Тогда и промежуточные
       кадры без дыр; иначе плитки перелетали друг через друга, оставляя чёрные провалы — лучше сразу на место */
    const topo=ns=>ns.map(n=>id(n)+'<'+n.parent).join('|'),calm=same&&ps0===psig()&&topo(prev)===topo(nodes);
    let show=nodes;
    if(same&&move<MAP_DEAD){
      /* раскладка почти та же — геометрию не трогаем (никакого дрожания), обновляем подписи и цвета */
      const by=new Map(nodes.map(n=>[id(n),n]));
      for(const p of prev){const n=by.get(id(p));p.m=n.m;p.path=n.path;if(!p.head)p.rgb=n.rgb;}
      show=prev;
      if(!MAP.from){const r=i=>prev[i].r;if(recolor||MAP.draft)mapPaint(cv,prev,r,1);mapCompose(cv,prev,r);}
    }else{
      /* плитка появилась, пропала или соседи поменялись местами — сразу на место, без анимации */
      MAP.nodes=nodes;MAP.from=calm&&move>=MAP_DEAD?from:null;
      const r=i=>nodes[i].r;
      if(MAP.from){MAP.t0=performance.now();MAP.last=0;mapAnimate();}
      else{cancelAnimationFrame(MAP.raf);mapPaint(cv,nodes,r,1);mapCompose(cv,nodes,r);}
    }
    /* двойной клик — приблизить группу плитки (приложение или процесс с дочерними), если внутри больше
       одной плитки; иначе «приблизить нельзя» (раньше одиночный процесс открывался одной плиткой на всю карту) */
    const real=g=>g.kids?g.kids.filter(x=>!x.ghost):[];
    const zOf=g=>{const k=real(g);return k.length>1||k.length===1&&real(k[0]).length>1?(g.zoomId||(g.node?g.node.id:null)):null;};
    const procs=m=>m.ghost?0:m.rest?m.items.reduce((s,k)=>s+procs(k),0):m.kids?m.kids.reduce((s,k)=>s+procs(k),0):m.node?1:0;
    const zoomOf=n=>{let z=zOf(n.m);if(z&&z!==S.map.root)return z;for(let p=n.parent;p>=0;p=show[p].parent){z=zOf(show[p].m);if(z&&z!==S.map.root)return z;}return null;};
    cv._rects=show.map(n=>{const m=n.m,q=n.r,z=zoomOf(n);return {id:mapId(n),x:q.x,y:q.y,w:q.w,h:n.head?MAP_HDR:q.h,node:m.node||m.rep||null,label:m.label,v:m.raw,path:n.path,
      self:m.self,own:!!m.node,procs:procs(m),cpu:cpuOf(m),rest:m.rest?m.items.map(k=>k.label):null,short:m.short||null,done:!!m.done,unseen:m.key==='mUNSEEN',zoom:z};});
    if(MAP.mouse){const h=hitMap(cv,MAP.mouse);mapHover(h&&h.id);}
    mapChrome(el); // «крошки» и легенда — по новой раскладке (имя приближенного, суммы программ); высота у них постоянная
    mapStatus();
  }else if(MAP.nodes&&!MAP.from){const r=i=>MAP.nodes[i].r;if(MAP.draft){mapPaint(cv,MAP.nodes,r,1);mapCompose(cv,MAP.nodes,r);}else mapFrames(cv,MAP.nodes,r);} // выбор — только рамки
}

/* =================================================================
   Ряд нагрузки процесса вместе с дочерними за выбранный период:
   до 5 минут — посекундные данные самих процессов,
   дольше — история приложения, к которому относится процесс.
   ================================================================= */
function nodeSeries(n,m){
  const R=S.range;
  if(R.ms<=SPARKN*1000){
    const keys=appDesc(n).map(x=>[x.pid,x.ct]);const pts=Math.round(R.ms/1000);
    const v=SP(keys,BY[m]==='io'?'io':BY[m],pts);if(!v)return null;
    const data=v[0].map(conv(m));return {t0:NOW-(data.length-1)*1000,step:1000,data,caption:appDesc(n).length>1?'с дочерними процессами приложения':''};
  }
  /* у прерываний и DPC долгой истории нет, а «всё приложение Windows» — не они: последние 5 минут */
  if(PSEUDO[n.pid]){const data=rtail(m==='cpu'?n.rc:n.rio,SPARKN);return {t0:NOW-(data.length-1)*1000,step:1000,data,caption:'последние 5 минут'};}
  const a=appOf(n);if(!a)return {t0:NOW,step:1000,data:[],caption:''};
  const h=H('apps',BY[m],1,[a.key]);if(!h)return null;
  const s=h.series[0];const data=s?s.values.map(conv(m)):new Array(h.points).fill(0);
  return {t0:h.start_ms,step:h.step_ms,missing:h.missing,data,caption:`всё приложение «${a.title}»`};
}

/* =================================================================
   Главная зона: вкладка отдельного процесса («открыть отдельно»)
   ================================================================= */
const PROC_TABS=new Map();
function mountProcTab(el,id){
  PROC_TABS.set(id,el);
  el.innerHTML='<div class="scroll pt-body"></div>';
  el.addEventListener('click',e=>{const j=e.target.closest('[data-go]');if(j)select(j.dataset.go,true);});
  el.addEventListener('mousemove',e=>{const cv=e.target.closest('canvas');if(cv)chartHover(cv,cv.nextElementSibling,e);});
  el.addEventListener('mouseout',e=>{if(e.target.tagName==='CANVAS'){S.hoverT=null;e.target.nextElementSibling.style.display='none';renderCharts();}});
}
function renderProcTabs(chartsOnly){
  for(const [id,el] of PROC_TABS){
    if(!vis(el))continue;const n=NODES.get(id),body=$('.pt-body',el);
    if(!n){body.innerHTML='<div class="empty">Процесс завершился, данных больше нет</div>';continue;}
    if((!chartsOnly||!body._m)&&!(body._m&&selIn(body))){
      body._m=1;
      body.innerHTML=`<div class="dt-h">${ico(n,1)}<div><h3>${esc(nameOf(n))}</h3><div class="caption">PID ${n.pid} · ${esc(n.exe)} · ${n.alive?'работает '+agoStr((NOW-ctToMs(n.ct))/1000):'завершён'} · вместе с дочерними: ${desc(n).length}</div></div></div>
        <div class="crumbs"><span class="caption" style="margin-right:4px">Кто запустил:</span>${ancestors(n).map(a=>`<a data-go="${esc(a.id)}">${esc(nameOf(a))}</a>`).join('<span class="sep">›</span>')||'<span class="caption">система</span>'}</div>
        <div class="pt-grid">${[['cpu','ЦП'],['mem','Память'],['dsk','Диск']].map(([m,t])=>`<div class="cell"><div class="caption"><span class="pt-cap" data-m="${m}">${t}</span></div><canvas data-m="${m}"></canvas><div class="pop"></div></div>`).join('')}</div>`;
    }
    for(const cv of body.querySelectorAll('canvas')){const m=cv.dataset.m,c=COLS.find(c=>c.m===m);
      const s=nodeSeries(n,m);const cap=body.querySelector(`.pt-cap[data-m="${m}"]`);
      if(cap)cap.textContent=`${c.t}${s&&s.caption?' · '+s.caption:''} · ${S.range.label}`;
      if(!s){drawTS(cv,{series:[],t0:NOW,step:1000,fmt:c.fmt,empty:'Загружаю историю…'});continue;}
      drawTS(cv,{series:[{name:c.t,color:PAL[{cpu:0,mem:2,dsk:4}[m]],data:s.data}],t0:s.t0,step:s.step,missing:s.missing,fmt:c.fmt,fill:true});}
  }
}
function openProcTab(id){
  const n=NODES.get(id);if(!n)return;const pid='proc:'+id;
  const ex=dock.getPanel(pid);if(ex){ex.api.setActive();return;}
  dock.addPanel({id:pid,component:'proc',title:nameOf(n),params:{id}});
  requestAnimationFrame(()=>{renderAll();flushNeeds();});
}

/* =================================================================
   Главная зона: «Docker» — контейнеры из Docker Engine.
   Процессы контейнеров в Windows видны одним vmmem; здесь — разбивка.
   Статистику движок собирает, только пока вкладку кто-то смотрит.
   ================================================================= */
let DOCKER=null,dockerBusy=false,dockerAt=0;
const DK_ACTS={start:'Запустить',stop:'Остановить',restart:'Перезапустить',pause:'Приостановить',unpause:'Продолжить',kill:'Остановить принудительно'};
function mountDocker(el){
  el.innerHTML=`<div class="ph"><span class="caption dk-head">Подключаюсь к Docker…</span><div class="spacer"></div><span class="caption">процессы контейнеров в списке Windows видны одним vmmem</span></div>
    <div class="tbl-wrap"><table class="tbl" style="min-width:680px"><colgroup><col><col style="width:72px"><col style="width:84px"><col style="width:136px"><col style="width:128px"><col style="width:44px"><col style="width:40px"></colgroup>
    <thead><tr><th style="cursor:default">Контейнер</th><th class="act">ЦП</th><th>Память</th><th>Сеть ↓ / ↑</th><th>Диск чт. / зап.</th><th>PID</th><th style="cursor:default"></th></tr></thead><tbody></tbody></table></div>
    <div class="empty dk-empty" hidden></div>`;
  const open=(e,id)=>{
    const c=DOCKER&&DOCKER.containers.find(x=>x.id===id);if(!c)return;
    const on=c.state==='running',paused=c.state==='paused';
    const acts=on?['stop','restart','pause','kill']:paused?['unpause','stop','kill']:['start'];
    menuIds=null;
    menu.innerHTML=`<div class="mh">${esc(c.name)} · ${esc(c.image)}</div>`+acts.map(a=>`<div class="mi${a==='kill'||a==='stop'?' danger':''}" data-dk="${a}" data-id="${esc(c.id)}"><span>${DK_ACTS[a]}</span></div>`).join('');
    menu.style.display='block';const r=menu.getBoundingClientRect();
    menu.style.left=Math.min(e.clientX,innerWidth-r.width-8)+'px';menu.style.top=Math.max(8,Math.min(e.clientY,innerHeight-r.height-8))+'px';
  };
  el.addEventListener('click',e=>{const b=e.target.closest('[data-dkm]');if(b)open(e,b.dataset.dkm);});
  el.addEventListener('contextmenu',e=>{const tr=e.target.closest('tr[data-id]');if(!tr)return;e.preventDefault();open(e,tr.dataset.id);});
}
/* перезапуск от администратора — из шапки, из меню и по ссылкам там, где без прав чего-то не видно */
const isAdmin=()=>!!(SYSINFO&&SYSINFO.elevated);
const ADMIN_LINK=' <a class="admin-link" data-admin>Перезапустить от администратора</a>';
async function runAdmin(){if(!TAURI)return toast('Запустите приложение, а не режим разработки','yel');
  toast('Подтвердите запуск в окне Windows — если его не видно, нажмите мигающий щит на панели задач','info');
  try{await appCmd('admin');}catch(err){toast(err.message||String(err),'yel');}}
$('#adminBtn').addEventListener('click',runAdmin);
document.addEventListener('click',e=>{if(e.target.closest('[data-admin]')){e.preventDefault();runAdmin();}});
menu.addEventListener('click',async e=>{
  const b=e.target.closest('[data-dk]');if(!b)return;closeMenu();
  const c=DOCKER&&DOCKER.containers.find(x=>x.id===b.dataset.id);if(!c)return;
  const a=b.dataset.dk;
  try{await rpc('docker_act',{id:c.id,action:a,name:c.name});toast(`Docker: ${c.name} — ${DK_ACTS[a].toLowerCase()}: готово`,'ok');}
  catch(err){toast(err.message||String(err),'red',6000);}
  dockerAt=0;renderDocker();
});
function fetchDocker(){
  if(dockerBusy||Date.now()-dockerAt<1800)return;
  dockerBusy=true;
  rpc('docker').then(d=>{DOCKER=d;}).catch(e=>{DOCKER={available:false,error:e.message||String(e),containers:[]};})
    .finally(()=>{dockerBusy=false;dockerAt=Date.now();renderDocker(true);});
}
function renderDocker(fromFetch){
  const el=PANEL_EL.docker;if(!vis(el))return;
  if(!fromFetch)fetchDocker();
  const head=$('.dk-head',el),empty=$('.dk-empty',el),tb=$('tbody',el);
  if(!DOCKER){return;}
  if(!DOCKER.available){
    head.textContent='Docker недоступен';
    empty.hidden=false;setHTML(empty,`${esc(DOCKER.error||'Docker не запущен')}.<br>Запустите Docker Desktop — контейнеры появятся здесь сами.`);
    patchRows(tb,[]);return;
  }
  empty.hidden=true;
  const run=DOCKER.containers.filter(c=>c.state==='running'||c.state==='paused');
  const cpu=run.reduce((s,c)=>s+c.cpu,0),mem=run.reduce((s,c)=>s+c.mem,0);
  setHTML(head,`Docker ${esc(DOCKER.version||'')} · контейнеров ${DOCKER.containers.length}, работает ${run.length} · вместе ЦП ${fmtPct(cpu)}, память ${fmtMem(mem/MB)}`);
  patchRows(tb,DOCKER.containers.map(c=>{
    const on=c.state==='running',paused=c.state==='paused';
    const dash='<span style="color:var(--text-4)">—</span>';
    return {id:c.id,cls:on?'':'susp',cells:[
      {h:`<div class="nm"><span class="n1">${esc(c.name)}</span><span class="n2">${esc(c.image)} · ${esc(c.id)}</span>${c.project?`<span class="chip">${esc(c.project)}</span>`:''}${on?'':`<span class="chip">${esc(c.status)}</span>`}</div>`},
      {c:'act',h:on?`<span class="cell-bar" style="width:${clamp(c.cpu,0,100).toFixed(1)}%"></span><span class="cell-v">${fmtPct(c.cpu)}</span>`:dash},
      {h:on||paused?`<span class="cell-v">${fmtMem(c.mem/MB)}</span>`:dash,t:c.mem_limit?`лимит ${fmtMem(c.mem_limit/MB)}`:''},
      {h:on?`<span class="cell-v">${fmtMbit(c.net_rx_bps*8/1e6)} / ${fmtMbit(c.net_tx_bps*8/1e6)}</span>`:dash},
      {h:on?`<span class="cell-v">${fmtMBs(c.blk_read_bps/MB)} / ${fmtMBs(c.blk_write_bps/MB)}</span>`:dash},
      {h:on||paused?`<span class="cell-v">${c.pids}</span>`:dash},
      {h:`<button class="ib" data-dkm="${esc(c.id)}" title="Действия">⋯</button>`},
    ]};
  }));
}

/* =================================================================
   Пул ядра: память драйверов и объектов ядра по меткам — её не видно ни у одного процесса.
   Движок снимает пул раз в минуту и считает рост; панель спрашивает, только пока видна.
   ================================================================= */
let POOL=null,poolBusy=false,poolAt=0,POOLA=[];
const PS={by:'size'};
function mountPool(el){
  el.innerHTML=`<div class="ph"><span class="caption pl-head">Читаю пул ядра…</span><div class="spacer"></div>
    <div class="seg pl-by"><button data-b="size">По размеру</button><button data-b="growth">По росту</button></div>
    <button class="btn pl-own" title="Поискать метки в файлах загруженных драйверов (10–30 с, в фоне)">Найти драйверы</button></div>
    <div class="pl-alerts"></div>
    <div class="tbl-wrap"><table class="tbl" style="min-width:740px"><colgroup><col style="width:78px"><col><col style="width:88px"><col style="width:88px"><col style="width:96px"><col style="width:100px"><col style="width:124px"></colgroup>
    <thead><tr><th style="cursor:default">Метка</th><th style="cursor:default;text-align:left">Что это</th><th>Невыгр.</th><th>Выгр.</th><th>Объектов</th><th>Рост в час</th><th style="cursor:default">График</th></tr></thead><tbody></tbody></table></div>
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
/* форма ряда от минимума до максимума: рост 190 → 192 МБ иначе не заметен */
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
  if(POOL.error){setHTML(head,'Пул ядра недоступен: '+esc(POOL.error));patchRows(tb,[]);return;}
  const cnt=v=>Math.round(v).toLocaleString('ru');
  const watch=POOL.watching_ms>=600e3?` · наблюдение ${agoStr(POOL.watching_ms/1000)}`:'';
  const zomb=POOL.zombie_procs||POOL.zombie_threads?` · завершённых, но не освобождённых: процессов ${cnt(POOL.zombie_procs)}, потоков ${cnt(POOL.zombie_threads)}`:'';
  setHTML(head,`Невыгружаемый ${fmtMem(POOL.nonpaged/MB)} · выгружаемый ${fmtMem(POOL.paged/MB)}${watch}${zomb}`);
  const o=POOL.owners||{};
  own.disabled=o.state==='running';
  own.textContent=o.state==='running'?`Ищу… ${o.total?Math.round(o.scanned/o.total*100):0} %`:o.state==='done'?'Искать заново':'Найти драйверы';
  setHTML($('.pl-alerts',el),(POOL.alerts||[]).map(a=>`<div class="issue ${a.level}"><span class="dot ${a.level}"></span><span>${esc(a.text)}</span></div>`).join(''));
  const dash='<span style="color:var(--text-4)">—</span>';
  const rate=r=>r==null?dash:Math.abs(r)<65536?'0':`${r>0?'+':'−'}${fmtMem(Math.abs(r)/MB)}`;
  patchRows(tb,POOL.tags.map(t=>{
    const own=t.owners||[];
    const who=own.length?`<span class="n2">${esc(own.slice(0,3).join(', '))}${own.length>3?` и ещё ${own.length-3}`:''}</span>`:o.state==='done'&&!t.about?'<span class="n2">драйвер не найден</span>':'';
    return {id:t.tag,cls:'',cells:[
      {h:`<div class="nm"><span class="n1 mono">${esc(t.tag)}</span>${t.alert?'<span class="dot red"></span>':''}</div>`},
      {h:`<div class="nm">${t.about?`<span class="n1">${esc(t.about)}</span>`:''}${who}</div>`,t:[t.about,own.length?'Встречается в: '+own.join(', '):''].filter(Boolean).join('\n')},
      {h:t.nonpaged?`<span class="cell-v">${fmtMem(t.nonpaged/MB)}</span>`:dash},
      {h:t.paged?`<span class="cell-v">${fmtMem(t.paged/MB)}</span>`:dash},
      {h:`<span class="cell-v">${cnt(t.count)}</span>`},
      {c:t.rate>=1048576?'act':'',h:`<span class="cell-v">${rate(t.rate)}</span>`,
       t:t.count_rate!=null?`объектов ${t.count_rate>0?'+':''}${cnt(t.count_rate)} в час · посчитано за ${agoStr(t.rate_window_ms/1000)}`:'рост появится после 10 минут наблюдения'},
      {h:poolSpark(t.spark),t:t.spark_step_ms?`последние ${agoStr((t.spark.length-1)*t.spark_step_ms/1000)}, точка раз в ${t.spark_step_ms/60000} мин`:''},
    ]};
  }));
  setHTML($('.pl-foot',el),(POOL.watching_ms<600e3?'Рост в час появится через 10 минут: движок снимает пул раз в минуту. ':'')+
    'Метка — четыре буквы, которыми ядро или драйвер помечает свою память. Если метка растёт без остановки, это утечка: память освободит перезагрузка, а остановит рост обновление или удаление виновника.');
}

/* =================================================================
   Службы Windows: список, запуск и остановка; какие службы живут в каком svchost
   ================================================================= */
let SVCS=null,svcBusy=false,svcAt=0,svcNamesAt=0;
const SV={q:'',all:false};
let SVC_BY_PID=new Map(); /* pid → службы внутри процесса (имена для svchost.exe) */
const SVC_STATE={running:'работает',stopped:'остановлена',start_pending:'запускается',stop_pending:'останавливается',paused:'приостановлена',pause_pending:'приостанавливается',continue_pending:'продолжается'};
const SVC_START={auto:'Автоматически',auto_delayed:'Автоматически (отложенно)',manual:'Вручную',disabled:'Отключена',boot:'При загрузке',system:'При загрузке'};
function indexSvcs(list){const m=new Map();for(const s of list)if(s.pid){if(!m.has(s.pid))m.set(s.pid,[]);m.get(s.pid).push(s);}SVC_BY_PID=m;}
/* имена служб нужны и без открытой вкладки: у svchost.exe в списке процессов — какие службы внутри */
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
/* PID → живой узел: карта на полсекунды, а не проход по всем узлам на каждую строку служб и подключений */
let PIDM=null;
const nodeByPid=pid=>{const t=performance.now();if(!PIDM||t-PIDM.t>500){const m=new Map();for(const n of NODES.values())if(n.alive)m.set(n.pid,n);PIDM={t,m};}return PIDM.m.get(pid)||null;};
function mountSvcs(el){
  el.innerHTML=`<div class="ph"><input class="search sv-q" placeholder="Поиск службы…">
      <label class="chk"><input type="checkbox" class="sv-all"> и остановленные</label>
      <div class="spacer"></div><span class="caption sv-head">Читаю список служб…</span></div>
    <div class="tbl-wrap"><table class="tbl left" style="min-width:540px"><colgroup><col><col style="width:108px"><col style="width:112px"><col style="width:136px"><col style="width:40px"></colgroup>
    <thead><tr><th style="cursor:default;text-align:left">Служба</th><th style="cursor:default;text-align:left">Состояние</th><th style="cursor:default;text-align:left">Запуск</th><th style="cursor:default;text-align:left">Процесс</th><th style="cursor:default"></th></tr></thead><tbody></tbody></table></div>
    <div class="caption sv-foot" style="padding:6px 14px 8px"></div>`;
  $('.sv-q',el).addEventListener('input',e=>{SV.q=e.target.value.trim().toLowerCase();renderSvcs(true);});
  $('.sv-all',el).addEventListener('change',e=>{SV.all=e.target.checked;renderSvcs(true);});
  const open=(e,name)=>{
    const s=SVCS&&SVCS.services.find(x=>x.name===name);if(!s)return;
    const on=s.state==='running',off=s.state==='stopped';
    const it=[];
    /* без прав администратора Windows не даст управлять службами: пункты видны, но недоступны */
    const off2=SVCS.elevated?'':' off';
    if(!SVCS.elevated&&(off||(on&&s.can_stop)))it.push('<div class="mh">Нужны права администратора</div>');
    if(off)it.push(`<div class="mi${off2}" data-sva="start" data-name="${esc(s.name)}"><span>Запустить</span></div>`);
    if(on&&s.can_stop)it.push(`<div class="mi danger${off2}" data-sva="stop" data-name="${esc(s.name)}"><span>Остановить</span></div>`,`<div class="mi danger${off2}" data-sva="restart" data-name="${esc(s.name)}"><span>Перезапустить</span></div>`);
    if(!SVCS.elevated&&(off||(on&&s.can_stop))&&TAURI)it.push('<div class="mi" data-svadm="1"><span>Перезапустить диспетчер от администратора…</span></div>');
    if(s.pid&&nodeByPid(s.pid))it.push('<div class="sep"></div>',`<div class="mi" data-svgo="${s.pid}"><span>Перейти к процессу</span></div>`);
    if(!it.length)it.push('<div class="mh">Служба не принимает команды</div>');
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
const SVC_VERB={start:'Запустить',stop:'Остановить',restart:'Перезапустить'};
async function svcAct(name,action){
  const s=SVCS&&SVCS.services.find(x=>x.name===name);if(!s)return;
  let force=false;
  if(action!=='start'){
    const users=(SVC_BY_PID.get(s.pid)||[]).filter(x=>x.name!==s.name);
    const body=`<p class="m-lead">${action==='stop'?'Служба остановится, пока её не запустят снова или не перезагрузят компьютер.':'Служба остановится и сразу запустится снова.'}${s.description?' '+esc(s.description):''}</p>
      ${s.critical?`<div class="m-warn">${ICON_WARN}<span>Системная служба: без неё Windows перестанет работать как надо (вход, запуск программ, устройства). Останавливайте, только если точно знаете зачем.</span></div>`:''}
      ${users.length?`<p class="m-lead">В том же процессе svchost работают и другие службы: ${esc(users.slice(0,6).map(x=>x.display).join(', '))}${users.length>6?` и ещё ${users.length-6}`:''} — они продолжат работать.</p>`:''}`;
    const r=await dialog({title:`${SVC_VERB[action]} службу «${s.display}»?`,body,ok:SVC_VERB[action],danger:true});
    if(!r)return;
    force=s.critical;
  }
  try{
    const r=await rpc('service_act',{name,action,force});
    toast(`${s.display}: ${SVC_STATE[r.state]||r.state}`,'ok');
  }catch(err){
    const m=err.message||String(err);
    toast(m,'red',8000,/администратор/.test(m)&&TAURI&&!isAdmin()?{t:'Запустить от администратора',f:runAdmin}:null);
  }
  fetchSvcs(true);
}
function renderSvcs(fromFetch){
  const el=PANEL_EL.svcs;if(!vis(el))return;
  if(!fromFetch)fetchSvcs();
  if(!SVCS)return;
  const head=$('.sv-head',el),tb=$('tbody',el);
  if(SVCS.error){setHTML(head,'Список служб недоступен: '+esc(SVCS.error));patchRows(tb,[]);return;}
  const all=SVCS.services,run=all.filter(s=>s.state==='running').length;
  setHTML(head,`${run} работает · всего ${all.length}${SVCS.elevated?'':' · запуск и остановка — от администратора'+ADMIN_LINK}`);
  const q=SV.q,list=all.filter(s=>(SV.all||q||s.state!=='stopped')&&(!q||s.name.toLowerCase().includes(q)||s.display.toLowerCase().includes(q)||(s.description||'').toLowerCase().includes(q)));
  const dot=st=>st==='running'?'background:var(--success)':st==='stopped'?'background:var(--text-4)':'background:var(--caution)';
  patchRows(tb,list.map(s=>{
    const n=s.pid?nodeByPid(s.pid):null;
    return {id:s.name,cls:s.state==='stopped'?'dim':'',cells:[
      {h:`<div class="nm"><span class="n1">${esc(s.display)}</span><span class="n2">${esc(s.name)}${s.critical?' · системная':''}${s.shared?'':' · свой процесс'}</span></div>`,t:s.description||''},
      {h:`<span class="sv-st"><span class="dot" style="${dot(s.state)}"></span>${SVC_STATE[s.state]||s.state}</span>`},
      {h:`<span class="caption">${SVC_START[s.start]||'—'}</span>`},
      {h:n?`<a data-go="${esc(n.id)}" class="sv-proc">${esc(n.exe)} · ${s.pid}</a>`:s.pid?`<span class="caption">PID ${s.pid}</span>`:'<span style="color:var(--text-4)">—</span>'},
      {h:`<button class="ib" data-svm="${esc(s.name)}" title="Действия">⋯</button>`,c:'stick'},
    ]};
  }));
  setHTML($('.sv-foot',el),list.length?`Показано: ${list.length}. Правый клик или «⋯» — запустить, остановить, перезапустить.`:'Ничего не найдено.');
}

/* =================================================================
   Подключения и открытые порты (GetExtendedTcpTable / GetExtendedUdpTable)
   ================================================================= */
let CONNS=null,connBusy=false,connAt=0;
const CN={q:'',listen:false,closed:false};
const CONN_STATE={listen:'ожидает',established:'установлено',time_wait:'закрывается',close_wait:'закрывается',syn_sent:'подключается',syn_received:'подключается',fin_wait1:'закрывается',fin_wait2:'закрывается',closing:'закрывается',last_ack:'закрывается',closed:'закрыто'};
const hostPort=(a,p)=>a.includes(':')?`[${a}]:${p}`:`${a}:${p}`;
function fetchConns(){
  if(connBusy||Date.now()-connAt<2000)return;
  connBusy=true;
  rpc('connections').then(d=>{CONNS=d.connections;fetchConns.err=null;}).catch(e=>{CONNS=null;const m=e.message||String(e);if(fetchConns.err!==m){fetchConns.err=m;toast('Подключения: '+m,'red');}})
    .finally(()=>{connBusy=false;connAt=Date.now();renderConns(true);});
}
function mountConns(el){
  el.innerHTML=`<div class="ph"><input class="search cn-q" placeholder="Поиск: процесс, адрес, порт…">
      <label class="chk"><input type="checkbox" class="cn-l"> только открытые порты</label>
      <label class="chk" title="Соединения в состоянии TIME_WAIT: процесс их уже закрыл, Windows держит адрес ещё пару минут"><input type="checkbox" class="cn-cl"> <span class="cn-c">и закрытые</span></label>
      <div class="spacer"></div><span class="caption cn-head"></span></div>
    <div class="tbl-wrap"><table class="tbl left" style="min-width:640px"><colgroup><col><col style="width:52px"><col style="width:170px"><col style="width:190px"><col style="width:100px"></colgroup>
    <thead><tr><th style="cursor:default;text-align:left">Процесс</th><th style="cursor:default;text-align:left">Прот.</th><th style="cursor:default;text-align:left">Локальный адрес</th><th style="cursor:default;text-align:left">Удалённый адрес</th><th style="cursor:default;text-align:left">Состояние</th></tr></thead><tbody></tbody></table></div>
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
  /* PID 0 — закрытые соединения в TIME_WAIT: процесса у них уже нет, по умолчанию скрыты */
  const closed=CONNS.filter(c=>c.pid===0).length;
  const rows=dedupConns(CONNS.filter(c=>(CN.closed||c.pid!==0)&&(!CN.listen||c.state==='listen'||c.proto==='udp'))).map(x=>{const n=nodeByPid(x.c.pid);return {...x,nd:n,nm:n?nameOf(n):''};})
    .filter(({c,nd})=>!q||String(c.pid).includes(q)||c.local.includes(q)||c.remote.includes(q)||String(c.local_port)===q||String(c.remote_port)===q||(nd&&(nameOf(nd).toLowerCase().includes(q)||nd.exe.toLowerCase().includes(q))));
  const rank=({c,nd})=>c.pid===0?2:nd?0:1;
  rows.sort((a,b)=>rank(a)-rank(b)||a.nm.localeCompare(b.nm)||a.c.local_port-b.c.local_port);
  const live=CONNS.filter(c=>c.pid!==0),est=live.filter(c=>c.state==='established').length,lis=live.filter(c=>c.state==='listen').length;
  setHTML($('.cn-head',el),`установлено ${est} · открытых TCP-портов ${lis} · UDP ${live.filter(c=>c.proto==='udp').length}`);
  $('.cn-c',el).textContent=`и закрытые (${closed})`;
  patchRows($('tbody',el),rows.slice(0,800).map(({c,n,nd})=>({id:`${c.proto}|${c.local}|${c.local_port}|${c.remote}|${c.remote_port}|${c.state}|${c.pid}`,cls:c.pid===0?'dim':'',cells:[
    {h:nd?`<div class="nm">${ico(nd)}<a data-go="${esc(nd.id)}" class="n1">${esc(nameOf(nd))}</a><span class="n2">${c.pid}</span></div>`:`<span class="caption">${c.pid?'PID '+c.pid:'завершено'}</span>`},
    {h:`<span class="caption">${c.proto.toUpperCase()}</span>`},
    {h:`<span class="mono">${esc(hostPort(c.local,c.local_port))}</span>`},
    {h:c.remote?`<span class="mono">${esc(hostPort(c.remote,c.remote_port))}</span>`:'<span style="color:var(--text-4)">—</span>'},
    {h:`<span class="caption">${c.proto==='udp'?'открыт':CONN_STATE[c.state]||c.state}${n>1?` ×${n}`:''}</span>`,t:n>1?`${n} одинаковых сокетов`:''},
  ]})));
  setHTML($('.cn-foot',el),!rows.length?'Ничего не найдено.':rows.length>800?`Показаны первые 800 из ${rows.length} — уточните поиск.`:`Показано: ${rows.length}.`);
}

/* =================================================================
   Кто держит файл: Restart Manager, как у установщиков Windows
   ================================================================= */
async function whoHolds(){
  if(DIALOG)return;
  const bg=document.createElement('div');bg.className='modal-bg top'; /* сверху: поле ввода не прыгает, когда меняется высота результата */
  bg.innerHTML=`<div class="modal" role="dialog" aria-modal="true" aria-labelledby="wh-t"><h3 id="wh-t">Кто держит файл</h3>
    <p class="m-lead">Путь к файлу или папке, которые не удаляются, не переименовываются или заняты «другим процессом».</p>
    <div class="wh-row"><input class="search wh-p" placeholder="C:\\путь\\к\\файлу или папке" spellcheck="false"><button class="btn primary wh-go">Найти</button></div>
    <div class="m-body scroll wh-res"></div>
    <div class="m-acts"><button class="btn" data-r="0">Закрыть</button></div></div>`;
  const prevFocus=document.activeElement;
  const close=()=>{bg.remove();DIALOG=null;document.removeEventListener('keydown',key,true);if(prevFocus&&prevFocus.focus)prevFocus.focus();};
  const key=e=>{e.stopImmediatePropagation();if(e.key==='Escape'){e.preventDefault();close();}else if(e.key==='Enter'&&e.target.matches('.wh-p')){e.preventDefault();go();}
    else if(e.key==='Tab'){const f=[...bg.querySelectorAll('button:not(:disabled),input')];const i=f.indexOf(document.activeElement);e.preventDefault();f[(i+(e.shiftKey?f.length-1:1))%f.length].focus();}};
  const res=$('.wh-res',bg);
  const go=async()=>{
    const path=$('.wh-p',bg).value.trim().replace(/^"|"$/g,'');if(!path)return;
    const btn=$('.wh-go',bg);if(btn.disabled)return;btn.disabled=true;
    res.innerHTML='<p class="caption">Ищу… в большой папке проверка занимает несколько секунд.</p>';
    try{
      const r=await rpc('file_holders',{path});
      const note=(r.truncated?`<p class="caption">Папка большая: проверены только ${r.files} файлов верхних уровней — для точного ответа укажите вложенную папку или файл.</p>`:'')
        +(r.skipped?`<p class="caption">Пропущено файлов без доступа: ${r.skipped}.${isAdmin()?'':ADMIN_LINK}</p>`:'');
      if(!r.holders.length){res.innerHTML=(r.truncated?'<p class="m-lead">В проверенной части папки файлы никто не держит.</p>':'<p class="m-lead">Никто не держит этот путь открытым. Если удалить всё равно нельзя — дело в правах или атрибуте «только чтение».</p>')+note;return;}
      res.innerHTML=note+`<div class="m-list">${r.holders.map(h=>{const n=NODES.get(h.pid+':'+h.create_time); /* только точное совпадение: PID мог достаться другому процессу */
        return `<div class="m-row wh-h">${n?ico(n):'<span class="m-ico"></span>'}<span class="m-n">${esc(n?nameOf(n):h.app)}${h.service?` <span class="caption">· служба ${esc(h.service)}</span>`:''}</span><span class="caption num">${h.pid}</span>${n?`<button class="btn danger wh-k" data-id="${esc(n.id)}">Завершить</button>`:'<span></span>'}</div>`;}).join('')}</div>`;
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
   Детали процесса: службы внутри и сетевые подключения
   ================================================================= */
let DCONN={at:0,list:null,busy:false};
/* одинаковые сокеты (десяток UDP 5353 у браузера) — одной строкой с «×N» */
function dedupConns(list){
  const m=new Map();
  for(const c of list){const k=`${c.proto}|${c.local}|${c.local_port}|${c.remote}|${c.remote_port}|${c.state}|${c.pid}`;const x=m.get(k);if(x)x.n++;else m.set(k,{c,n:1});}
  return [...m.values()];
}
function detailExtras(n,secOpen){
  const svcs=SVC_BY_PID.get(n.pid)||[];
  /* сеть — всего приложения: у браузера соединения держит дочерний «сетевой» процесс, а не главный */
  if(Date.now()-DCONN.at>3000&&!DCONN.busy){DCONN.busy=true;
    rpc('connections').then(d=>{DCONN={at:Date.now(),list:d.connections,busy:false};renderDetails();}).catch(()=>{DCONN={at:Date.now(),list:DCONN.list,busy:false};});}
  const tree=appDesc(n),pids=new Set(tree.map(x=>x.pid));
  const conns=DCONN.list?DCONN.list.filter(c=>pids.has(c.pid)):[];
  let h='';
  if(svcs.length)h+=`<details class="dsec" data-s="svcs" ${secOpen('svcs')}><summary>${CHEV}Службы в процессе<span class="caption">${svcs.length}</span></summary>
    <div class="kids">${svcs.slice(0,20).map(s=>`<div class="kid2"><span>${esc(s.display)}</span><span class="caption">${esc(s.name)}</span></div>`).join('')}${svcs.length>20?`<div class="caption" style="padding:2px 8px">и ещё ${svcs.length-20}</div>`:''}</div></details>`;
  if(conns.length){
    const lis=dedupConns(conns.filter(c=>c.state==='listen'||c.proto==='udp')),est=dedupConns(conns.filter(c=>c.state!=='listen'&&c.proto==='tcp'&&c.pid!==0));
    const ne=est.reduce((a,x)=>a+x.n,0),nl=lis.length;
    const who=x=>tree.length>1&&x.c.pid!==n.pid?` <span class="caption">· ${x.c.pid}</span>`:'';
    const times=x=>x.n>1?` ×${x.n}`:'';
    h+=`<details class="dsec" data-s="net" ${secOpen('net')}><summary>${CHEV}Сеть${tree.length>1?' приложения':''}<span class="caption">${ne} ${plural(ne,'подключение','подключения','подключений')} · ${nl} ${plural(nl,'порт','порта','портов')}</span></summary><div class="kids">
      ${lis.slice(0,8).map(x=>`<div class="kid2"><span class="mono">${x.c.proto.toUpperCase()} ${esc(hostPort(x.c.local,x.c.local_port))}${who(x)}</span><span class="caption">${x.c.proto==='udp'?'открыт':'ожидает'}${times(x)}</span></div>`).join('')}
      ${est.slice(0,12).map(x=>`<div class="kid2"><span class="mono">→ ${esc(hostPort(x.c.remote,x.c.remote_port))}${who(x)}</span><span class="caption">${CONN_STATE[x.c.state]||x.c.state}${times(x)}</span></div>`).join('')}
      ${lis.length>8||est.length>12?'<div class="caption" style="padding:2px 8px">остальное — во вкладке «Сеть»</div>':''}</div></details>`;
  }
  return h;
}

/* =================================================================
   Правая панель: «Детали»
   ================================================================= */
const SEC={kids:true,info:true,svcs:true,net:true};
function renderDetails(){
  const body=$('#details');if(!S.right||!vis(body))return;
  const n=NODES.get(S.sel);
  if(!n||!SYS){body.innerHTML='<div class="empty">Выберите процесс в списке, на карте или на графике.</div>';body._id=null;return;}
  if(body._id===n.id&&selIn(body)){renderDetailChart();return;}
  body._id=n.id;
  const r=curRes(),dead=!n.alive,kids=aliveKids(n),iss=ISS.get(n.id)||[],f=n.full||{},i=INFO.get(n.id)||{};
  const secOpen=k=>SEC[k]?'open':'';
  const mm=r.m==='net'?'cpu':r.m,c=COLS.find(c=>c.m===mm);
  const kidsHTML=kids.slice().sort((a,b)=>cur(b,mm,true)-cur(a,mm,true)).slice(0,10).map(k=>`<div class="kid" data-go="${esc(k.id)}">${ico(k)}<span>${esc(nameOf(k))}${ISS.has(k.id)?` <span class="dot ${ISS.get(k.id).some(i=>i.lvl==='red')?'red':'yel'}"></span>`:''}</span><span class="v">${c.fmt(cur(k,mm,true))}</span><span class="v">${fmtMem(cur(k,'mem',true))}</span></div>`).join('');
  const started=ctToMs(n.ct);
  if(PSEUDO[n.pid]){
    /* не процесс: ни пути, ни времени запуска, ни действий — только объяснение и график */
    body.innerHTML=`<div class="dt-h">${ico(n,1)}<div style="min-width:0"><h3>${esc(nameOf(n))}</h3><div class="caption">нагрузка ядра Windows, не процесс</div></div></div>
     <div class="dchart"><div class="caption"><span class="d-cap"></span><span><span class="num d-now"></span><button class="ib d-max"></button></span></div><canvas class="d-cv"></canvas><div class="pop"></div></div>
     <p class="caption" style="padding:0 16px;line-height:1.5">${n.pid===4294967293
       ?'Время, которое процессоры тратят на обработку прерываний от устройств: сеть, диски, USB, звук. Больше 5–10 % долго — обычно драйвер устройства.'
       :'Отложенные вызовы процедур (DPC): вторая половина обработки прерываний, работа драйверов. Постоянно высокая доля — признак проблемного драйвера (часто сеть, звук или видеокарта).'}
     Как и в System Informer, эта нагрузка показана отдельной строкой, а не приписана процессу «System».</p>`;
    renderDetailChart();return;
  }
  body.innerHTML=`
   <div class="dt-h">${ico(n,1)}<div style="min-width:0"><h3>${esc(nameOf(n))}</h3><div class="caption">${esc(n.exe)} · PID ${n.pid}${i.company?' · '+esc(i.company):''}</div></div></div>
   ${dead?`<div class="dead-note">Процесс завершён ${agoStr((NOW-n.deadAt)/1000)} назад.</div>`:''}
   ${iss.map(x=>`<div class="issue ${x.lvl}"><span class="dot ${x.lvl}"></span><span>${esc(x.txt)}</span></div>`).join('')}
   ${dead?'':`<div class="acts">
     <button class="btn danger" data-a="kill">Завершить</button>
     ${kids.length?`<button class="btn" data-a="tree">С дочерними (${desc(n).length})</button>`:''}
     <button class="btn" data-a="suspend">${n.susp?'Возобновить':'Приостановить'}</button>
     <button class="btn subtle" data-a="open" title="Открыть историю процесса отдельной вкладкой">Открыть отдельно</button>
     <button class="btn subtle" data-a="more" title="Все действия">Ещё…</button></div>`}
   ${ancestors(n).length?`<div class="crumbs"><span class="caption" style="margin-right:4px">Кто запустил:</span>${ancestors(n).map(a=>`<a data-go="${esc(a.id)}">${esc(nameOf(a))}</a>`).join('<span class="sep">›</span>')}</div>`:''}
   <div class="dchart"><div class="caption"><span class="d-cap"></span><span><span class="num d-now"></span><button class="ib d-max"></button></span></div><canvas class="d-cv"></canvas><div class="pop"></div></div>
   ${kids.length?`<details class="dsec" data-s="kids" ${secOpen('kids')}><summary>${CHEV}Дочерние процессы<span class="caption">${kids.length}</span></summary><div class="kids">${kidsHTML}${kids.length>10?`<div class="caption" style="padding:2px 8px">и ещё ${kids.length-10}</div>`:''}</div></details>`:''}
   ${dead?'':detailExtras(n,secOpen)}
   <details class="dsec" data-s="info" ${secOpen('info')}><summary>${CHEV}Сведения</summary>
   <dl class="kv">
     <dt>PID</dt><dd class="num">${n.pid}</dd>
     <dt>Запущен</dt><dd>${agoStr(Math.max(0,NOW-started)/1000)} назад · ${new Date(started).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}</dd>
     ${i.description?`<dt>Описание</dt><dd>${esc(i.description)}</dd>`:''}
     <dt>Путь</dt><dd class="mono">${i.path?esc(i.path):`нет доступа — нужны права администратора.${isAdmin()?'':ADMIN_LINK}`}</dd>
     ${f.cmdline?`<dt>Командная строка</dt><dd class="mono">${esc(f.cmdline)}</dd>`:''}
     ${i.company?`<dt>Издатель</dt><dd>${esc(i.company)} <span class="caption">(из свойств файла)</span></dd>`:''}
     <dt>ЦП всего</dt><dd>${agoStr(n.cpuMs/1000)}</dd>
     <dt>Память</dt><dd>${fmtMem(n.mem)} частная · ${fmtMem(n.ws)} рабочий набор · ${fmtMem(n.priv)} выделено</dd>
     ${NETPP?`<dt>Сеть</dt><dd>↓ ${fmtMbit(n.nrx)} · ↑ ${fmtMbit(n.ntx)}</dd>`:''}
     ${n.gpu>=.05||n.gmem>=1?`<dt>Видеокарта</dt><dd>${fmtPct(n.gpu)} · видеопамять ${fmtMem(n.gmem)}</dd>`:''}
     <dt>Потоки</dt><dd class="num">${n.threads}</dd><dt>Дескрипторы</dt><dd class="num">${n.handles.toLocaleString('ru')}</dd>
     <dt>Сеанс</dt><dd class="num">${n.session}${n.session===0?' (службы)':''}</dd>
     <dt>Приоритет</dt><dd>${PRIO_NAMES[n.prio]||'—'}</dd>
     ${appOf(n)?`<dt>Приложение</dt><dd>${esc(appOf(n).title)} · процессов: ${appOf(n).count}</dd>`:''}
   </dl></details>`;
  renderDetailChart();
}
function renderDetailChart(){
  const body=$('#details');if(!S.right||!vis(body))return;
  const cv=$('.d-cv',body),n=NODES.get(S.sel);if(!cv||!n)return;
  maxMark(cv.parentElement,'max',S.max==='detail',$('.d-max',body));
  const r=curRes(),mm=r.m==='net'?'cpu':r.m,c=COLS.find(c=>c.m===mm);
  $('.d-now',body).textContent=c.fmt(cur(n,mm,true));
  const s=nodeSeries(n,mm);
  $('.d-cap',body).textContent=`${c.t}${s&&s.caption?' · '+s.caption:''} · ${S.range.label}`;
  if(!s){drawTS(cv,{series:[],t0:NOW,step:1000,fmt:c.fmt,empty:'Загружаю историю…'});return;}
  drawTS(cv,{series:[{name:c.t,color:PAL[r.m==='net'?0:r.col],data:s.data}],t0:s.t0,step:s.step,missing:s.missing,fmt:c.fmt,fill:true});
}
$('#details').addEventListener('click',e=>{
  if(e.target.closest('.d-max')){setMax('detail');return;}
  const a=e.target.closest('[data-a]');
  if(a){if(a.dataset.a==='more'){const r=a.getBoundingClientRect();openMenu(r.left,r.bottom+4,[S.sel]);}else if(a.dataset.a==='open')openProcTab(S.sel);else act(a.dataset.a,[S.sel]);return;}
  const j=e.target.closest('[data-go]');if(j)select(j.dataset.go,true);
});
$('#details').addEventListener('toggle',e=>{const d=e.target.closest('.dsec');if(d)SEC[d.dataset.s]=d.open;},true);
$('#details').addEventListener('dblclick',e=>{if(e.target.closest('.d-cv'))setMax('detail');});
$('#details').addEventListener('mousemove',e=>{const cv=e.target.closest('canvas');if(cv)chartHover(cv,cv.nextElementSibling,e);});
$('#details').addEventListener('mouseout',e=>{if(e.target.tagName==='CANVAS'){S.hoverT=null;e.target.nextElementSibling.style.display='none';renderCharts();}});

/* =================================================================
   Каркас: главная зона на dockview + нижняя и правая панели
   ================================================================= */
const DV=window['dockview-core'];
/* основные вкладки не закрываются — только переключаются и перетаскиваются;
   крестик есть лишь у вкладок отдельных процессов */
const FIXED=['procs','map','docker','pool','svcs','conns'];
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
    else if(o.name==='docker'){PANEL_EL.docker=el;mountDocker(el);}
    else if(o.name==='pool'){PANEL_EL.pool=el;mountPool(el);}
    else if(o.name==='svcs'){PANEL_EL.svcs=el;mountSvcs(el);}
    else if(o.name==='conns'){PANEL_EL.conns=el;mountConns(el);}
    else if(o.name==='proc'){mountProcTab(el,String(o.id).slice(5));}
    new ResizeObserver(()=>{if(!DRAGGING&&vis(el)){renderAll();flushNeeds();}}).observe(el);
    return {element:el,init(){},dispose(){if(o.name==='proc')PROC_TABS.delete(String(o.id).slice(5));}};
  },
  /* плавающие окна выключены: оторванную основную вкладку нельзя было закрыть */
  disableFloatingGroups:true,
});
const dockEl=$('#dock');
const relayout=()=>{if(dockEl.clientWidth)dock.layout(dockEl.clientWidth,dockEl.clientHeight);};
new ResizeObserver(relayout).observe(dockEl);
relayout();
function defaultLayout(){
  dock.clear();
  dock.addPanel({id:'procs',component:'procs',tabComponent:'fixed',title:'Процессы'});
  dock.addPanel({id:'map',component:'map',tabComponent:'fixed',title:'Карта',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'docker',component:'docker',tabComponent:'fixed',title:'Docker',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'pool',component:'pool',tabComponent:'fixed',title:'Пул ядра',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'svcs',component:'svcs',tabComponent:'fixed',title:'Службы',position:{referencePanel:'procs',direction:'within'},inactive:true});
  dock.addPanel({id:'conns',component:'conns',tabComponent:'fixed',title:'Сеть',position:{referencePanel:'procs',direction:'within'},inactive:true});
}
const LAYOUT_KEY='tm-layout-3';
let restored=false;
try{const j=localStorage.getItem(LAYOUT_KEY);if(j){const L=JSON.parse(j);delete L.floatingGroups;delete L.popoutGroups;for(const k of FIXED)if(L.panels&&L.panels[k])L.panels[k].tabComponent='fixed';dock.fromJSON(L);for(const p of dock.panels.slice())if(p.id.startsWith('proc:'))p.api.close();restored=!!dock.getPanel('procs')||!!dock.getPanel('map');}}catch(e){restored=false;}
if(!restored)defaultLayout();
/* основная вкладка могла остаться в выкинутом плавающем окне — возвращаем её в общую группу */
function ensureFixed(){const ref=FIXED.map(k=>dock.getPanel(k)).find(Boolean);
  for(const [k,t] of [['procs','Процессы'],['map','Карта'],['docker','Docker'],['pool','Пул ядра'],['svcs','Службы'],['conns','Сеть']])if(!dock.getPanel(k))dock.addPanel({id:k,component:k,tabComponent:'fixed',title:t,inactive:!!ref,...(ref?{position:{referencePanel:ref.id,direction:'within'}}:{})});}
ensureFixed();
/* сохранённая раскладка помнит старые названия вкладок */
{const c=dock.getPanel('conns');if(c&&c.title!=='Сеть')c.api.setTitle('Сеть');}
dock.onDidLayoutChange(()=>{try{localStorage.setItem(LAYOUT_KEY,JSON.stringify(dock.toJSON()));}catch(e){}});
dock.onDidActivePanelChange(()=>requestAnimationFrame(()=>{renderAll();flushNeeds();}));

/* размеры — прямо на панели: наследуемая CSS-переменная на #shell заставляла пересчитывать стили всех элементов */
function sizeZones(){$('#bottom').style.height=S.bh+'px';$('#right').style.width=S.rw+'px';}
function applyShell(){
  const sh=$('#shell');
  sh.classList.toggle('no-rail',!S.rail);sh.classList.toggle('no-main',!S.main);sh.classList.toggle('no-bottom',!S.bottom);sh.classList.toggle('no-right',!S.right);
  sizeZones();
  $('#tglRail').classList.toggle('on',S.rail);$('#tglMain').classList.toggle('on',S.main);$('#tglBottom').classList.toggle('on',S.bottom);$('#tglRight').classList.toggle('on',S.right);
  $('#btabs').querySelectorAll('[data-t]').forEach(b=>b.classList.toggle('on',b.dataset.t===S.btab));
  $('#bChart').hidden=S.btab!=='chart';$('#bLog').hidden=S.btab!=='log';
  requestAnimationFrame(()=>{relayout();renderAll();flushNeeds();});
}
const toggleBottom=v=>{S.bottom=v==null?!S.bottom:v;if(!S.bottom)S.main=true;if(!S.bottom&&S.max==='bottom'){S.max=null;maxMark($('#shell'),'max-bottom',false,$('#maxBottom'));}saveUI();applyShell();};
/* центр не бывает пустым: спрятали вкладки — показываем нижнюю панель, и наоборот */
const toggleMain=v=>{S.main=v==null?!S.main:v;if(!S.main){S.bottom=true;if(S.max==='bottom'){S.max=null;maxMark($('#shell'),'max-bottom',false,$('#maxBottom'));}}saveUI();applyShell();};
const toggleRail=v=>{S.rail=v==null?!S.rail:v;saveUI();applyShell();};
const toggleRight=v=>{S.right=v==null?!S.right:v;saveUI();applyShell();};
$('#tglRail').addEventListener('click',()=>toggleRail());$('#tglMain').addEventListener('click',()=>toggleMain());
$('#tglBottom').addEventListener('click',()=>toggleBottom());
$('#maxBottom').addEventListener('click',()=>setMax('bottom'));maxMark($('#shell'),'max-bottom',false,$('#maxBottom'));
$('#tglRight').addEventListener('click',()=>toggleRight());
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.dataset.close==='bottom'?toggleBottom(false):toggleRight(false)));
function sash(id,apply){
  const s=$(id);let start,base;
  let raf=0;
  s.addEventListener('pointerdown',e=>{if(e.button!==0)return;e.preventDefault();s.setPointerCapture(e.pointerId);s.classList.add('drag');start={x:e.clientX,y:e.clientY};base={bh:S.bh,rw:S.rw};DRAGGING=true;});
  /* размер меняется сразу на каждое движение (это ~2 мс), а графики перерисовываются раз в кадр —
     иначе растянутые холсты дёргались; запросы данных — только после отпускания */
  const move=e=>{apply(e.clientX-start.x,e.clientY-start.y,base);sizeZones();relayout();
    if(!raf)raf=requestAnimationFrame(()=>{raf=0;renderAll();});};
  s.addEventListener('pointermove',e=>{if(start)move(e);});
  const end=e=>{if(!start)return;if(e&&e.type==='pointerup')move(e);start=null;DRAGGING=false;s.classList.remove('drag');
    if(s.hasPointerCapture&&e&&s.hasPointerCapture(e.pointerId))s.releasePointerCapture(e.pointerId);saveUI();renderAll();flushNeeds();};
  s.addEventListener('pointerup',end);s.addEventListener('pointercancel',end);s.addEventListener('lostpointercapture',end);
}
sash('#sashB',(dx,dy,b)=>{S.bh=clamp(b.bh-dy,160,Math.max(160,innerHeight-260));});
sash('#sashR',(dx,dy,b)=>{S.rw=clamp(b.rw-dx,280,Math.max(280,Math.min(640,innerWidth-700)));});

/* верхняя строка */
function renderTop(){
  $('#range').innerHTML=RANGES.map(r=>`<button data-k="${r.key}" class="${S.range===r?'on':''}">${r.label}</button>`).join('');
  const all=[...ISS.entries()].map(([id,i])=>({n:NODES.get(id),lvl:i.some(z=>z.lvl==='red')?'red':'yel'})).filter(x=>alive(x.n));
  const red=all.filter(x=>x.lvl==='red').length,yel=all.length-red;
  $('#issues').innerHTML=all.length?`${red?`<span class="dot red"></span>${red} ${red===1?'проблема':'проблемы'}`:''}${yel?`<span class="dot yel" style="margin-left:${red?8:0}px"></span>${yel} ${yel===1?'предупреждение':'предупреждения'}`:''}`:'<span class="dot" style="background:var(--success)"></span>Всё спокойно';
  $('#issues')._list=all;
  $('#host').innerHTML=SYSINFO?(SYSINFO.elevated?'<span class="chip adm">администратор</span>':'')+(TAURI?'':' <span class="chip">режим разработки</span>'):'';
}
$('#range').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;S.range=RANGES.find(r=>r.key===b.dataset.k);try{localStorage.setItem('tm-range',S.range.key);}catch(x){}renderAll();renderMap(true);flushNeeds();});
let issIdx=0;
$('#issues').addEventListener('click',()=>{const l=$('#issues')._list||[];if(!l.length)return;const s=l.slice().sort((a,b)=>(a.lvl==='red'?0:1)-(b.lvl==='red'?0:1));select(s[issIdx++%s.length].n.id,true);});
let paused=false,autostart=null;
$('#moreBtn').addEventListener('click',async e=>{
  const r=e.currentTarget.getBoundingClientRect();menuIds=null;
  if(TAURI&&autostart===null){try{autostart=await appCmd('autostart_get');}catch(x){}}
  menu.innerHTML=`<div class="mi" data-g="pause"><span>${paused?'Продолжить обновление':'Пауза обновления'}</span></div>
    <div class="mi" data-g="reset"><span>Сбросить раскладку</span></div>
    <div class="sep"></div><div class="mh">Панели</div>
    <div class="mi" data-g="rail"><span><span class="ck">${S.rail?'✓':''}</span> Ресурсы и графики (слева)</span><kbd>Ctrl+B</kbd></div>
    <div class="mi" data-g="main"><span><span class="ck">${S.main?'✓':''}</span> Вкладки: процессы, карта… (центр)</span></div>
    <div class="mi" data-g="bottom"><span><span class="ck">${S.bottom?'✓':''}</span> График и журнал (снизу)</span><kbd>Ctrl+J</kbd></div>
    <div class="mi" data-g="right"><span><span class="ck">${S.right?'✓':''}</span> Детали (справа)</span><kbd>Ctrl+Alt+B</kbd></div><div class="sep"></div>
    ${SYSINFO&&SYSINFO.elevated?'':'<div class="mi" data-g="admin"><span>Перезапустить от администратора</span></div>'}
    ${TAURI?`<div class="mi" data-g="autostart"><span>${autostart?'✓ ':''}Запускать вместе с Windows</span></div><div class="mi" data-g="hide"><span>Свернуть в трей</span><kbd>Esc</kbd></div><div class="sep"></div><div class="mi danger" data-g="quit"><span>Выйти (сбор истории остановится)</span></div>`:''}`;
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
    else if(g==='autostart'){autostart=await appCmd('autostart_set',!autostart);toast(autostart?'Диспетчер будет запускаться вместе с Windows (в трее)':'Автозапуск выключен','info');}
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
  if(e.key==='Delete'&&S.sel)act(e.shiftKey?'tree':'kill',[...(S.multi.size?S.multi:[S.sel])]);
  if(e.key==='Escape'){if(menu.style.display==='block')closeMenu();else if(S.max)setMax(S.max);else if(mapUp()){}else if(TAURI)appCmd('hide').catch(()=>{});}
});

function renderAll(){if(!SYS)return;RES=resList();renderTop();renderRail();renderChart();renderLog();renderProcs();renderMap();renderDocker();renderPool();renderSvcs();renderConns();fetchSvcNames();renderDetails();renderProcTabs();}

/* =================================================================
   Главный цикл: ждём следующий замер движка (длинный опрос).
   Пока окно скрыто (свёрнуто в трей) — не опрашиваем и не рисуем.
   ================================================================= */
let BOOTING=true;
async function backfill(){
  /* после показа окна: дозаполнить мини-графики за время, пока окно было скрыто */
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
