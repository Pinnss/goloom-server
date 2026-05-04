package admin

import (
	"fmt"
	"net/http"
)

const dashboardCSS = `
:root{--bg:#0e1014;--panel:#161a22;--panel2:#1d2230;--text:#e6e8ee;--muted:#888;--accent:#3a8;--danger:#e55}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:20px;font-size:14px}
h1{font-size:18px;margin:0 0 16px;display:flex;align-items:center;gap:12px}
h1 .badge{font-size:11px;background:var(--accent);color:#fff;padding:2px 8px;border-radius:10px;font-weight:normal}
.bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
button,input,textarea{font-family:inherit;font-size:13px;border:1px solid #333;background:var(--panel);color:var(--text);padding:8px 12px;border-radius:4px}
input,textarea{width:100%}
button{cursor:pointer;background:var(--accent);color:#fff;border:0}
button.danger{background:var(--danger)}
button.ghost{background:transparent;border:1px solid #333;color:var(--muted)}
button:hover{filter:brightness(1.1)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px}
.card{background:var(--panel);border-radius:8px;padding:16px;border:1px solid #232938}
.card h2{font-size:15px;margin:0 0 8px;display:flex;justify-content:space-between;align-items:center}
.card .tag{font-family:monospace;font-size:12px;background:var(--panel2);padding:2px 8px;border-radius:4px}
.row{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin:4px 0}
.row b{color:var(--text);font-weight:normal;font-family:monospace}
.phase{padding:2px 8px;border-radius:10px;font-size:11px;text-transform:uppercase}
.phase.relaying{background:#0a4;color:#fff}
.phase.handshaking,.phase.waiting_peer,.phase.starting{background:#a80;color:#fff}
.phase.waiting_for_client{background:#268;color:#fff}
.phase.error{background:var(--danger);color:#fff}
.phase.stopped{background:#444;color:#fff}
.actions{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
.qr{margin:10px 0;text-align:center}
.qr img{max-width:200px;background:#fff;padding:6px;border-radius:4px}
details{margin-top:8px}
summary{cursor:pointer;color:var(--muted);font-size:12px}
pre{background:#000;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;max-height:120px}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);align-items:center;justify-content:center;z-index:10}
.modal.open{display:flex}
.modal .body{background:var(--panel);padding:20px;border-radius:8px;min-width:400px;max-width:90vw}
.field{margin:10px 0}
.field label{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}
.empty{text-align:center;color:var(--muted);padding:40px}
.banner{background:#3a1f1f;border:1px solid #7a3838;color:#ffd2c4;padding:10px 14px;border-radius:6px;margin-bottom:16px;display:flex;align-items:center;gap:12px}
.banner.hidden{display:none}
.banner b{color:#fff}
.account{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted)}
.account .user{font-family:monospace;color:var(--text)}
`

const dashboardHTML = `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>goloom admin</title>
<link rel="stylesheet" href="/static/style.css">
</head><body>
<h1>goloom <span class="badge">admin</span>
  <span style="flex:1"></span>
  <span class="account"><span class="user" id="curUser">…</span>
    <button class="ghost" onclick="openAccount()">⚙ Аккаунт</button>
    <button class="ghost" onclick="logout()">Выйти</button>
  </span>
</h1>

<div id="defaultPwBanner" class="banner hidden">
  ⚠ <span>Используется временный пароль по умолчанию. <b>Смените его сейчас</b>, чтобы никто посторонний не получил доступ к панели.</span>
  <span style="flex:1"></span>
  <button onclick="openAccount()">Сменить пароль</button>
</div>

<div class="bar">
  <button onclick="openModal()">+ Создать inbound</button>
  <button class="ghost" onclick="refresh()">Обновить</button>
</div>
<div id="cards" class="cards"></div>

<details style="margin-top:24px">
  <summary>WG-интерфейсы на сервере</summary>
  <div id="wgList" style="margin-top:8px"></div>
</details>

<div id="accountModal" class="modal"><div class="body">
<h2>Сменить пароль</h2>
<div class="field"><label>Текущий пароль</label><input id="pwCurrent" type="password" autocomplete="current-password"></div>
<div class="field"><label>Новый пароль (минимум 8 символов)</label><input id="pwNew" type="password" autocomplete="new-password"></div>
<div class="field"><label>Подтверждение нового пароля</label><input id="pwConfirm" type="password" autocomplete="new-password"></div>
<div id="pwErr" style="color:var(--danger);font-size:12px;min-height:16px"></div>
<div class="actions">
<button onclick="changePassword()">Сменить</button>
<button class="ghost" onclick="closeAccount()">Отмена</button>
</div>
</div></div>

<div id="modal" class="modal"><div class="body">
<h2>Новый inbound</h2>
<div class="field"><label>Tag (короткое имя)</label><input id="tag" placeholder="personal"></div>
<div class="field"><label>Meeting URL</label><input id="meeting" placeholder="https://telemost.yandex.ru/j/..."></div>
<div class="field"><label>Display name (пусто = случайное)</label><input id="displayName"></div>
<div class="field"><label><input type="checkbox" id="autoProvision" checked> Создать новый WG-интерфейс автоматически</label></div>
<div class="field" id="endpointField" style="display:none"><label>WG endpoint (если без авто-провижна)</label><input id="wgEndpoint" value="127.0.0.1:51820"></div>
<div class="actions">
<button onclick="createInbound()">Создать</button>
<button class="ghost" onclick="closeModal()">Отмена</button>
</div>
</div></div>

<script>
// Auth теперь cookie-based; fetch автоматически шлёт session cookie.
function authHeaders(){return {"Content-Type":"application/json"}}
function on401(r){if(r.status===401){location="/login";return true}return false}
async function refresh(){
  var r=await fetch("/api/inbounds",{headers:authHeaders()});
  if(on401(r))return;
  var list=await r.json();
  var el=document.getElementById("cards");
  if(!list||!list.length){el.innerHTML='<div class="empty">Пока пусто. Жми <b>+ Создать inbound</b> сверху.</div>';return}
  el.innerHTML=list.map(renderCard).join("");
}
function renderCard(s){
  var bytes=function(n){if(!n)return "0 B";var k=1024;if(n<k)return n+" B";if(n<k*k)return (n/k).toFixed(1)+" KB";if(n<k*k*k)return (n/k/k).toFixed(1)+" MB";return (n/k/k/k).toFixed(2)+" GB"};
  var qr='/api/inbounds/'+s.id+'/qr.png';
  return '<div class="card">'+
    '<h2><span>'+escapeHtml(s.tag)+'</span><span class="phase '+s.phase+'">'+s.phase+'</span></h2>'+
    '<div class="row"><span>Meeting</span><b style="word-break:break-all;text-align:right">'+escapeHtml(short(s.meeting))+'</b></div>'+
    '<div class="row"><span>WG endpoint</span><b>'+escapeHtml(s.wg_endpoint)+'</b></div>'+
    (s.wg_iface?'<div class="row"><span>WG iface</span><b>'+escapeHtml(s.wg_iface)+'</b></div>':'')+
    '<div class="row"><span>↑ TX</span><b>'+s.tx_packets+' / '+bytes(s.tx_bytes)+'</b></div>'+
    '<div class="row"><span>↓ RX</span><b>'+s.rx_packets+' / '+bytes(s.rx_bytes)+'</b></div>'+
    (s.last_error?'<div class="row"><span>error</span><b style="color:#e55">'+escapeHtml(s.last_error)+'</b></div>':'')+
    '<svg class="spark" data-id="'+s.id+'" viewBox="0 0 240 40" preserveAspectRatio="none" style="width:100%;height:40px;background:#0a0c10;border-radius:4px;margin:6px 0"></svg>'+
    '<div class="qr"><img src="'+qr+'"></div>'+
    '<div class="actions">'+
      '<button data-id="'+s.id+'" data-act="copy">📋 connection</button>'+
      '<button class="ghost" data-id="'+s.id+'" data-act="conf">⬇ wg.conf</button>'+
      '<button class="ghost" data-id="'+s.id+'" data-act="toggle">'+(s.enabled?'⏸':'▶')+'</button>'+
      '<button class="danger" data-id="'+s.id+'" data-act="delete">✕ delete</button>'+
    '</div>'+
  '</div>';
}
function short(u){return u.length>50?u.slice(0,47)+'...':u}
function escapeHtml(s){return (s||'').replace(/[&<>"']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]})}
function openModal(){document.getElementById("modal").classList.add("open")}
function closeModal(){document.getElementById("modal").classList.remove("open")}
function openAccount(){
  document.getElementById("accountModal").classList.add("open");
  document.getElementById("pwErr").textContent="";
  document.getElementById("pwCurrent").value="";
  document.getElementById("pwNew").value="";
  document.getElementById("pwConfirm").value="";
}
function closeAccount(){document.getElementById("accountModal").classList.remove("open")}
async function logout(){await fetch("/logout",{method:"POST"});location="/login"}
async function changePassword(){
  var err=document.getElementById("pwErr");err.textContent="";
  var cur=document.getElementById("pwCurrent").value;
  var nw=document.getElementById("pwNew").value;
  var cf=document.getElementById("pwConfirm").value;
  if(nw.length<8){err.textContent="Новый пароль слишком короткий (8+ символов)";return}
  if(nw!==cf){err.textContent="Пароли не совпадают";return}
  var r=await fetch("/api/admin/password",{method:"POST",headers:authHeaders(),
    body:JSON.stringify({current:cur,new:nw})});
  if(r.ok){closeAccount();refreshAdmin();alert("Пароль обновлён");return}
  err.textContent=await r.text();
}
async function refreshAdmin(){
  var r=await fetch("/api/admin/state",{headers:authHeaders()});
  if(on401(r))return;
  var st=await r.json();
  document.getElementById("curUser").textContent=st.username||"";
  document.getElementById("defaultPwBanner").classList.toggle("hidden",!st.is_default_password);
}
document.getElementById("autoProvision").addEventListener("change",function(e){
  document.getElementById("endpointField").style.display=e.target.checked?"none":"block";
});
async function createInbound(){
  var body={
    tag:document.getElementById("tag").value,
    meeting:document.getElementById("meeting").value,
    display_name:document.getElementById("displayName").value,
    auto_provision:document.getElementById("autoProvision").checked,
    wg_endpoint:document.getElementById("wgEndpoint").value,
  };
  var r=await fetch("/api/inbounds",{method:"POST",headers:authHeaders(),body:JSON.stringify(body)});
  if(!r.ok){alert("Ошибка: "+await r.text());return}
  closeModal();refresh();
}
async function deleteInbound(id){
  if(!confirm("Удалить inbound?"))return;
  await fetch("/api/inbounds/"+id,{method:"DELETE",headers:authHeaders()});
  refresh();
}
async function toggleInbound(id){
  await fetch("/api/inbounds/"+id+"/toggle",{method:"POST",headers:authHeaders()});
  refresh();
}
async function copyConn(id){
  var r=await fetch("/api/inbounds/"+id+"/connstr",{headers:authHeaders()});
  var s=await r.text();
  try{await navigator.clipboard.writeText(s)}catch(e){}
  alert("Connection string:\n\n"+s);
}
function downloadConf(id){
  location="/api/inbounds/"+id+"/client.conf";
}
document.addEventListener("click",function(e){
  var b=e.target.closest("button[data-act]");
  if(!b)return;
  var id=b.dataset.id, act=b.dataset.act;
  if(act==="copy")copyConn(id);
  else if(act==="conf")downloadConf(id);
  else if(act==="toggle")toggleInbound(id);
  else if(act==="delete")deleteInbound(id);
});
// Pull history for each visible card and render TX (orange) + RX (green)
// rate sparklines. Rate = byte delta per second, normalised to the
// max within the window so visual amplitude stays readable when the
// connection is mostly idle vs hammering.
async function refreshSparks(){
  var svgs=document.querySelectorAll("svg.spark");
  for(var i=0;i<svgs.length;i++){
    var svg=svgs[i], id=svg.dataset.id;
    try{
      var r=await fetch("/api/inbounds/"+id+"/history",{headers:authHeaders()});
      if(!r.ok)continue;
      var data=await r.json();
      if(!data||data.length<2){svg.innerHTML="";continue}
      var W=240,H=40;
      var txRates=[], rxRates=[], maxRate=1;
      for(var j=1;j<data.length;j++){
        var dt=Math.max(1,data[j].t-data[j-1].t);
        var tx=Math.max(0,(data[j].tx-data[j-1].tx)/dt);
        var rx=Math.max(0,(data[j].rx-data[j-1].rx)/dt);
        txRates.push(tx);rxRates.push(rx);
        if(tx>maxRate)maxRate=tx;
        if(rx>maxRate)maxRate=rx;
      }
      var n=txRates.length;
      var pathFor=function(arr){
        return arr.map(function(v,k){var x=k*W/(n-1||1);var y=H-(v/maxRate)*(H-2)-1;return (k===0?"M":"L")+x.toFixed(1)+" "+y.toFixed(1)}).join(" ");
      };
      svg.innerHTML='<path d="'+pathFor(rxRates)+'" stroke="#3a8" stroke-width="1.2" fill="none"/>'+
                    '<path d="'+pathFor(txRates)+'" stroke="#e90" stroke-width="1.2" fill="none"/>';
    }catch(e){}
  }
}

async function refreshWG(){
  var r=await fetch("/api/system/wg-interfaces",{headers:authHeaders()});
  if(!r.ok)return;
  var list=await r.json();
  var el=document.getElementById("wgList");
  if(!list||!list.length){el.innerHTML='<div class="row"><span style="color:var(--muted)">Нет активных wg-интерфейсов</span></div>';return}
  el.innerHTML='<table style="width:100%;border-collapse:collapse;font-size:12px">'+
    '<tr style="color:var(--muted);border-bottom:1px solid #222"><th style="text-align:left;padding:4px">iface</th><th style="text-align:left">port</th><th style="text-align:left">peers</th><th style="text-align:left">статус</th></tr>'+
    list.map(function(w){
      var status=w.managed?'<span style="color:var(--accent)">managed: '+escapeHtml(w.inbound_tag)+'</span>':'<span style="color:#a80">unmanaged</span>';
      return '<tr style="border-bottom:1px solid #1a1a1a"><td style="padding:4px"><code>'+escapeHtml(w.name)+'</code></td><td>'+w.listen_port+'</td><td>'+w.num_peers+'</td><td>'+status+'</td></tr>';
    }).join('')+'</table>';
}

refreshAdmin();
refresh();
refreshWG();
refreshSparks();
setInterval(function(){refresh();refreshWG();refreshAdmin();},5000);
setInterval(refreshSparks,2000);
</script>
</body></html>`

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Header().Set("Cache-Control", "max-age=3600")
	fmt.Fprint(w, dashboardCSS)
}
