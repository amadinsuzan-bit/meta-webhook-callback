let dashboardPassword = "";
let cachedEvents = [];
const $ = id => document.getElementById(id);
function baseUrl(){return window.location.origin}
$("webhookUrl").textContent = baseUrl()+"/webhook";
$("callbackUrl").textContent = baseUrl()+"/callback";
document.querySelectorAll("[data-copy]").forEach(btn=>btn.addEventListener("click",async()=>{
 const value=btn.dataset.copy==="webhook"?baseUrl()+"/webhook":baseUrl()+"/callback";
 try{await navigator.clipboard.writeText(value);btn.textContent="Copied!";setTimeout(()=>btn.textContent="Copy URL",1300)}catch{prompt("Copy this URL",value)}
}));
async function api(url, options={}) {
 const res=await fetch(url,{...options,headers:{...(options.headers||{}),"x-dashboard-password":dashboardPassword}});
 const data=await res.json().catch(()=>({}));
 if(!res.ok) throw new Error(data.error||"Request failed");
 return data;
}
$("loginBtn").addEventListener("click",login);
$("password").addEventListener("keydown",e=>{if(e.key==="Enter")login()});
async function login(){
 dashboardPassword=$("password").value;
 try{await api("/api/stats");$("loginPanel").hidden=true;$("dashboard").hidden=false;$("loginError").textContent="";await refresh()}
 catch(e){$("loginError").textContent=e.message;dashboardPassword=""}
}
async function refresh(){
 try{
  const [stats,events]=await Promise.all([api("/api/stats"),api("/api/events?limit=200")]);
  $("total").textContent=stats.total;$("today").textContent=stats.today;$("rejected").textContent=stats.rejected;
  cachedEvents=events;renderEvents(events);await loadTokenStatus();
 }catch(e){$("loginError").textContent=e.message}
}
function renderEvents(events){
 const body=$("eventRows");
 if(!events.length){body.innerHTML='<tr><td colspan="6" class="empty">No events received yet. Send a test event to /webhook or /callback.</td></tr>';return}
 body.innerHTML=events.map((e,i)=>`<tr><td>${escapeHtml(e.event_type||"unknown")}</td><td>${escapeHtml(e.source)}</td><td>${new Date(e.received_at).toLocaleString()}</td><td><span class="pill ${e.signature_valid===0?"bad":""}">${e.signature_valid===null?"N/A":e.signature_valid?"VALID":"INVALID"}</span></td><td>${escapeHtml(e.status)}</td><td><button class="eventbtn" data-index="${i}">Inspect â</button></td></tr>`).join("");
 body.querySelectorAll("[data-index]").forEach(b=>b.addEventListener("click",()=>showEvent(Number(b.dataset.index))));
}
function showEvent(i){const e=cachedEvents[i];$("payload").textContent=JSON.stringify({id:e.id,source:e.source,event_type:e.event_type,received_at:e.received_at,headers:e.headers,signature_valid:e.signature_valid,status:e.status,note:e.note,payload:e.payload},null,2);$("detail").scrollIntoView({behavior:"smooth",block:"start"})}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
$("refreshBtn").addEventListener("click",refresh);
$("clearBtn").addEventListener("click",async()=>{if(!confirm("Permanently clear all stored event logs?"))return;try{await api("/api/events",{method:"DELETE"});$("payload").textContent="{ }";await refresh()}catch(e){alert(e.message)}});

async function loadTokenStatus(){
 try{
  const s=await api("/api/token/status");
  $("tokenStatus").textContent=s.connected?`Connected Â· ${s.token_type||"bearer"} Â· expires ${s.expires_at?new Date(s.expires_at).toLocaleString():"not provided"}`:"No Meta account connected yet.";
 }catch(e){$("tokenStatus").textContent=e.message}
}
let savedToken="";
$("revealTokenBtn").addEventListener("click",async()=>{
 try{
  const result=await api("/api/token/reveal",{method:"POST"});savedToken=result.access_token;
  $("tokenOutput").hidden=false;$("tokenOutput").textContent=savedToken;
  $("copyTokenBtn").hidden=false;
 }catch(e){alert(e.message)}
});
$("copyTokenBtn").addEventListener("click",async()=>{
 try{await navigator.clipboard.writeText(savedToken);$("copyTokenBtn").textContent="Copied";setTimeout(()=>$("copyTokenBtn").textContent="Copy token",1400)}catch{prompt("Copy your long-lived token",savedToken)}
});
const params=new URLSearchParams(location.search);
if(params.get("facebook_connected")==="1") { history.replaceState({},"",location.pathname); alert("Facebook connected. Your long-lived token has been encrypted and saved."); }
