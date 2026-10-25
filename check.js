
'use strict';const $=id=>document.getElementById(id),v=id=>$(id).value,s=(id,x)=>$(id).value=x??'',key='officina_manager_v1';let db={appointments:[],jobs:[],clients:[]};let cryptoKey=null, unlocked=false;
const secureKey=key+'_encrypted';

// Accesso automatico: salva la CryptoKey non esportabile solo nell'IndexedDB di questo sito/dispositivo.
// Non memorizza la password. La chiave è utilizzabile da chi ha accesso a questo profilo browser.
const AUTO_DB='otm_auto_unlock_v1', AUTO_STORE='keys';
function autoStore(){
 return new Promise((resolve,reject)=>{
  if(!('indexedDB' in window)){reject(Error('IndexedDB non disponibile'));return}
  const req=indexedDB.open(AUTO_DB,1);
  req.onupgradeneeded=()=>{if(!req.result.objectStoreNames.contains(AUTO_STORE))req.result.createObjectStore(AUTO_STORE)};
  req.onerror=()=>reject(req.error||Error('Apertura non riuscita'));
  req.onsuccess=()=>resolve(req.result);
 });
}
async function autoGet(){
 const database=await autoStore();
 return new Promise((resolve,reject)=>{
  const tx=database.transaction(AUTO_STORE,'readonly'),req=tx.objectStore(AUTO_STORE).get('archive');
  req.onsuccess=()=>resolve(req.result||null);
  req.onerror=()=>reject(req.error);
  tx.oncomplete=()=>database.close();
  tx.onerror=()=>{database.close();reject(tx.error)};
 });
}
async function autoPut(value){
 const database=await autoStore();
 return new Promise((resolve,reject)=>{
  const tx=database.transaction(AUTO_STORE,'readwrite');
  tx.objectStore(AUTO_STORE).put(value,'archive');
  tx.oncomplete=()=>{database.close();resolve()};
  tx.onerror=()=>{database.close();reject(tx.error)};
 });
}
async function autoClear(){
 const database=await autoStore();
 return new Promise((resolve,reject)=>{
  const tx=database.transaction(AUTO_STORE,'readwrite');
  tx.objectStore(AUTO_STORE).delete('archive');
  tx.oncomplete=()=>{database.close();resolve()};
  tx.onerror=()=>{database.close();reject(tx.error)};
 });
}
async function showAutoStatus(){
 const label=$('autoUnlockStatus'),enable=$('autoUnlockEnable'),disable=$('autoUnlockDisable');
 if(!label)return;
 try{
  const stored=await autoGet(),active=!!(stored&&stored.key);
  label.textContent=active?'Attivo su questo dispositivo.':'Disattivato su questo dispositivo.';
  enable.disabled=active;disable.disabled=!active;
 }catch(_){label.textContent='Non disponibile in questo browser o modalità privata.';enable.disabled=true;disable.disabled=true}
}
async function enableAutoUnlock(){
 if(!unlocked||!cryptoKey)return alert('Sblocca prima l’archivio con la password.');
 if(!confirm('Attivare l’accesso senza password su questo browser? Chi usa il dispositivo potrà leggere i dati dei clienti.'))return;
 try{
  const record=JSON.parse(localStorage.getItem(secureKey));
  if(!record||!record.salt)throw Error('Archivio mancante');
  await autoPut({key:cryptoKey,salt:record.salt});
  const test=await autoGet();
  if(!test||!test.key||test.salt!==record.salt)throw Error('Verifica fallita');
  await decryptData(record,test.key);
  await showAutoStatus();
  alert('Accesso automatico attivato su questo dispositivo.');
 }catch(err){try{await autoClear()}catch(_){}await showAutoStatus();alert('Non è stato possibile attivare l’accesso automatico in questo browser.')}
}
async function disableAutoUnlock(){
 if(!confirm('Disattivare l’accesso automatico? Alla prossima apertura servirà la password.'))return;
 try{await autoClear();await showAutoStatus();alert('Accesso automatico disattivato.')}catch(_){alert('Non è stato possibile disattivarlo. Riprova.')}
}
async function tryAutoUnlock(){
 try{
  const recordText=localStorage.getItem(secureKey);
  if(!recordText)return;
  const record=JSON.parse(recordText),stored=await autoGet();
  if(!stored||!stored.key||stored.salt!==record.salt)return;
  const restored=await decryptData(record,stored.key);
  db=restored;cryptoKey=stored.key;unlocked=true;
  $('lockScreen').classList.add('hidden');
  renderDashboard();
 }catch(_){/* Password manuale ancora disponibile; non cancellare i dati */ }
}

const bytes=a=>new Uint8Array(a);
const b64=a=>btoa(String.fromCharCode(...bytes(a)));
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function derive(password,salt){let base=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function encryptData(data,k){let iv=crypto.getRandomValues(new Uint8Array(12));let cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode(JSON.stringify(data)));return {iv:b64(iv),data:b64(cipher)}}
async function decryptData(record,k){let plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(record.iv)},k,unb64(record.data));let x=JSON.parse(new TextDecoder().decode(plain));if(!['appointments','jobs','clients'].every(y=>Array.isArray(x[y])))throw Error('Archivio non valido');return x}
async function unlock(password){
 const saved=localStorage.getItem(secureKey);
 if(saved){let record=JSON.parse(saved);let k=await derive(password,unb64(record.salt));db=await decryptData(record,k);cryptoKey=k}
 else {
   let legacy=localStorage.getItem(key),initial={appointments:[],jobs:[],clients:[]};
   if(legacy){let x=JSON.parse(legacy);if(!['appointments','jobs','clients'].every(y=>Array.isArray(x[y])))throw Error('Archivio precedente non valido');initial=x}
   let salt=crypto.getRandomValues(new Uint8Array(16)),k=await derive(password,salt),enc=await encryptData(initial,k);
   localStorage.setItem(secureKey,JSON.stringify({salt:b64(salt),...enc}));
   let verify=await decryptData(JSON.parse(localStorage.getItem(secureKey)),k);
   db=verify;cryptoKey=k;
   if(legacy)localStorage.removeItem(key);
 }
 unlocked=true;document.getElementById('lockScreen').classList.add('hidden');renderDashboard();
 document.getElementById('lockPassword').value='';
}
document.getElementById('lockForm').addEventListener('submit',async ev=>{
 ev.preventDefault();let btn=document.getElementById('lockButton');btn.disabled=true;document.getElementById('lockError').textContent='';
 try{await unlock(document.getElementById('lockPassword').value)}
 catch(err){document.getElementById('lockError').textContent='Password errata oppure archivio non accessibile. Non cancellare i dati del sito.'}
 finally{btn.disabled=false}
});
document.getElementById('lockMessage').textContent=localStorage.getItem(secureKey)?'Inserisci la password per aprire il tuo archivio.':'Crea una password di almeno 8 caratteri. I lavori già salvati saranno cifrati dopo il primo sblocco. Conserva prima un backup.';
document.getElementById('lockButton').textContent=localStorage.getItem(secureKey)?'Sblocca archivio':'Crea password e apri';
tryAutoUnlock();
const id=()=>Date.now().toString(36)+Math.random().toString(36).slice(2),today=()=>{let d=new Date();return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')},e=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),eur=n=>(Number(n)||0).toLocaleString('it-IT',{style:'currency',currency:'CHF'});async function save(){try{
 if(!unlocked||!cryptoKey)throw Error('Archivio bloccato');
 let record=JSON.parse(localStorage.getItem(secureKey));
 let enc=await encryptData(db,cryptoKey);
 localStorage.setItem(secureKey,JSON.stringify({salt:record.salt,...enc}));
 return true
}catch(err){alert('Impossibile salvare: controlla spazio e impostazioni del browser.');return false}}document.getElementById('changePasswordForm').addEventListener('submit',async ev=>{
 ev.preventDefault();
 const oldPassword=v('oldPassword'),newPassword=v('newPassword'),confirmation=v('confirmPassword');
 const msg=$('changePasswordMessage'),button=$('changePasswordButton');
 msg.textContent='';
 if(!unlocked||!cryptoKey){msg.textContent='Sblocca prima l’archivio.';return}
 if(newPassword.length<8){msg.textContent='La nuova password deve contenere almeno 8 caratteri.';return}
 if(newPassword!==confirmation){msg.textContent='Le nuove password non coincidono.';return}
 if(oldPassword===newPassword){msg.textContent='Scegli una password diversa da quella attuale.';return}
 if(!confirm('Hai già esportato un backup aggiornato? Confermi il cambio password?'))return;
 button.disabled=true;
 let oldRecord=null,updated=false;
 try{
   oldRecord=localStorage.getItem(secureKey);
   if(!oldRecord)throw Error('Archivio non trovato');
   const record=JSON.parse(oldRecord);
   const oldKey=await derive(oldPassword,unb64(record.salt));
   const archived=await decryptData(record,oldKey);
   // Reencrypt the exact persisted archive; don't accidentally discard fields.
   const newSalt=crypto.getRandomValues(new Uint8Array(16));
   const newKey=await derive(newPassword,newSalt);
   const enc=await encryptData(archived,newKey);
   const newRecord=JSON.stringify({salt:b64(newSalt),...enc});
   const verified=await decryptData(JSON.parse(newRecord),newKey);
   if(JSON.stringify(verified)!==JSON.stringify(archived))throw Error('Verifica archivio fallita');
   localStorage.setItem(secureKey,newRecord);updated=true;
   // Confirm the actual stored bytes can be decrypted before changing active key.
   await decryptData(JSON.parse(localStorage.getItem(secureKey)),newKey);
   cryptoKey=newKey;
   $('changePasswordForm').reset();
   try{await autoClear()}catch(_){};await showAutoStatus();msg.textContent='Password modificata. Accesso automatico disattivato: riattivalo dalle impostazioni se lo desideri.';
 }catch(err){
   if(updated&&oldRecord!==null){try{localStorage.setItem(secureKey,oldRecord)}catch(_) {}}
   msg.textContent='Cambio password non riuscito. Se la password attuale è corretta, controlla lo spazio disponibile. Non cancellare i dati.';
 }finally{button.disabled=false}
});
const RATE_DEFAULTS={hour:110,wheels:40,tires:70};
function getRates(){let x=db.rates||{};return Object.fromEntries(Object.entries(RATE_DEFAULTS).map(([k,n])=>[k,Number.isFinite(Number(x[k]))&&x[k]!==undefined&&x[k]!==null?Number(x[k]):n]))}
function showRates(){const r=getRates();for(const k of ['hour','wheels','tires'])s('cfg_'+k,r[k])}
async function saveRates(){let rates={};for(const k of ['hour','wheels','tires']){const input=$('cfg_'+k);if(input.value.trim()===''||!Number.isFinite(Number(input.value))||Number(input.value)<0)return alert('Inserisci una tariffa valida per '+k);rates[k]=Number(input.value)}db.rates=rates;if(await save())alert('Tariffe salvate. Saranno proposte nei nuovi lavori.')}
function checkedValue(name){return document.querySelector('input[name="'+name+'"]:checked')?.value||''}
function setCheckedValue(name,value){let option=[...document.querySelectorAll('input[name="'+name+'"]')].find(x=>x.value===value);(option||document.querySelector('input[name="'+name+'"]')).checked=true}
function tireCharge(){let service=checkedValue('tireService');if(service==='none'||!service)return 0;let rate=v('j_tireRate');return Number(rate)||0}
function updateTireServiceRate(){let service=checkedValue('tireService');s('j_tireRate',service==='wheels'?getRates().wheels:service==='tires'?getRates().tires:0);calc()}
let navHistory=[];
function goBack(){
 navHistory=[];
 go('home',true);
}
function go(page,fromBack=false){
 const current=document.querySelector('main section.active')?.id||'home';
 if(!document.getElementById(page))return;
 if(!fromBack&&page!==current){
  if(page==='home')navHistory=[];
  else navHistory.push(current);
 }
 if(page==='home'){renderDashboard();otmBackupNotice();}
 document.querySelectorAll('main section').forEach(x=>x.classList.toggle('active',x.id===page));
 if(page==='quotes')renderQuotes();if(page==='reminders')renderReminders();if(page==='stats')renderStats();if(page==='agenda')renderAppts();if(page==='jobs')renderJobs();if(page==='workHistory')renderWorkHistory();if(page==='clients')renderClients();if(page==='clientHistory')renderClientHistory();if(page==='settings'){showRates();showAutoStatus()}
 $('backNav').style.display=page==='home'?'none':'inline-flex';
 scrollTo(0,0);
}function renderDashboard(){
 if(!unlocked)return;
 const date=today(),todayAppts=db.appointments.filter(a=>a.date===date).sort((a,b)=>String(a.time||'').localeCompare(String(b.time||'')));
 const progress=db.jobs.filter(j=>j.status==='In lavorazione').length; $('otmAllAgendaCount').textContent=db.appointments.filter(a=>!['Completato','Annullato'].includes(a.status)).length+' appuntamenti attivi in agenda · tutte le date';
 const done=db.jobs.filter(j=>isJobComplete(j)).length;
 $('dashToday').textContent=todayAppts.length;$('dashProgress').textContent=progress;$('dashDone').textContent=done;
 $('dashDate').textContent=new Date(date+'T12:00:00').toLocaleDateString('it-CH',{weekday:'long',day:'numeric',month:'long',year:'numeric'});
 const box=$('dashAgenda');box.replaceChildren();
 if(!todayAppts.length){const empty=document.createElement('div');empty.className='dash-empty';empty.textContent='Nessun appuntamento per oggi.';box.appendChild(empty);return}
 for(const a of todayAppts){const btn=document.createElement('button');btn.type='button';btn.className='dash-appointment';btn.onclick=()=>editAppt(a.id);
 const time=document.createElement('span');time.className='dash-time';time.textContent=a.time||'—';
 const info=document.createElement('span');info.className='dash-appt-main';const name=document.createElement('strong');name.textContent=a.client||'Cliente';const details=document.createElement('small');details.textContent=[a.plate,a.vehicle,a.desc].filter(Boolean).join(' · ');info.append(name,details);
 const status=document.createElement('span');status.className='dash-status'+(a.status==='In lavorazione'?' progress':a.status==='Completato'?' done':a.status==='Annullato'?' cancelled':'');status.textContent=a.status||'Prenotato';btn.append(time,info,status);box.appendChild(btn)}
}
function normalizeSearch(t){return String(t||'').trim().toLocaleLowerCase('it').replace(/\s+/g,' ')}
function clearApptSelection(){s('a_vehicleId','');$('a_matchHelp').textContent='Veicolo modificato: seleziona di nuovo dall’archivio oppure salva i dati manualmente.'}
function selectApptVehicle(vehicleId){
 const c=db.clients.find(x=>x.id===vehicleId);if(!c)return;
 s('a_vehicleId',c.id);s('a_client',c.name||'');s('a_plate',c.plate||'');s('a_vehicle',c.vehicle||'');
 $('a_matches').style.display='none';$('a_matches').innerHTML='';
 $('a_customerHint').textContent='✓ Cliente e auto recuperati dall’archivio.';
 $('a_matchHelp').textContent='✓ Veicolo selezionato: '+(c.vehicle||'Auto')+(c.vin?' · Telaio '+c.vin:'');
}
function addAnotherApptCar(){
 const name=v('a_client').trim();if(!name){alert('Scrivi prima il nome del cliente.');return}
 const known=db.clients.filter(c=>normalizeSearch(c.name)===normalizeSearch(name));
 if(!known.length){alert('Cliente non ancora registrato: completa l’appuntamento e potrai aprire la scheda cliente al salvataggio.');return}
 pendingAppointmentDraft=null;openNewCarForm(name,{},false);clientReturnPage='apptEdit';
}
function searchApptVehicles(){
 s('a_vehicleId','');
 const name=normalizeSearch(v('a_client')),plate=normalizedPlate(v('a_plate'));
 const box=$('a_matches');box.innerHTML='';
 const field=document.activeElement?.id;
 const exact=db.clients.filter(c=>normalizeSearch(c.name)===name);
 let matches=db.clients.filter(c=>field==='a_plate'?(plate&&normalizedPlate(c.plate).includes(plate)):(name&&normalizeSearch(c.name).includes(name)));
 if(!matches.length&&field!=='a_plate'&&plate)matches=db.clients.filter(c=>normalizedPlate(c.plate).includes(plate));
 $('a_customerHint').textContent=exact.length?('✓ Cliente già registrato: '+exact.length+' auto. Scegli un’auto qui sotto o premi «Aggiungi un’altra auto».'):(name?'Cliente non ancora registrato: al salvataggio potrai aggiungerlo all’archivio.':'');
 if(!name&&!plate){box.style.display='none';$('a_matchHelp').textContent='Cerca per nome o targa. Se ci sono più veicoli, scegli quello giusto.';return}
 if(!matches.length){box.style.display='none';$('a_matchHelp').textContent='Nessun veicolo trovato: puoi compilare manualmente.';return}
 // Una sola auto con nome esatto: completa automaticamente senza sovrascrivere una targa già scritta.
 if(field==='a_client'&&exact.length===1&&!plate){selectApptVehicle(exact[0].id);$('a_customerHint').textContent='✓ Cliente e auto compilati automaticamente. Per una seconda auto usa il pulsante dedicato.';return}
 box.style.display='block';$('a_matchHelp').textContent=matches.length+' veicolo/i trovato/i: scegli il veicolo corretto.';
 for(const c of matches.slice(0,30)){
  const b=document.createElement('button');b.type='button';b.className='item';
  const title=document.createElement('strong');title.textContent=(c.name||'Cliente')+' — '+(c.vehicle||'Veicolo non specificato');
  const sub=document.createElement('span');sub.className='muted';sub.textContent=' '+(c.plate||'Senza targa')+(c.vin?' · VIN '+c.vin:'');
  b.append(title,document.createElement('br'),sub);b.onclick=()=>selectApptVehicle(c.id);box.appendChild(b);
 }
}
function renderApptJobPanel(apptId){
 const panel=$('a_jobPanel'),links=$('a_linkedJobs'),button=$('a_createJob');
 panel.style.display=apptId?'block':'none';links.innerHTML='';
 if(!apptId)return;
 const jobs=db.jobs.filter(j=>j.appointmentId===apptId);
 button.textContent=jobs.length?'🔧 Crea un altro lavoro da appuntamento':'🔧 Crea lavoro da appuntamento';
 if(jobs.length){
  const heading=document.createElement('p');heading.textContent='Lavori collegati:';links.appendChild(heading);
  for(const job of jobs){
   const b=document.createElement('button');b.type='button';b.className='item';
   b.textContent=(job.date||'')+' · '+(job.desc||'Lavoro')+' · '+(job.plate||'');
   b.onclick=()=>editJob(job.id);links.appendChild(b);
  }
 }
}
let pendingAppointmentId='';
function createJobFromAppt(){
 const appt=db.appointments.find(a=>a.id===v('a_id'));
 if(!appt)return alert('Salva prima l’appuntamento.');
 const linked=db.jobs.filter(j=>j.appointmentId===appt.id);
 if(linked.length&&!confirm('Questo appuntamento ha già un lavoro collegato. Vuoi crearne un altro?'))return;
 editJob();
 pendingAppointmentId=appt.id;s('j_appointmentId',appt.id);
 s('j_date',appt.date||today());s('j_time',appt.time||'');s('j_client',appt.client||'');
 s('j_plate',appt.plate||'');s('j_vehicle',appt.vehicle||'');
 s('j_desc',appt.desc||'');
 s('j_status','In lavorazione');
 let vehicle=appt.vehicleId?db.clients.find(c=>c.id===appt.vehicleId):null;
 if(!vehicle){
  const matches=db.clients.filter(c=>normalizeSearch(c.name)===normalizeSearch(appt.client)&&normalizedPlate(c.plate)===normalizedPlate(appt.plate)&&normalizeSearch(c.vehicle)===normalizeSearch(appt.vehicle));
  if(matches.length===1)vehicle=matches[0];
 }
 if(vehicle)for(const k of ['vin','engine','kw','ident'])s('j_'+k,vehicle[k]??'');
 lastPlateLookup=normalizedPlate(appt.plate);
 $('j_apptInfo').style.display='block';
 $('j_apptInfo').textContent='Collegato all’appuntamento del '+(appt.date||'')+' alle '+(appt.time||'')+'. Lo stato cambierà al salvataggio del lavoro.';
 $('quickMsg').textContent='✓ Dati copiati dall’appuntamento.';
}
function editAppt(xid){let x=db.appointments.find(a=>a.id===xid)||{};
 ['id','date','time','client','plate','vehicle','desc','status'].forEach(k=>s('a_'+k,x[k]??(k==='date'?today():k==='status'?'Prenotato':'')));
 s('a_vehicleId',x.vehicleId||'');$('a_customerHint').textContent='';$('a_matches').innerHTML='';$('a_matches').style.display='none';
 $('a_matchHelp').textContent=x.vehicleId?'Veicolo collegato all’archivio.':'Cerca per nome o targa. Se ci sono più veicoli, scegli quello giusto.';
 $('a_delete').classList.toggle('hide',!x.id);renderApptJobPanel(x.id);go('apptEdit')}
let pendingAppointmentDraft=null;
function appointmentDraft(){let x={};['id','date','time','client','plate','vehicle','desc','status','vehicleId'].forEach(k=>x[k]=v('a_'+k).trim());x.id=x.id||id();x.plate=x.plate.toUpperCase();return x}
async function persistAppointment(x){
 const before=db.appointments.map(a=>({...a}));
 const i=db.appointments.findIndex(a=>a.id===x.id);if(i<0)db.appointments.push(x);else db.appointments[i]=x;
 if(await save()){go('agenda');return true}db.appointments=before;return false;
}
$('apptForm').onsubmit=async ev=>{
 ev.preventDefault();const x=appointmentDraft();
 if(x.vehicleId){const c=db.clients.find(c=>c.id===x.vehicleId);if(!c||normalizeSearch(c.name)!==normalizeSearch(x.client)||normalizedPlate(c.plate)!==normalizedPlate(x.plate)||normalizeSearch(c.vehicle)!==normalizeSearch(x.vehicle))x.vehicleId=''}
 const plateMatches=x.plate?db.clients.filter(c=>normalizedPlate(c.plate)===normalizedPlate(x.plate)):[];
 const exactName=db.clients.filter(c=>normalizeSearch(c.name)===normalizeSearch(x.client));
 const existing=x.vehicleId?db.clients.find(c=>c.id===x.vehicleId):plateMatches.find(c=>normalizeSearch(c.name)===normalizeSearch(x.client));
 if(!existing&&plateMatches.length){if(!confirm('Questa targa è già presente nell’archivio. Vuoi salvare solo l’appuntamento senza creare un’altra auto?'))return;}
 else if(!existing&&x.plate){
  const msg=exactName.length?'Vuoi aggiungere questa auto a '+exactName[0].name+'? Si aprirà la scheda completa per inserire tutti i dati.':'Vuoi registrare '+x.client+' come nuovo cliente? Si aprirà la scheda per inserire telefono e dati dell’auto.';
  if(confirm(msg)){
   pendingAppointmentDraft=x;
   openNewCarForm(x.client,{plate:x.plate,vehicle:x.vehicle},true);
   return;
  }
 }
 await persistAppointment(x);
};
function renderAppts(){
 const active=db.appointments.filter(a=>!['Completato','Annullato'].includes(a.status)).length;
 $('agendaCount').textContent=active+' appuntamenti attivi in agenda (tutte le date)';
 $('agendaTodayCount').textContent=db.appointments.filter(a=>a.date===today()&&a.status!=='Completato').length+' appuntamenti oggi';
 let a=[...db.appointments].filter(a=>a.status!=='Completato').sort((x,y)=>(x.date+x.time).localeCompare(y.date+y.time));$('appts').innerHTML=a.length?a.map(x=>`<button class="item" data-id="${e(x.id)}" onclick="editAppt(this.dataset.id)"><strong>${e(x.date)} ${e(x.time)} — ${e(x.client)}</strong>${e(x.plate)} · ${e(x.vehicle)}<br><span class="muted">${e(x.desc)} · ${e(x.status)}</span></button>`).join(''):'<p class="muted">Nessun appuntamento.</p>'}async function delItem(collection,input,page){if(!confirm('Eliminare questa scheda?'))return;db[collection]=db[collection].filter(x=>x.id!==v(input));if(await save())go(page)}function addPart(p={}){let d=document.createElement('div');d.className='part';d.innerHTML=`<div class="field"><label>Materiale / ricambio</label><input class="pn" list="knownParts" value="${e(p.name||'')}"></div><div class="two"><div class="field"><label>Quantità</label><input class="pq" type="number" min="0" step="0.01" value="${e(p.qty??1)}"></div><div class="field"><label>Prezzo unitario (CHF)</label><input class="pp" type="number" min="0" step="0.01" value="${e(p.price??0)}"></div></div><div class="row"><strong class="subtotal">0,00 CHF</strong><button type="button" class="secondary danger">Rimuovi</button></div>`;d.querySelectorAll('input').forEach(i=>i.oninput=calc);d.querySelector('button').onclick=()=>{d.remove();calc()};$('parts').appendChild(d);calc()}function quickPart(name){
 let price=0;
 for(const job of [...db.jobs].reverse()){
  const previous=(job.parts||[]).find(p=>(p.name||'').trim().toLowerCase()===name.toLowerCase());
  if(previous){price=Number(previous.price)||0;break}
 }
 addPart({name,qty:1,price});
 const last=$('parts').lastElementChild;
 if(last){last.querySelector('.pq').focus();last.scrollIntoView({behavior:'smooth',block:'nearest'})}
}
function getParts(){return [...$('parts').querySelectorAll('.part')].map(d=>({name:d.querySelector('.pn').value.trim(),qty:Number(d.querySelector('.pq').value)||0,price:Number(d.querySelector('.pp').value)||0}))}function calc(){let p=getParts(),m=p.reduce((a,x)=>a+x.qty*x.price,0),l=(Number(v('j_hours'))||0)*(Number(v('j_rate'))||0);$('parts').querySelectorAll('.part').forEach((d,i)=>d.querySelector('.subtotal').textContent=eur(p[i].qty*p[i].price));$('mats').textContent=eur(m);$('labor').textContent=eur(l);$('tireCost').textContent=eur(tireCharge());$('grand').textContent=eur(m+l+tireCharge());return m+l+tireCharge()}function refreshSuggestions(){
 const clients=[...new Set(db.clients.map(x=>x.name).filter(Boolean))];
 const vehicles=[...new Set(db.clients.map(x=>x.vehicle).filter(Boolean))];
 const materials=[...new Set(db.jobs.flatMap(x=>(x.parts||[]).map(p=>p.name)).filter(Boolean))];
 $('knownClients').innerHTML=clients.map(x=>`<option value="${e(x)}">`).join('');
 $('knownVehicles').innerHTML=vehicles.map(x=>`<option value="${e(x)}">`).join('');
 $('knownParts').innerHTML=materials.map(x=>`<option value="${e(x)}">`).join('');
}
function searchJobVehicles(){
 const name=normalizeSearch(v('j_client')),box=$('j_matches');box.innerHTML='';
 if(!name){box.style.display='none';$('j_matchHelp').textContent='Scrivi il nome del cliente e scegli il veicolo dall’elenco.';return}
 const matches=db.clients.filter(c=>normalizeSearch(c.name).includes(name));
 if(!matches.length){box.style.display='none';$('j_matchHelp').textContent='Cliente non trovato: puoi inserire i dati manualmente.';return}
 box.style.display='block';$('j_matchHelp').textContent=matches.length+' auto trovata/e. Scegli quella corretta.';
 for(const c of matches.slice(0,30)){
  const b=document.createElement('button');b.type='button';b.className='item';
  const title=document.createElement('strong');title.textContent=(c.name||'Cliente')+' — '+(c.vehicle||'Veicolo non specificato');
  const detail=document.createElement('span');detail.className='muted';detail.textContent=(c.plate||'Senza targa')+(c.vin?' · VIN '+c.vin:'');
  b.append(title,detail);b.onclick=()=>selectJobVehicle(c.id);box.appendChild(b);
 }
}
function selectJobVehicle(vehicleId){
 const c=db.clients.find(x=>x.id===vehicleId);if(!c)return;
 s('j_client',c.name||'');s('j_plate',c.plate||'');s('j_vehicle',c.vehicle||'');
 for(const k of ['vin','engine','kw','ident'])s('j_'+k,c[k]??'');
 lastPlateLookup=normalizedPlate(c.plate);
 $('j_matches').innerHTML='';$('j_matches').style.display='none';
 $('j_matchHelp').textContent='✓ Auto selezionata: '+(c.vehicle||'Veicolo')+' · '+(c.plate||'Senza targa');
 $('quickMsg').textContent='✓ Cliente e veicolo compilati dall’archivio.';
}
let lastPlateLookup = null;
function fillFromPlate(){
 const plate=v('j_plate').trim().toUpperCase().replace(/\s/g,'');
 const currentId=v('j_id');
 const match=plate?(db.clients.find(x=>(x.plate||'').toUpperCase().replace(/\s/g,'')===plate)
 || [...db.jobs].reverse().find(x=>(x.plate||'').toUpperCase().replace(/\s/g,'')===plate)):null;
 // Preserve user-entered details until the plate actually changes.
 if(lastPlateLookup===plate)return;
 lastPlateLookup=plate;
 if(match){
  s('j_client',match.name||match.client||'');
  s('j_vehicle',match.vehicle||'');
  for(const k of ['vin','engine','kw','ident'])s('j_'+k,match[k]||'');
  $('quickMsg').textContent='✓ Cliente e veicolo aggiornati per questa targa.';
 }else{
  s('j_client','');s('j_vehicle','');for(const k of ['vin','engine','kw','ident'])s('j_'+k,'');
  $('quickMsg').textContent=plate?'Targa non trovata: inserisci i dati del nuovo cliente.':'Inserisci una targa.';
 }
}
function duplicateJob(){
 let plate=v('j_plate').trim().toUpperCase();
 let candidates=plate?db.jobs.filter(x=>(x.plate||'').toUpperCase()===plate):db.jobs;
 if(!candidates.length){alert('Nessun lavoro precedente da duplicare. Inserisci una targa già presente nello storico.');return}
 let last=[...candidates].sort((a,b)=>b.date.localeCompare(a.date))[0];
 if(!confirm('Copiare l’ultimo lavoro trovato? Potrai modificarlo prima di salvarlo.'))return;
 const original=last;
 s('j_id','');s('j_date','');s('j_time','');lastPlateLookup=null;
 for(const k of ['client','plate','vehicle','vin','engine','kw','ident','km','desc','hours','rate','notes'])s('j_'+k,original[k]??'');
 s('j_status','Da fare');document.querySelectorAll('input[name="jobStatusChoice"]').forEach(r=>r.checked=r.value==='Da fare');s('j_tireSize',original.tireSize||'');for(const pos of ['VR','VL','HR','HL'])s('j_tire'+pos,original.tireDepth?.[pos]??'');setCheckedValue('tireSeason',original.tireSeason||'');setCheckedValue('tireService',original.tireService||'none');s('j_tireRate',original.tireRate??(original.tireService==='wheels'?getRates().wheels:original.tireService==='tires'?getRates().tires:0));$('parts').innerHTML='';
 (original.parts||[]).forEach(addPart);
 $('j_delete').classList.add('hide');calc();
 $('quickMsg').textContent='✓ Lavoro duplicato. Verrà salvato come nuova scheda.';
}
function editJob(xid){let x=db.jobs.find(a=>a.id===xid)||{};window.otmPhotos=[...(x.photos||[])];setTimeout(()=>{s('j_payment',x.payment||'Da pagare');s('j_deposit',x.deposit||0);s('j_nextService',x.nextService||'');s('j_nextKm',x.nextKm||'');renderJobPhotos();},0);
pendingAppointmentId='';s('j_appointmentId','');$('j_apptInfo').style.display='none';refreshSuggestions();$('quickMsg').textContent='';lastPlateLookup=null;$('j_matches').innerHTML='';$('j_matches').style.display='none';$('j_matchHelp').textContent='Scrivi il nome del cliente e scegli il veicolo dall’elenco.';
if(x.id&&isJobComplete(x)&&!otmCorrectionId){openHistoryJob(x.id);return}if(!x.id)x.rate=getRates().hour;
['id','date','client','plate','vehicle','vin','engine','kw','ident','km','desc','status','hours','rate','notes'].forEach(k=>s('j_'+k,x[k]??(k==='date'?'':k==='status'?'Da fare':k==='hours'||k==='rate'?0:'')));s('j_time',x.time||db.appointments.find(a=>a.id===x.appointmentId)?.time||'');s('j_tireSize',x.tireSize||'');for(const pos of ['VR','VL','HR','HL'])s('j_tire'+pos,x.tireDepth?.[pos]??'');setCheckedValue('tireSeason',x.tireSeason||'');setCheckedValue('tireService',x.tireService||'none');s('j_tireRate',x.tireRate??(x.tireService==='wheels'?getRates().wheels:x.tireService==='tires'?getRates().tires:0));$('parts').innerHTML='';(x.parts||[]).forEach(addPart);$('j_delete').classList.toggle('hide',!x.id);calc();document.querySelectorAll('input[name="jobStatusChoice"]').forEach(r=>r.checked=r.value===v('j_status'));go('jobEdit')}// Una scheda cliente-auto per targa; conserva telefono e note esistenti.
function normalizedPlate(plate){return String(plate||'').toUpperCase().replace(/\s+/g,'').trim()}
function mergeClientFromJob(job){
 const plate=normalizedPlate(job.plate);
 if(!plate||!String(job.client||'').trim())return false;
 let candidates=db.clients.filter(c=>normalizedPlate(c.plate)===plate);
 let existing=(job.vin&&candidates.find(c=>c.vin&&String(c.vin).toUpperCase()===String(job.vin).toUpperCase())) ||
 candidates.find(c=>normalizeSearch(c.name)===normalizeSearch(job.client)&&normalizeSearch(c.vehicle)===normalizeSearch(job.vehicle)&&(!job.vin||!c.vin||String(c.vin).toUpperCase()===String(job.vin).toUpperCase()));
 if(!existing&&candidates.length===1&&!job.vin&&!job.vehicle&&normalizeSearch(candidates[0].name)===normalizeSearch(job.client))existing=candidates[0];
 const fields={name:job.client,plate:job.plate,vehicle:job.vehicle,vin:job.vin,engine:job.engine,kw:job.kw,ident:job.ident};
 if(existing){
   let changed=false;
   for(const [k,value] of Object.entries(fields)){
     // Non eliminare informazioni già registrate quando il campo lavoro è vuoto.
     if(String(value??'').trim()&&existing[k]!==value){existing[k]=value;changed=true}
   }
   return changed;
 }
 db.clients.push({id:id(),phone:'',notes:'',...Object.fromEntries(Object.entries(fields).map(([k,val])=>[k,String(val??'').trim()]))});
 return true;
}
async function recoverClientsFromJobs(){
 if(!db.jobs.length)return alert('Non ci sono lavori nello storico.');
 if(!confirm('Recuperare clienti e auto dai lavori già salvati? I dati vuoti non cancelleranno quelli esistenti.'))return;
 const oldClients=JSON.parse(JSON.stringify(db.clients));
 let count=0;
 const jobs=[...db.jobs].sort((a,b)=>String(a.date||'').localeCompare(String(b.date||'')));
 for(const job of jobs)if(mergeClientFromJob(job))count++;
 if(!count)return alert('Clienti e auto già aggiornati.');
 if(await save()){renderClients();alert('Clienti e auto aggiornati dallo storico.')}else db.clients=oldClients;
}
$('jobForm').onsubmit=async ev=>{ev.preventDefault();let x={};['id','date','client','plate','vehicle','vin','engine','kw','ident','km','desc','status','hours','rate','notes'].forEach(k=>x[k]=v('j_'+k).trim());x.id=x.id||id();x.time=v('j_time');x.plate=x.plate.toUpperCase();x.vin=x.vin.toUpperCase();x.engine=x.engine.toUpperCase();x.parts=getParts();x.tireSize=v('j_tireSize').trim();x.tireSeason=checkedValue('tireSeason');x.tireService=checkedValue('tireService')||'none';x.tireRate=Number(v('j_tireRate'))||0;x.tireDepth=Object.fromEntries(['VR','VL','HR','HL'].map(pos=>[pos,v('j_tire'+pos).trim()]));x.total=calc();let i=db.jobs.findIndex(a=>a.id===x.id);const oldJobs=db.jobs.slice(),oldClients=JSON.parse(JSON.stringify(db.clients));if(i<0&&(v('j_appointmentId')||pendingAppointmentId))x.appointmentId=v('j_appointmentId')||pendingAppointmentId;
else if(i>=0&&db.jobs[i].appointmentId)x.appointmentId=db.jobs[i].appointmentId;
const oldAppointments=db.appointments.map(a=>({...a}));
const prior=i>=0?db.jobs[i]:{};
if(i>=0&&isJobComplete(prior)&&otmCorrectionId!==x.id)return alert('Scheda completata: usa Rettifica dallo storico.');
if(x.status==='Completato'&&!isJobComplete(prior)&&!confirm('Confermi la chiusura definitiva? Il lavoro passerà nello storico e sarà modificabile solo con Rettifica.'))return;
if(otmCorrectionId===x.id){x.audit=[...(prior.audit||[]),{at:new Date().toISOString(),type:'Rettifica',before:JSON.parse(JSON.stringify(prior))}];otmCorrectionId='';}
x.payment=v('j_payment');x.deposit=Number(v('j_deposit'))||0;x.photos=window.otmPhotos||prior.photos||[];x.nextService=v('j_nextService');x.nextKm=v('j_nextKm');
if(i<0)db.jobs.push(x);else db.jobs[i]=x;
mergeClientFromJob(x);
if(!x.appointmentId){
 const appt={id:id(),date:x.date,time:x.time,client:x.client,plate:x.plate,vehicle:x.vehicle,desc:x.desc,status:isJobComplete(x)?'Completato':'Prenotato',jobId:x.id};
 db.appointments.push(appt);x.appointmentId=appt.id;
}else{
 const appt=db.appointments.find(a=>a.id===x.appointmentId);
 if(appt){Object.assign(appt,{date:x.date,time:x.time,client:x.client,plate:x.plate,vehicle:x.vehicle,desc:x.desc,status:isJobComplete(x)?'Completato':'In lavorazione',jobId:x.id})}
}
if(await save()){pendingAppointmentId='';go(isJobComplete(x)?'workHistory':'jobs')}
else{db.jobs=oldJobs;db.clients=oldClients;db.appointments=oldAppointments;}};
let otmHistoryJobId='',otmCorrectionId='';
function isJobComplete(j){return j&&['Completato','Consegnato'].includes(j.status)}
function renderWorkHistory(){
 const q=normalizeSearch(v('historySearch'));
 const rows=[...db.jobs].filter(isJobComplete).filter(j=>normalizeSearch([j.client,j.plate,j.vehicle,j.desc].join(' ')).includes(q)).sort((a,b)=>String(b.date||'').localeCompare(String(a.date||'')));
 $('historyItems').innerHTML=rows.length?rows.map(j=>`<button type="button" class="item" data-id="${e(j.id)}" onclick="openHistoryJob(this.dataset.id)"><strong>${e(j.client)} · ${e(j.plate)}</strong><div>${e(j.vehicle||'')} · ${e(j.date||'')}</div><div>${e(j.desc||'')}</div><strong>${eur(j.total)}</strong></button>`).join(''):'<p class="muted">Nessun intervento completato trovato.</p>';
}
function openHistoryJob(jobId){
 const j=db.jobs.find(x=>x.id===jobId);if(!j)return;
 otmHistoryJobId=jobId;
 const box=$('jobReadDetails');box.replaceChildren();
 for(const [label,value] of [['Cliente',j.client],['Targa',j.plate],['Auto',j.vehicle],['Data',j.date],['Intervento',j.desc],['Stato',j.status],['Km',j.km],['Materiali',(j.parts||[]).map(p=>(p.name||'')+' × '+p.qty+' — '+eur(p.price)).join(' | ')],['Ore',j.hours],['Tariffa',eur(j.rate)],['Totale',eur(j.total)],['Pagamento',j.payment],['Note',j.notes]]){
 const line=document.createElement('p');const strong=document.createElement('strong');strong.textContent=label+': ';line.append(strong,document.createTextNode(String(value??'')));box.appendChild(line);
 }
 go('jobRead');
}
function requestJobCorrection(){
 const j=db.jobs.find(x=>x.id===otmHistoryJobId);if(!j)return;
 if(!confirm('Aprire una rettifica controllata? La versione precedente sarà conservata nel registro della scheda.'))return;
 otmCorrectionId=j.id;editJob(j.id);
}
function printHistoryJob(){
 const j=db.jobs.find(x=>x.id===otmHistoryJobId);if(!j)return;
 const rows=[['Cliente',j.client],['Targa',j.plate],['Veicolo',j.vehicle],['Data',j.date],['Lavoro',j.desc],['Km',j.km],['Materiali',(j.parts||[]).map(p=>`${p.name||''} — ${p.qty||0} × ${eur(p.price)}`).join('; ')],['Manodopera',`${j.hours||0} ore × ${eur(j.rate)}`],['Totale',eur(j.total)],['Pagamento',j.payment],['Note',j.notes]].map(([k,val])=>`<p><b>${e(k)}:</b> ${e(val)}</p>`).join('');
 const html=`<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Intervento ${e(j.plate)}</title><style>body{font:15px Arial,sans-serif;max-width:760px;margin:24px auto;padding:15px;color:#111}img{width:125px}header{display:flex;align-items:center;gap:24px}nav{display:flex;gap:12px;margin:20px 0}button{padding:12px;border:1px solid #aaa;border-radius:8px;background:#fff}@media print{nav{display:none}body{margin:0}}</style></head><body><nav><button onclick="window.close()">← Torna all'app</button><button onclick="window.print()">🖨 Stampa / PDF</button></nav><header><img src="${location.origin+location.pathname.replace(/[^/]*$/,'')}otm-logo.png"><h1>OTM Garage — Intervento</h1></header>${rows}</body></html>`;
 const w=window.open('','_blank');if(!w)return alert('Consenti le finestre a comparsa per stampare.');w.document.open();w.document.write(html);w.document.close();w.focus();try{w.print()}catch(err){}
}
function renderJobs(){const upcoming=db.appointments.filter(a=>!['Completato','Annullato'].includes(a.status)).sort((a,b)=>String(a.date+' '+(a.time||'')).localeCompare(String(b.date+' '+(b.time||''))));$('jobsAgendaCount').textContent=upcoming.length+' appuntamenti attivi in agenda';$('jobsAgendaItems').innerHTML=upcoming.length?upcoming.map(a=>`<button type="button" class="item" data-id="${e(a.id)}" onclick="editAppt(this.dataset.id)"><strong>${e(a.date)} ${e(a.time||'--:--')} · ${e(a.client||'')}</strong><div>${e(a.plate||'')} · ${e(a.desc||'')}</div><small>${e(a.status||'Prenotato')}</small></button>`).join(''):'<p class="muted">Nessun appuntamento attivo.</p>';let q=v('search').toLowerCase(),a=[...db.jobs].filter(x=>!isJobComplete(x)).filter(x=>[x.plate,x.client,x.desc,x.vehicle,x.vin,x.engine,x.ident].join(' ').toLowerCase().includes(q)).sort((x,y)=>y.date.localeCompare(x.date));$('jobItems').innerHTML=a.length?a.map(x=>`<button class="item" data-id="${e(x.id)}" onclick="editJob(this.dataset.id)"><strong>${e(x.plate)} — ${e(x.client)}</strong>${e(x.date)} · ${e(x.desc)}<div class="row"><span class="muted">${e(x.status)}</span><strong>${eur(x.total)}</strong></div></button>`).join(''):'<p class="muted">Nessun lavoro trovato.</p>'}let clientReturnPage='clients';
function openNewCarForm(name,car={},fromAppointment=false){
 const related=db.clients.filter(c=>normalizeSearch(c.name)===normalizeSearch(name));
 clientReturnPage=fromAppointment?'apptEdit':'clients';
 editClient();s('c_name',related[0]?.name||name||'');s('c_phone',related[0]?.phone||'');
 for(const k of ['plate','vehicle','vin','engine','kw','ident'])s('c_'+k,car[k]||'');
 $('c_context').style.display='block';$('c_context').textContent=fromAppointment?'Compila la scheda dell’auto. Salvando qui registrerai anche l’appuntamento. «Indietro» torna all’appuntamento senza salvare.':related.length?'Nuova auto per '+related[0].name+'. Il cliente resterà lo stesso.':'Inserisci i dati del nuovo cliente e della sua auto.';
 $('c_saveButton').textContent=fromAppointment?'Salva cliente, auto e appuntamento':'Salva nuova auto';
}
function addCarForClient(vehicleId){const c=db.clients.find(x=>x.id===vehicleId);if(!c)return;pendingAppointmentDraft=null;openNewCarForm(c.name)}
function backFromClient(){if(clientReturnPage==='apptEdit'){pendingAppointmentDraft=null;go('apptEdit')}else go('clients')}
function editClient(xid){let x=db.clients.find(a=>a.id===xid)||{};clientReturnPage='clients';$('c_context').style.display='none';$('c_saveButton').textContent='Salva cliente e auto';['id','name','phone','plate','vehicle','vin','engine','kw','ident','notes'].forEach(k=>s('c_'+k,x[k]||''));$('c_delete').classList.toggle('hide',!x.id);go('clientEdit')}
$('clientForm').onsubmit=async ev=>{
 ev.preventDefault();let x={};['id','name','phone','plate','vehicle','vin','engine','kw','ident','notes'].forEach(k=>x[k]=v('c_'+k).trim());
 x.id=x.id||id();x.plate=x.plate.toUpperCase();x.vin=x.vin.toUpperCase();x.engine=x.engine.toUpperCase();
 const dup=x.plate&&db.clients.find(c=>c.id!==x.id&&normalizedPlate(c.plate)===normalizedPlate(x.plate));
 if(dup){alert('Questa targa è già registrata per '+dup.name+'. Apri la scheda esistente invece di crearne una nuova.');return}
 const previousClients=db.clients.map(c=>({...c})),previousAppointments=db.appointments.map(a=>({...a}));
 const i=db.clients.findIndex(a=>a.id===x.id);if(i<0)db.clients.push(x);else db.clients[i]=x;
 if(pendingAppointmentDraft){let a={...pendingAppointmentDraft,client:x.name,plate:x.plate,vehicle:x.vehicle,vehicleId:x.id};const ai=db.appointments.findIndex(z=>z.id===a.id);if(ai<0)db.appointments.push(a);else db.appointments[ai]=a;}
 if(await save()){
  if(pendingAppointmentDraft){pendingAppointmentDraft=null;go('agenda')}
  else if(clientReturnPage==='apptEdit'){s('a_client',x.name);s('a_plate',x.plate);s('a_vehicle',x.vehicle);s('a_vehicleId',x.id);go('apptEdit')}else go('clients');
 }else{db.clients=previousClients;db.appointments=previousAppointments}
};
let selectedHistoryClient='';
function jobsForClient(group){
 const names=new Set(group.map(c=>normalizeSearch(c.name)).filter(Boolean));
 const plates=new Set(group.map(c=>normalizedPlate(c.plate)).filter(Boolean));
 return db.jobs.filter(j=>names.has(normalizeSearch(j.client))||(j.plate&&plates.has(normalizedPlate(j.plate))));
}
function openClientHistory(name){selectedHistoryClient=normalizeSearch(name);go('clientHistory')}
function renderClientHistory(){
 const group=db.clients.filter(c=>normalizeSearch(c.name)===selectedHistoryClient);
 const jobs=jobsForClient(group).sort((a,b)=>String(b.date||'').localeCompare(String(a.date||'')));
 $('clientHistoryTitle').textContent='Storico · '+(group[0]?.name||'Cliente');
 $('clientHistoryInfo').textContent=group.length+' auto · '+jobs.length+' interventi · Totale lavori '+eur(jobs.reduce((sum,j)=>sum+(Number(j.total)||0),0))+' · Veicoli: '+group.map(c=>(c.vehicle||'Auto')+' ('+(c.plate||'senza targa')+')').join(', ');
 const container=$('clientHistoryItems');container.innerHTML='';
 if(!jobs.length){const p=document.createElement('p');p.className='muted';p.textContent='Nessuno storico disponibile per questo cliente.';container.appendChild(p);return}
 for(const job of jobs){
  const b=document.createElement('button');b.type='button';b.className='item';
  const title=document.createElement('strong');title.textContent=(job.date||'Senza data')+' · '+(job.plate||'Senza targa');
  const desc=document.createElement('div');desc.textContent=job.desc||'Intervento';
  const footer=document.createElement('div');footer.className='row';
  const status=document.createElement('span');status.className='muted';status.textContent=job.status||'';
  const amount=document.createElement('strong');amount.textContent=eur(job.total);
  footer.append(status,amount);b.append(title,desc,footer);b.onclick=()=>isJobComplete(job)?openHistoryJob(job.id):editJob(job.id);container.appendChild(b);
 }
}
function renderClients(){
 const q=normalizeSearch(v('clientSearch'));const groups=new Map();
 for(const c of db.clients){const k=normalizeSearch(c.name)||('senzanome:'+c.id);if(!groups.has(k))groups.set(k,[]);groups.get(k).push(c)}
 const rows=[...groups.values()].sort((a,b)=>normalizeSearch(a[0].name).localeCompare(normalizeSearch(b[0].name)));
 const matches=rows.filter(group=>group.some(c=>[c.name,c.plate,c.vehicle,c.phone,c.vin,c.engine,c.ident].some(t=>normalizeSearch(t).includes(q))));
 const container=$('clientItems');container.innerHTML='';
 if(!matches.length){container.innerHTML=q?'<p class="muted">Nessun cliente o veicolo trovato.</p>':'<p class="muted">Nessun cliente registrato.</p>';return}
 for(const group of matches){
  const card=document.createElement('div');card.className='card';
  const title=document.createElement('button');title.type='button';title.className='item';title.style.width='100%';
  const label=document.createElement('strong');label.textContent=group[0].name+' · '+group.length+' auto';
  const hint=document.createElement('span');hint.className='muted';hint.textContent='Tocca per vedere lo storico ›';
  title.append(label,hint);title.onclick=()=>openClientHistory(group[0].name);card.appendChild(title);
  const jobs=jobsForClient(group);const summary=document.createElement('p');summary.className='muted';summary.style.fontSize='0.82rem';
  summary.textContent=group.length+' veicoli registrati';card.appendChild(summary);
  const phone=document.createElement('p');phone.className='muted';phone.textContent=group.find(c=>c.phone)?.phone||'';if(phone.textContent)card.appendChild(phone);
  for(const c of group){const b=document.createElement('button');b.type='button';b.className='item';b.textContent='✏️ '+(c.vehicle||'Auto senza modello')+' · '+(c.plate||'Senza targa');b.onclick=()=>editClient(c.id);card.appendChild(b)}
  const add=document.createElement('button');add.type='button';add.className='secondary';add.style.width='100%';add.textContent='➕ Aggiungi un’altra auto';add.onclick=()=>addCarForClient(group[0].id);card.appendChild(add);container.appendChild(card)
 }
}function exportBackup(){alert('Attenzione: il backup esportato NON è cifrato. Conservalo in un luogo sicuro.');let b=new Blob([JSON.stringify({format:key,...db},null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='officina-backup-'+today()+'.json';document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1500)}async function importBackup(){let f=$('backupFile').files[0];if(!f)return alert('Seleziona il file di backup.');try{let x=JSON.parse(await f.text());if(!['appointments','jobs','clients'].every(k=>Array.isArray(x[k])))throw Error('Formato non valido');if(!confirm('Sostituire tutti i dati presenti?'))return;db={...x,appointments:x.appointments,jobs:x.jobs,clients:x.clients,rates:x.rates||{}};if(await save()){alert('Backup ripristinato');go('home')}}catch(err){alert('Errore nel backup: '+err.message)}}if('serviceWorker'in navigator)navigator.serviceWorker.register('./sw.js').catch(()=>{});

/* OTM Garage: additional features */
function otmBackupNotice(){const d=db.lastBackup||'';const days=d?Math.floor((Date.now()-new Date(d).getTime())/86400000):999;const el=document.querySelector('.dash-backup');if(el)el.textContent=days>=7?'🔒 Backup consigliato: nessun backup recente registrato su questo dispositivo.':'🔒 Ultimo backup: '+new Date(d).toLocaleDateString('it-CH');}
const originalExport=exportBackup;exportBackup=function(){originalExport();db.lastBackup=new Date().toISOString();save().then(()=>otmBackupNotice());};
function saveVat(){db.vat=Number(v('cfg_vat'))||0;save().then(ok=>{if(ok)alert('IVA salvata')})}
const oldShowRates=showRates;showRates=function(){oldShowRates();s('cfg_vat',db.vat??0)};
function renderJobPhotos(){const box=$('j_photos');box.replaceChildren();(window.otmPhotos||[]).forEach((p,i)=>{const wrap=document.createElement('div');wrap.className='otm-photo';const img=document.createElement('img');img.src=p;img.alt='Foto lavoro';const del=document.createElement('button');del.className='secondary';del.type='button';del.textContent='Rimuovi';del.onclick=()=>{window.otmPhotos.splice(i,1);renderJobPhotos()};wrap.append(img,del);box.append(wrap)})}
function addJobPhoto(input){const f=input.files?.[0];input.value='';if(!f)return;if((window.otmPhotos||[]).length>=2)return alert('Massimo 2 foto per lavoro.');if(!f.type.startsWith('image/'))return alert('Seleziona una foto.');const reader=new FileReader();reader.onload=()=>{const im=new Image();im.onload=()=>{const max=720,scale=Math.min(1,max/Math.max(im.width,im.height));const c=document.createElement('canvas');c.width=Math.round(im.width*scale);c.height=Math.round(im.height*scale);c.getContext('2d').drawImage(im,0,0,c.width,c.height);const data=c.toDataURL('image/jpeg',.6);if(data.length>260000)return alert('Foto troppo grande.');(window.otmPhotos??=[]).push(data);renderJobPhotos()};im.src=reader.result};reader.readAsDataURL(f)}
function populateQuoteClients(selectedName='',selectedPlate=''){
 const clients=$('q_client'),plates=$('q_plate');
 const names=[...new Set((db.clients||[]).map(c=>String(c.name||'').trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'it'));
 clients.replaceChildren();const placeholder=new Option('— Seleziona cliente —','');clients.add(placeholder);
 for(const name of names)clients.add(new Option(name,name));
 if(selectedName&&!names.includes(selectedName))clients.add(new Option(selectedName+' (archivio precedente)',selectedName));
 clients.value=selectedName||'';
 const hint=$('q_clientHint');if(hint)hint.textContent=names.length?names.length+' cliente/i disponibili. Seleziona un nome.':'Nessun cliente registrato. Premi «Aggiungi cliente» per iniziare.';
 quoteClientChanged(selectedPlate);
}
function quoteClientChanged(selectedPlate=''){
 const plates=$('q_plate'),name=$('q_client').value;
 const cars=(db.clients||[]).filter(c=>String(c.name||'').trim()===name);
 const plateValues=[...new Set(cars.map(c=>String(c.plate||'').trim().toUpperCase()).filter(Boolean))];
 plates.replaceChildren();plates.add(new Option('— Seleziona auto / targa —',''));
 for(const plate of plateValues){const car=cars.find(c=>String(c.plate||'').trim().toUpperCase()===plate);plates.add(new Option((car.vehicle?car.vehicle+' · ':'')+plate,plate))}
 if(selectedPlate&&!plateValues.includes(selectedPlate))plates.add(new Option(selectedPlate+' (archivio precedente)',selectedPlate));
 plates.value=selectedPlate||'';
}
function closeQuote(){
 $('quoteEditor').classList.add('hide');
 $('quoteItems').scrollIntoView({behavior:'smooth',block:'start'});
}
function addQuoteMaterial(item={}){
 const container=$('q_materialRows'),row=document.createElement('div');
 row.className='card';row.style.margin='10px 0';
 row.innerHTML='<div class="field"><label>Descrizione materiale</label><input class="qm_desc" placeholder="Es. Olio motore 5W-30"></div><div class="two"><div class="field"><label>Quantità</label><input class="qm_qty" type="number" min="0" step="0.01" placeholder="Inserisci quantità"></div><div class="field"><label>Prezzo unitario CHF</label><input class="qm_price" type="number" min="0" step="0.01" placeholder="Inserisci prezzo unitario"></div></div><button type="button" class="secondary qm_remove">Rimuovi materiale</button>';
 row.querySelector('.qm_desc').value=item.desc||'';
 row.querySelector('.qm_qty').value=item.qty??'';
 row.querySelector('.qm_price').value=item.price??'';
 row.querySelector('.qm_remove').onclick=()=>{row.remove();updateQuoteMaterialTotal()};
 row.querySelectorAll('input').forEach(input=>input.addEventListener('input',updateQuoteMaterialTotal));
 container.append(row);updateQuoteMaterialTotal();
}
function quoteMaterials(){
 return [...$('q_materialRows').children].map(row=>({
  desc:row.querySelector('.qm_desc').value.trim(),
  qty:Number(row.querySelector('.qm_qty').value)||0,
  price:Number(row.querySelector('.qm_price').value)||0
 })).filter(m=>m.desc||m.qty*m.price);
}
function updateQuoteMaterialTotal(){
 const total=quoteMaterials().reduce((sum,m)=>sum+m.qty*m.price,0);
 $('q_materialTotal').textContent=eur(total);
}
function dateToSwiss(d){const m=String(d||'').match(/^(\d{4})-(\d{2})-(\d{2})$/);return m?m[3]+'.'+m[2]+'.'+m[1]:String(d||'')}
function swissToDate(d){const m=String(d||'').match(/^(\d{2})\.(\d{2})\.(\d{4})$/);if(!m)return '';const iso=m[3]+'-'+m[2]+'-'+m[1];const date=new Date(iso+'T12:00:00');return !Number.isNaN(date.getTime())&&date.getDate()===Number(m[1])&&date.getMonth()+1===Number(m[2])?iso:''}
function newQuote(qid){const q=(db.quotes||[]).find(x=>x.id===qid)||{};$('quoteEditor').classList.remove('hide');for(const k of ['id','date','client','plate','desc','hours','rate','status','payment','deposit'])s('q_'+k,q[k]??(k==='date'?today():k==='rate'?getRates().hour:k==='status'?'Bozza':k==='payment'?'Non pagato':k==='deposit'?0:''));s('q_date',dateToSwiss(q.date||today()));populateQuoteClients(q.client||'',q.plate||'');$('q_materialRows').replaceChildren();if(Array.isArray(q.materials)&&q.materials.length){q.materials.forEach(addQuoteMaterial)}else if(Number(q.parts)>0){addQuoteMaterial({desc:'Ricambi e materiali (preventivo precedente)',qty:1,price:Number(q.parts)})}else addQuoteMaterial();$('q_delete').disabled=!q.id;$('q_convert').textContent=q.linkedJobId?'🔧 Apri scheda lavoro':'🔧 Trasforma in scheda lavoro';$('quoteEditor').scrollIntoView({behavior:'smooth'})}
function quoteDraft(){return {id:v('q_id')||id(),date:swissToDate(v('q_date'))||today(),client:v('q_client').trim(),plate:v('q_plate').trim().toUpperCase(),desc:v('q_desc').trim(),materials:quoteMaterials(),parts:quoteMaterials().reduce((sum,m)=>sum+m.qty*m.price,0),hours:Number(v('q_hours'))||0,rate:Number(v('q_rate'))||0,vat:Number(db.vat)||0,status:v('q_status'),payment:v('q_payment'),deposit:Math.max(0,Number(v('q_deposit'))||0)}}
async function saveQuote(){if(!swissToDate(v('q_date')))return alert('Inserisci una data valida nel formato gg.mm.aaaa.');const q=quoteDraft();if(!q.client||!q.desc)return alert('Inserisci cliente e descrizione.');if(q.materials.some(m=>!m.desc||m.qty<=0||m.price<0))return alert('Controlla descrizione, quantità e prezzo dei materiali.');const prior=(db.quotes||[]).find(x=>x.id===q.id);if(q.deposit>quoteTotal(q).total)return alert('Acconto superiore al totale.');db.quotes??=[];const old=[...db.quotes],i=db.quotes.findIndex(x=>x.id===q.id);if(i<0)db.quotes.push(q);else db.quotes[i]=q;if(await save()){s('q_id',q.id);renderQuotes();$('q_delete').disabled=false;alert('Preventivo salvato.')}else db.quotes=old}
async function deleteQuote(){
 const quoteId=v('q_id'),existing=(db.quotes||[]).find(q=>q.id===quoteId);
 if(!existing)return alert('Questo preventivo non è ancora salvato. Usa «Chiudi preventivo» per uscire.');
 if(!confirm('Eliminare definitivamente il preventivo di '+existing.client+'? Questa azione non elimina eventuali schede lavoro già create.'))return;
 const before=[...db.quotes];
 db.quotes=db.quotes.filter(q=>q.id!==quoteId);
 if(await save()){
  closeQuote();renderQuotes();alert('Preventivo eliminato.');
 }else db.quotes=before;
}
async function convertQuoteToJob(){
 const quoteId=v('q_id'),q=(db.quotes||[]).find(q=>q.id===quoteId);
 if(!q)return alert('Salva prima il preventivo. Poi potrai trasformarlo in scheda lavoro.');
 const existing=(db.jobs||[]).find(j=>j.sourceQuoteId===quoteId||j.id===q.linkedJobId);
 if(existing){
  if(confirm('Questo preventivo ha già una scheda lavoro. Vuoi aprirla?')){closeQuote();editJob(existing.id)}
  return;
 }
 if(!q.client||!q.plate)return alert('Per creare la scheda lavoro servono cliente e targa. Completa e salva il preventivo.');
 if(!confirm('Creare una scheda lavoro dal preventivo salvato? Il preventivo originale verrà conservato.'))return;
 const chosenDate=prompt('Data appuntamento (AAAA-MM-GG):',today());
 if(chosenDate===null)return;
 if(!/^\d{4}-\d{2}-\d{2}$/.test(chosenDate)||Number.isNaN(new Date(chosenDate+'T12:00:00').getTime()))return alert('Inserisci una data valida nel formato AAAA-MM-GG.');

 const car=(db.clients||[]).find(c=>c.name===q.client&&normalizedPlate(c.plate)===normalizedPlate(q.plate))||{};
 const materials=Array.isArray(q.materials)&&q.materials.length
   ?q.materials.map(m=>({name:m.desc,qty:Number(m.qty)||0,price:Number(m.price)||0}))
   :(Number(q.parts)>0?[{name:'Materiali da preventivo',qty:1,price:Number(q.parts)}]:[]);
 const job={
  id:id(),date:chosenDate,client:q.client,plate:q.plate,
  vehicle:car.vehicle||'',vin:car.vin||'',engine:car.engine||'',kw:car.kw||'',ident:car.ident||'',
  km:'',desc:q.desc||'',status:'Da fare',hours:Number(q.hours)||0,rate:Number(q.rate)||0,
  notes:'Creato dal preventivo del '+(q.date||'')+'.',parts:materials,
  tireSize:'',tireSeason:'',tireService:'none',tireRate:0,tireDepth:{},
  total:materials.reduce((sum,m)=>sum+m.qty*m.price,0)+(Number(q.hours)||0)*(Number(q.rate)||0),
  payment:q.payment==='Pagato'?'Pagato':q.payment==='Acconto'?'Acconto':'Da pagare',
  deposit:Number(q.deposit)||0,photos:[],nextService:'',nextKm:'',sourceQuoteId:quoteId
 };
 const oldJobs=[...(db.jobs||[])],oldQuotes=[...(db.quotes||[])],oldAppointments=[...(db.appointments||[])];
 db.jobs.push(job);
 const appointment={id:id(),date:chosenDate,time:'',client:job.client,plate:job.plate,vehicle:job.vehicle,desc:job.desc,status:'Prenotato',jobId:job.id};
 db.appointments.push(appointment);job.appointmentId=appointment.id;
 db.quotes=db.quotes.map(item=>item.id===quoteId?{...item,linkedJobId:job.id,status:'Accettato'}:item);
 if(await save()){closeQuote();renderQuotes();editJob(job.id);alert('Scheda lavoro creata. Puoi completarla e salvarla.')}
 else{db.jobs=oldJobs;db.quotes=oldQuotes;db.appointments=oldAppointments}
}
function quoteTotal(q){const net=(Number(q.parts)||0)+(Number(q.hours)||0)*(Number(q.rate)||0);return {net,vat:net*q.vat/100,total:net*(1+q.vat/100)}}
function renderQuotes(){const box=$('quoteItems');box.replaceChildren();for(const q of [...(db.quotes||[])].reverse()){const b=document.createElement('button');b.className='item';b.textContent=(q.date||'')+' · '+q.client+' · '+eur(quoteTotal(q).total)+' · '+(q.status||'Bozza')+' · '+(q.payment||'Non pagato')+(q.linkedJobId?' · 🔧 Scheda lavoro':'');b.onclick=()=>newQuote(q.id);box.append(b)}if(!(db.quotes||[]).length)box.textContent='Nessun preventivo.'}
// Generatore PDF A4 offline: una pagina JPEG per foglio, senza servizi esterni.
// La condivisione iOS riceve un vero application/pdf, non un file HTML.
async function createQuotePdf(q,t,logoUrl){
 const W=1240,H=1754,M=92,R=W-M,usable=R-M;
 const pages=[];let canvas,ctx,y;
 function page(){canvas=document.createElement('canvas');canvas.width=W;canvas.height=H;ctx=canvas.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,W,H);y=M;}
 function font(size=25,bold=false){ctx.font=(bold?'700 ':'')+size+'px Arial,sans-serif';}
 function line(text,x,yy,size=25,bold=false,color='#152b3a') {font(size,bold);ctx.fillStyle=color;ctx.fillText(String(text??''),x,yy);}
 function wrap(text,maxWidth,size=25,bold=false){font(size,bold);const out=[];for(const para of String(text??'').split('\n')){let row='';for(const word of para.split(/\s+/)){const next=row?row+' '+word:word;if(ctx.measureText(next).width>maxWidth && row){out.push(row);row=word;}else row=next;}out.push(row);}return out;}
 function ensure(h){if(y+h>H-M){finish();page();}}
 function finish(){const data=canvas.toDataURL('image/jpeg',0.88).split(',')[1];const bin=atob(data);const arr=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i);pages.push(arr);}
 function block(text,size=25,bold=false,color='#152b3a',gap=12){const rows=wrap(text,usable,size,bold);const h=rows.length*(size+12)+gap;ensure(h);for(const row of rows){line(row,M,y+size,size,bold,color);y+=size+12;}y+=gap;}
 function rule(){ensure(24);ctx.strokeStyle='#d4e2e5';ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(M,y);ctx.lineTo(R,y);ctx.stroke();y+=20;}
 function money(n){return 'CHF '+(Number(n)||0).toFixed(2);}
 function item(desc,amount){const right=money(amount);font(24,true);const rw=ctx.measureText(right).width;const rows=wrap(desc,usable-rw-34,24);ensure(Math.max(58,rows.length*34+16));line(right,R-rw,y+28,24,true);for(const row of rows){line(row,M,y+28,24);y+=34;}y+=18;rule();}
 page();
 try{const img=new Image();img.src=logoUrl;await new Promise((resolve)=>{img.onload=resolve;img.onerror=resolve;setTimeout(resolve,1500)});if(img.complete&&img.naturalWidth)ctx.drawImage(img,M,y,125,125);}catch(_){}
 line('OTM GARAGE',M+155,y+55,52,true,'#0b4053');line('La tua officina, sempre con te',M+157,y+95,22,false,'#57717e');y+=160;
 ctx.fillStyle='#087f85';ctx.fillRect(M,y,usable,6);y+=55;
 block('PREVENTIVO',48,true,'#087f85',18);
 block('Cliente: '+q.client,27,true);block('Data: '+dateToSwiss(q.date||today())+'     Targa: '+(q.plate||'—'),25);rule();
 block('INTERVENTO PREVISTO',23,true,'#087f85');block(q.desc,25,false,'#152b3a',25);
 block('Stato: '+q.status+'     Pagamento: '+q.payment,22);block('Acconto: '+money(q.deposit),22);rule();
 block('DESCRIZIONE / IMPORTO',24,true,'#087f85',10);
 if((q.materials||[]).length){for(const m of q.materials)item((m.desc||'Materiale')+' ('+m.qty+' × '+money(m.price)+')',Number(m.qty)*Number(m.price));}
 else item('Ricambi e materiali',q.parts);
 item('Manodopera ('+q.hours+' ore × '+money(q.rate)+')',q.hours*q.rate);
 item('Subtotale',t.net);item('IVA ('+q.vat+'%)',t.vat);
 ensure(95);line('TOTALE',M,y+48,35,true,'#087f85');font(35,true);const total=money(t.total);line(total,R-ctx.measureText(total).width,y+48,35,true,'#087f85');y+=95;rule();
 block('Preventivo indicativo, salvo conferma.',20,false,'#657b86');
 finish();
 const encoder=new TextEncoder();const chunks=[];let length=0;const offsets=[0];
 function push(bytes){if(typeof bytes==='string')bytes=encoder.encode(bytes);chunks.push(bytes);length+=bytes.length;}
 function obj(id,body){offsets[id]=length;push(id+' 0 obj\n'+body+'\nendobj\n');}
 push('%PDF-1.4\n');const n=pages.length,ids=[];
 for(let i=0;i<n;i++)ids.push(3+i*3);
 obj(1,'<< /Type /Catalog /Pages 2 0 R >>');
 obj(2,'<< /Type /Pages /Kids ['+ids.map(id=>id+' 0 R').join(' ')+'] /Count '+n+' >>');
 for(let i=0;i<n;i++){
  const id=ids[i],img=pages[i];
  obj(id,'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Resources << /XObject << /Im0 '+(id+1)+' 0 R >> >> /Contents '+(id+2)+' 0 R >>');
  offsets[id+1]=length;push((id+1)+' 0 obj\n<< /Type /XObject /Subtype /Image /Width '+W+' /Height '+H+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length '+img.length+' >>\nstream\n');push(img);push('\nendstream\nendobj\n');
  const cmd='q\n595.28 0 0 841.89 0 0 cm\n/Im0 Do\nQ\n';obj(id+2,'<< /Length '+encoder.encode(cmd).length+' >>\nstream\n'+cmd+'endstream');
 }
 const start=length;push('xref\n0 '+(3+n*3)+'\n0000000000 65535 f \n');for(let i=1;i<3+n*3;i++)push(String(offsets[i]).padStart(10,'0')+' 00000 n \n');
 push('trailer\n<< /Size '+(3+n*3)+' /Root 1 0 R >>\nstartxref\n'+start+'\n%%EOF');
 return new Blob(chunks,{type:'application/pdf'});
}
function printQuote(){
 const q=quoteDraft();
 if(!q.client||!q.desc)return alert('Compila prima cliente e descrizione.');
 if(!swissToDate(v('q_date')))return alert('Inserisci una data valida nel formato gg.mm.aaaa.');
 const t=quoteTotal(q);
 const logo=new URL('otm-logo.png',location.href).href;
 const printable='<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Preventivo OTM Garage</title><style>'+
 '@page{size:A4 portrait;margin:15mm}*{box-sizing:border-box}html,body{margin:0;padding:0;background:white;color:#152b3a;font:11pt Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}'+
 '.sheet{width:100%;max-width:180mm;margin:0 auto}.head{display:flex;align-items:center;gap:14px;padding-bottom:14px;border-bottom:3px solid #087f85}.logo{width:74px;height:74px;object-fit:contain}.brand{font-size:23pt;font-weight:900;color:#0b4053;letter-spacing:1px}.tag{font-size:9pt;color:#57717e;margin-top:4px}'+
 'h1{font-size:19pt;margin:24px 0 15px;color:#087f85}.meta{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:16px 0 25px}.meta>div{border:1px solid #d5e1e5;border-radius:7px;padding:12px;min-height:68px}.lab{font-size:8pt;color:#607887;text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px}.description{white-space:pre-wrap;overflow-wrap:anywhere;margin:14px 0 22px;line-height:1.6}'+
 'table{width:100%;border-collapse:collapse;margin:20px 0}th{background:#e9f4f4;color:#1d4e58;text-align:left;font-size:9pt;text-transform:uppercase}th,td{padding:12px 10px;border-bottom:1px solid #d9e4e7}td:last-child,th:last-child{text-align:right}.total td{font-size:15pt;font-weight:900;color:#087f85;border-top:2px solid #087f85}.foot{margin-top:40px;padding-top:14px;border-top:1px solid #d9e4e7;color:#657b86;font-size:9pt}'+
 '.print-tools{display:flex;gap:12px;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10;background:#10283a;color:white;padding:12px 16px;font:600 14px Arial,sans-serif}.print-tools button{border:1px solid #64cfcf;background:#1fdddd;color:#072c36;padding:12px 18px;border-radius:10px;font-weight:800;font-size:15px;cursor:pointer}.print-tools button.back{background:transparent;color:#e8ffff}.print-tools .note{font-size:11px;color:#c0e1e6}'+
 '@media screen{body{background:#e6edf0;padding:0 10px 24px}.sheet{background:white;width:100%;max-width:210mm;min-height:297mm;padding:clamp(12px,4vw,15mm);margin:12px auto;box-shadow:0 8px 35px #0002}table{table-layout:fixed}td,th{overflow-wrap:anywhere}}@media print{.print-tools{display:none!important}.sheet{max-width:none;min-height:0;padding:0}tr{break-inside:avoid}body{background:white!important}}'+
 '</style></head><body><nav class="print-tools"><button type="button" class="back" onclick="window.close()">← Torna all’app</button><span class="note">Stampa o salva PDF</span><button type="button" onclick="window.print()">🖨 Stampa A4</button></nav><p id="returnHelp" hidden style="padding:12px;text-align:center;color:#153e50">Se la finestra non si chiude, usa il pulsante schede di Safari e torna a OTM Garage.</p><main class="sheet"><header class="head"><img class="logo" src="'+logo+'" alt="Logo OTM Garage"><div><div class="brand">OTM GARAGE</div><div class="tag">La tua officina, sempre con te</div></div></header><h1>PREVENTIVO</h1>'+
 '<div class="meta"><div><div class="lab">Cliente</div><strong>'+e(q.client)+'</strong></div><div><div class="lab">Data e targa</div><strong>'+e(dateToSwiss(q.date||today()))+'</strong><div>'+e(q.plate||'—')+'</div></div></div>'+
 '<div class="lab">Intervento previsto</div><div class="description">'+e(q.desc)+'</div><p><strong>Stato:</strong> '+e(q.status)+' · <strong>Pagamento:</strong> '+e(q.payment)+' · <strong>Acconto:</strong> '+eur(q.deposit)+'</p>'+
 '<table><thead><tr><th>Descrizione</th><th>Importo CHF</th></tr></thead><tbody>'+
 ((q.materials||[]).length?q.materials.map(m=>'<tr><td>'+e(m.desc)+' ('+e(m.qty)+' × '+eur(m.price)+')</td><td>'+eur(m.qty*m.price)+'</td></tr>').join(''):'<tr><td>Ricambi e materiali</td><td>'+eur(q.parts)+'</td></tr>')+'<tr><td>Manodopera ('+e(q.hours)+' ore × '+eur(q.rate)+')</td><td>'+eur(q.hours*q.rate)+'</td></tr>'+
 '<tr><td>Subtotale</td><td>'+eur(t.net)+'</td></tr><tr><td>IVA ('+e(q.vat)+'%)</td><td>'+eur(t.vat)+'</td></tr><tr class="total"><td>TOTALE</td><td>'+eur(t.total)+'</td></tr></tbody></table>'+
 '<div class="foot">Preventivo indicativo, salvo conferma. Documento predisposto per stampa o salvataggio PDF in formato A4 verticale.</div></main></body></html>';
 // Anteprima A4 nella stessa scheda: evita popup bloccati da Safari.
 let overlay=document.getElementById('otmA4Overlay');
 if(!overlay){
  overlay=document.createElement('section');overlay.id='otmA4Overlay';document.body.appendChild(overlay);
  const css=document.createElement('style');css.id='otmA4Styles';
  css.textContent=`#otmA4Overlay{position:fixed;inset:0;z-index:99999;background:#dfe8ec;color:#172e3a;overflow:auto;padding:0 10px 24px;-webkit-overflow-scrolling:touch}#otmA4Overlay .a4bar{position:sticky;top:0;z-index:2;display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px;background:#10283a;padding:10px max(8px,env(safe-area-inset-right));box-shadow:0 3px 12px #0003}#otmA4Overlay .a4bar button{background:#17c7d3;color:#06242c;border:0;border-radius:8px;padding:10px 8px;font-weight:800;font-size:12px;flex:1 1 42%;min-width:0}#otmA4Overlay .sheet{box-sizing:border-box;background:white;color:#152b3a;width:100%;max-width:210mm;min-height:297mm;padding:clamp(12px,4vw,15mm);margin:12px auto;box-shadow:0 8px 30px #0002;font:clamp(10px,2.9vw,11pt) Arial,sans-serif;overflow-wrap:anywhere}#otmA4Overlay .head{display:flex;align-items:center;gap:10px;padding-bottom:12px;border-bottom:3px solid #087f85}#otmA4Overlay .logo{width:clamp(42px,13vw,74px);height:auto;object-fit:contain}#otmA4Overlay .brand{font-size:clamp(16px,5vw,23pt);font-weight:900;color:#0b4053}#otmA4Overlay .tag{font-size:clamp(9px,2.4vw,9pt);color:#57717e}#otmA4Overlay h1{font-size:clamp(17px,5vw,19pt);margin:18px 0 12px;color:#087f85}#otmA4Overlay .meta{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:12px 0 18px}#otmA4Overlay .meta>div{border:1px solid #d5e1e5;border-radius:7px;padding:8px;min-width:0}#otmA4Overlay .lab{font-size:9px;color:#607887;text-transform:uppercase;margin-bottom:6px}#otmA4Overlay .description{white-space:pre-wrap;overflow-wrap:anywhere;margin:12px 0 18px}#otmA4Overlay table{width:100%;border-collapse:collapse;margin:14px 0;table-layout:fixed}#otmA4Overlay th,#otmA4Overlay td{padding:9px 5px;border-bottom:1px solid #d9e4e7;overflow-wrap:anywhere}#otmA4Overlay th:last-child,#otmA4Overlay td:last-child{width:36%;text-align:right}#otmA4Overlay .total td{font-size:clamp(13px,3.8vw,15pt);font-weight:900;color:#087f85}#otmA4Overlay .foot{margin-top:28px;border-top:1px solid #d9e4e7;padding-top:12px;color:#657b86;font-size:10px}@media print{@page{size:A4 portrait;margin:0}html,body{background:white!important}body:has(#otmA4Overlay:not([hidden]))>*:not(#otmA4Overlay){display:none!important}#otmA4Overlay{position:static!important;inset:auto!important;overflow:visible!important;background:white!important;padding:0!important}#otmA4Overlay .a4bar{display:none!important}#otmA4Overlay .sheet{box-shadow:none!important;margin:0!important;width:210mm!important;max-width:none!important;min-height:297mm!important;padding:15mm!important;font:11pt Arial,sans-serif!important}#otmA4Overlay .brand{font-size:23pt!important}#otmA4Overlay h1{font-size:19pt!important}#otmA4Overlay tr{break-inside:avoid}}`;
  document.head.appendChild(css);
 }
 const parsed=new DOMParser().parseFromString(printable,'text/html');
 overlay.replaceChildren();
 const toolbar=document.createElement('nav');toolbar.className='a4bar';
 const back=document.createElement('button');back.textContent='← Torna al preventivo';back.onclick=()=>{overlay.hidden=true;overlay.style.display='none'};
 const shareDoc=document.createElement('button');shareDoc.textContent='↗ Condividi PDF';
 shareDoc.onclick=async()=>{
  shareDoc.disabled=true;shareDoc.textContent='Preparazione PDF…';
  try{
   const pdf=await createQuotePdf(q,t,logo);
   const filename='OTM-Preventivo-'+(q.date||today())+'.pdf';
   const file=new File([pdf],filename,{type:'application/pdf'});
   if(navigator.share && (!navigator.canShare || navigator.canShare({files:[file]}))){
    try{await navigator.share({files:[file],title:'Preventivo OTM Garage'});return;}
    catch(err){if(err && err.name==='AbortError')return;}
   }
   const url=URL.createObjectURL(pdf);const a=document.createElement('a');a.href=url;a.download=filename;
   document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
   alert('PDF salvato. Aprilo nell’app File per stamparlo o inviarlo tramite WhatsApp.');
  }catch(err){alert('Impossibile creare il PDF: '+(err?.message||err));}
  finally{shareDoc.disabled=false;shareDoc.textContent='↗ Condividi PDF';}
 };
 toolbar.append(back,shareDoc);overlay.append(toolbar,parsed.querySelector('.sheet'));
 overlay.hidden=false;overlay.style.display='block';overlay.scrollTop=0;

}
function reminderMessage(j,kind){
 const name=j.client||'cliente',plate=j.plate?' ('+j.plate+')':'';
 const message='Buongiorno '+name+', le ricordiamo la manutenzione della sua auto'+plate+' prevista per il '+j.nextService+'. Ci contatti per fissare un appuntamento.\n\nOTM Garage';
 const client=(db.clients||[]).find(c=>normalizeSearch(c.name)===normalizeSearch(name)&&(!j.plate||c.plate===j.plate))||(db.clients||[]).find(c=>normalizeSearch(c.name)===normalizeSearch(name));
 if(kind==='wa'){
  const phone=String(client?.phone||'').replace(/\D/g,'');
  if(!phone)return alert('Numero di telefono non disponibile nella scheda cliente.');
  window.open('https://wa.me/'+phone+'?text='+encodeURIComponent(message),'_blank');
 }else location.href='mailto:?subject='+encodeURIComponent('Promemoria manutenzione OTM Garage')+'&body='+encodeURIComponent(message);
}
function renderReminders(){
 const box=$('reminderItems');box.replaceChildren();
 const cutoff=new Date();cutoff.setDate(cutoff.getDate()+30);const soon=cutoff.toISOString().slice(0,10);
 const filter=$('reminderFilter')?.value||'all';
 const jobs=db.jobs.filter(j=>j.nextService&&(filter!=='due'||j.nextService<=soon)).sort((a,b)=>a.nextService.localeCompare(b.nextService));
 if(!jobs.length){box.textContent='Nessuna manutenzione in questa selezione.';return}
 for(const j of jobs){
  const card=document.createElement('div');card.className='card';
  const heading=document.createElement('strong');heading.textContent=(j.nextService<today()?'🔔 SCADUTO · ':j.nextService<=soon?'⏰ IN ARRIVO · ':'')+j.nextService+' · '+(j.client||'')+' · '+(j.plate||'')+(j.nextKm?' · '+j.nextKm+' km':'');
  const actions=document.createElement('div');actions.className='actions';
  for(const [label,fn] of [['Apri lavoro',()=>editJob(j.id)],['WhatsApp',()=>reminderMessage(j,'wa')],['Email',()=>reminderMessage(j,'mail')]]){
   const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent=label;b.onclick=fn;actions.append(b)
  }card.append(heading,actions);box.append(card);
 }
}
function renderStats(){
 const input=$('statsMonth');if(!input.value)input.value=today().slice(0,7);
 const jobs=db.jobs.filter(j=>String(j.date||'').startsWith(input.value));
 const total=jobs.reduce((a,j)=>a+(Number(j.total)||0),0);
 const paid=jobs.reduce((a,j)=>a+(j.payment==='Pagato'?(Number(j.total)||0):j.payment==='Acconto'?Math.min(Number(j.total)||0,Number(j.deposit)||0):0),0);
 const quotes=(db.quotes||[]).filter(q=>String(q.date||'').startsWith(input.value));
 const qt=quotes.reduce((a,q)=>a+quoteTotal(q).total,0);
 $('statsItems').innerHTML='<div class="card"><h3>Riepilogo '+e(input.value)+'</h3><p>Lavori registrati: <strong>'+jobs.length+'</strong></p><p>Valore lavori: <strong>'+eur(total)+'</strong></p><p>Incassi registrati sui lavori: <strong>'+eur(paid)+'</strong></p><p>Da incassare sui lavori: <strong>'+eur(Math.max(0,total-paid))+'</strong></p><p>Preventivi: <strong>'+quotes.length+'</strong> · '+eur(qt)+'</p><p class="muted">Preventivi e lavori sono separati per evitare doppi conteggi. Le cifre seguono la data del lavoro e gli stati di pagamento inseriti manualmente, non la data effettiva di incasso.</p></div>';
 const year=input.value.slice(0,4),rows=[];
 for(let m=1;m<=12;m++){const month=year+'-'+String(m).padStart(2,'0');const jj=db.jobs.filter(j=>String(j.date||'').startsWith(month));const value=jj.reduce((a,j)=>a+(Number(j.total)||0),0);rows.push({month,value})}
 const peak=Math.max(1,...rows.map(r=>r.value));
 const outer=$('statsYearItems');outer.replaceChildren();const card=document.createElement('div');card.className='card';
 const title=document.createElement('h3');title.textContent='Andamento lavori '+year;card.append(title);
 for(const r of rows){const line=document.createElement('div');line.style.cssText='display:flex;align-items:center;gap:9px;margin:7px 0';const month=document.createElement('span');month.style.width='32px';month.textContent=r.month.slice(5);const track=document.createElement('div');track.style.cssText='flex:1;height:12px;background:#243b49;border-radius:8px;overflow:hidden';const bar=document.createElement('div');bar.style.cssText='height:100%;background:#14b8b0;width:'+Math.round(100*r.value/peak)+'%';track.append(bar);const amount=document.createElement('span');amount.style.cssText='min-width:100px;text-align:right;font-size:12px';amount.textContent=eur(r.value);line.append(month,track,amount);card.append(line)}
 outer.append(card);
}
function contactClient(kind){const name=$('clientHistoryTitle').textContent.replace(/^Storico · /,'');const group=db.clients.filter(c=>normalizeSearch(c.name)===selectedHistoryClient);const car=group[0]||{};const plate=car.plate?' ('+car.plate+')':'';const msgs={ready:'la sua auto'+plate+' è pronta per il ritiro.',appointment:'le confermiamo il suo appuntamento presso OTM Garage.',quote:'il preventivo per la sua auto'+plate+' è pronto. Ci contatti per i dettagli.',service:'le ricordiamo che è il momento di programmare la manutenzione della sua auto'+plate+'.'};const msg='Buongiorno '+name+', '+msgs[v('contactTemplate')]+'\n\nOTM Garage';if(kind==='wa'){const phone=String(car.phone||'').replace(/[^\d+]/g,'').replace(/^00/,'+');if(!phone)return alert('Inserisci prima il numero di telefono nella scheda cliente.');window.open('https://wa.me/'+phone.replace(/\D/g,'')+'?text='+encodeURIComponent(msg),'_blank')}else{const mail=v('contactEmail').trim();location.href='mailto:'+encodeURIComponent(mail)+'?subject='+encodeURIComponent('OTM Garage')+'&body='+encodeURIComponent(msg)}}
