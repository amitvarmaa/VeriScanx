(function(){
  "use strict";
  if (!VeriScanx.requireAuth()) return;
  const user = VeriScanx.getUser();

  /* ---------- chrome: user info, admin nav, logout, clock ---------- */
  document.getElementById('sideUserName').textContent = user.name;
  document.getElementById('sideUserRole').textContent = user.role;
  document.getElementById('acctName').textContent = user.username + ' (' + user.role + ')';
  if (user.role === 'admin'){
    document.getElementById('adminSep').hidden = false;
    document.getElementById('navOfficers').hidden = false;
    document.getElementById('navBlacklist').hidden = false;
    document.getElementById('addRegistryBtn').hidden = false;
  }
  document.getElementById('logoutBtn').addEventListener('click', ()=>{
    VeriScanx.clearSession(); window.location.href = '/login.html';
  });
  function tick(){ document.getElementById('dashClock').textContent = new Date().toLocaleString(); }
  tick(); setInterval(tick, 1000);

  /* ---------- toast ---------- */
  const toastEl = document.getElementById('toast');
  let toastTimer;
  function toast(msg, isError){
    clearTimeout(toastTimer);
    toastEl.textContent = msg;
    toastEl.className = 'toast show' + (isError?' error':'');
    toastTimer = setTimeout(()=> toastEl.classList.remove('show'), 3200);
  }

  /* ---------- modal ---------- */
  const modalBackdrop = document.getElementById('modalBackdrop');
  const modalBody = document.getElementById('modalBody');
  function openModal(html){ modalBody.innerHTML = html; modalBackdrop.hidden = false; }
  function closeModal(){ modalBackdrop.hidden = true; modalBody.innerHTML = ''; }
  modalBackdrop.addEventListener('click', (e)=>{ if(e.target===modalBackdrop) closeModal(); });

  /* ---------- view routing ---------- */
  const views = ['dashboard','verify','scans','registry','officers','blacklist','account'];
  function setView(name){
    if (!views.includes(name)) name = 'dashboard';
    if ((name==='officers'||name==='blacklist') && user.role!=='admin') name = 'dashboard';
    views.forEach(v=>{ document.getElementById('view-'+v).hidden = (v!==name); });
    document.querySelectorAll('.side-link').forEach(b=> b.classList.toggle('active', b.dataset.view===name));
    if (name==='dashboard') loadDashboard();
    if (name==='scans') loadScans();
    if (name==='registry') { registryOffset = 0; loadRegistry(); }
    if (name==='officers') loadOfficers();
    if (name==='blacklist') loadBlacklist();
    window.location.hash = name;
  }
  document.querySelectorAll('.side-link[data-view]').forEach(b=>{
    b.addEventListener('click', ()=> setView(b.dataset.view));
  });
  window.addEventListener('hashchange', ()=> setView(window.location.hash.slice(1)));

  /* ---------- icons ---------- */
  const ICON = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l6 6L20 6"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 5l14 14M19 5L5 19"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2z" fill="none"/><path d="M12 9v5M12 17h.01"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
    edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L18 10l-4-4L4 16z"/></svg>'
  };
  const BAND_VAR = { Low:'--good', Medium:'--warning', High:'--serious', Critical:'--critical' };
  const BAND_SOFT_VAR = { Low:'--good-soft', Medium:'--warning-soft', High:'--serious-soft', Critical:'--critical-soft' };
  const DOC_TYPE_VAR = { "Passport":"--cat-1", "Visa":"--cat-2", "National ID":"--cat-3", "Driving Licence":"--cat-4" };
  function statusPill(band){
    const icon = band==='Low'?ICON.check : band==='Critical'?ICON.x : ICON.warn;
    return `<span class="pill" style="background:var(${BAND_SOFT_VAR[band]}); color:var(${BAND_VAR[band]});">${icon}${band}</span>`;
  }

  /* ================= DASHBOARD ================= */
  async function loadDashboard(){
    try{
      const stats = await VeriScanx.api('/api/stats');
      document.getElementById('statGrid').innerHTML = [
        ['Total scans today', stats.totalToday, stats.totalAll+' all-time'],
        ['Flagged (14d, high/critical)', stats.bandCounts.High+stats.bandCounts.Critical, stats.flagRate+'% of 14-day scans'],
        ['Avg. processing time', (stats.avgProcessingMs/1000).toFixed(1)+'s', 'target < 8s'],
        ['Active alerts (24h)', stats.activeAlerts, 'critical-band, awaiting review']
      ].map(([label,value,delta])=>`
        <div class="stat-card"><div class="label">${label}</div><div class="value tnum">${value}</div><div class="delta">${delta}</div></div>
      `).join('');
      VeriScanxCharts.renderVolume(document.getElementById('volumeChart'), stats.volume14);
      VeriScanxCharts.renderBand(document.getElementById('bandChart'), stats.bandCounts);
      VeriScanxCharts.renderReasons(document.getElementById('reasonList'), stats.topReasons);
    }catch(err){ toast(err.message, true); }
    loadIdentityGraph();
  }

  /* ================= IDENTITY GRAPH =================
     Connections/duplicates/conflicts across the real, persistent scan
     history (the last 100 scans, DB-backed and cross-officer — strictly
     more than the public demo's single-browser-session version). Built
     as a simple bipartite graph (identities on one side, document
     numbers on the other) so it renders deterministically with plain
     SVG and no graphing library. */
  function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  function buildIdentityGraph(scans){
    const rows = scans.filter(s=>s.docNumber);
    const identities = new Map(); // "name|dob" -> {key,name,dob,docs:Set}
    const docs = new Map();       // docNumber -> {key,docNumber,identities:Set}
    const edgeSet = new Set();
    rows.forEach(s=>{
      const idKey = `${(s.travelerName||'').toLowerCase()}|${s.dob||''}`;
      if(!identities.has(idKey)) identities.set(idKey, {key:idKey, name:s.travelerName||'Unnamed traveler', dob:s.dob, docs:new Set()});
      identities.get(idKey).docs.add(s.docNumber);
      if(!docs.has(s.docNumber)) docs.set(s.docNumber, {key:s.docNumber, docNumber:s.docNumber, identities:new Set()});
      docs.get(s.docNumber).identities.add(idKey);
      edgeSet.add(idKey+'::'+s.docNumber);
    });
    const edges = [...edgeSet].map(k=>{ const [idKey,docKey] = k.split('::'); return {idKey, docKey}; });
    const conflicts = [];
    docs.forEach(d=>{
      if(d.identities.size>1){
        const names = [...d.identities].map(k=>identities.get(k).name);
        conflicts.push(`Document ${d.docNumber} is linked to ${d.identities.size} different identities: ${names.join(', ')}`);
      }
    });
    identities.forEach(idn=>{
      if(idn.docs.size>1){
        conflicts.push(`${idn.name} is linked to ${idn.docs.size} different document numbers: ${[...idn.docs].join(', ')}`);
      }
    });
    return { identities:[...identities.values()], docs:[...docs.values()], edges, conflicts };
  }

  async function loadIdentityGraph(){
    const container = document.getElementById('identityGraph');
    const listPanel = document.getElementById('identityGraphConflictsPanel');
    const listEl = document.getElementById('identityGraphConflicts');
    if(!container) return;
    let scans;
    try{
      const data = await VeriScanx.api('/api/scans?limit=100');
      scans = data.items || [];
    }catch(err){
      container.innerHTML = `<p class="empty-note">Could not load scan history for the identity graph.</p>`;
      return;
    }
    const g = buildIdentityGraph(scans);
    if(!g.identities.length){
      container.innerHTML = '<p class="empty-note">No scans on record yet — run a few in Verify &amp; scan to build the identity graph.</p>';
      if(listPanel) listPanel.hidden = true;
      return;
    }
    const ROWH = 30, PADY = 14, W = 560;
    const H = PADY*2 + Math.max(g.identities.length, g.docs.length, 1)*ROWH;
    const idY = k => PADY + g.identities.findIndex(n=>n.key===k)*ROWH + ROWH/2;
    const docY = k => PADY + g.docs.findIndex(n=>n.key===k)*ROWH + ROWH/2;
    let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;" role="img" aria-label="Identity graph">`;
    g.edges.forEach(e=>{
      const idn = g.identities.find(n=>n.key===e.idKey);
      const doc = g.docs.find(n=>n.key===e.docKey);
      const conflict = doc.identities.size>1 || idn.docs.size>1;
      svg += `<line x1="180" y1="${idY(e.idKey)}" x2="406" y2="${docY(e.docKey)}" stroke="${conflict?'var(--critical)':'var(--grid-line)'}" stroke-width="${conflict?2:1.4}" stroke-dasharray="${conflict?'4,3':'none'}"/>`;
    });
    g.identities.forEach((n,i)=>{
      const y = PADY + i*ROWH + ROWH/2;
      const flagged = n.docs.size>1;
      svg += `<circle cx="14" cy="${y}" r="4.5" fill="${flagged?'var(--critical)':'var(--accent-strong)'}"/>`;
      svg += `<text x="26" y="${y+4}" font-size="11" font-family="var(--font-body)" fill="var(--ink-2)">${escapeHtml(n.name)} · ${n.dob||'—'}</text>`;
    });
    g.docs.forEach((d,i)=>{
      const y = PADY + i*ROWH + ROWH/2;
      const flagged = d.identities.size>1;
      svg += `<circle cx="412" cy="${y}" r="4.5" fill="${flagged?'var(--critical)':'var(--seq-500)'}"/>`;
      svg += `<text x="424" y="${y+4}" font-size="11" font-family="var(--font-mono)" fill="var(--ink-2)">${escapeHtml(d.docNumber)}</text>`;
    });
    svg += `</svg>`;
    container.innerHTML = svg;
    if(listPanel && listEl){
      listPanel.hidden = g.conflicts.length===0;
      listEl.innerHTML = g.conflicts.map(c=>`<div class="idgraph-conflict">⚠ ${escapeHtml(c)}</div>`).join('');
    }
  }

  /* ================= VERIFY & SCAN ================= */
  VeriScanxVerify.init({
    stageUpload: document.getElementById('verifyStage-upload'),
    stageProcessing: document.getElementById('verifyStage-processing'),
    stageResults: document.getElementById('verifyStage-results'),
    pipelineStepsEl: document.getElementById('pipelineSteps'),
    resultsGrid: document.getElementById('resultsGrid'),
    uploadZone: document.getElementById('uploadZone'),
    fileInput: document.getElementById('fileInput'),
    sampleCleanBtn: document.getElementById('sampleClean'),
    sampleFlaggedBtn: document.getElementById('sampleFlagged'),
    scanAnotherBtn: document.getElementById('scanAnother'),
    downloadReportBtn: document.getElementById('downloadReportBtn'),
    onSaved: ()=> { toast('Scan saved to database.'); loadIdentityGraph(); }
  });
  document.getElementById('goToLog').addEventListener('click', ()=> setView('scans'));

  /* ================= SCANS LOG ================= */
  let scanOffset = 0;
  const SCAN_LIMIT = 12;
  let scanDebounce;
  function scanFilters(){
    return { q: document.getElementById('scanSearch').value.trim(), band: document.getElementById('scanBandFilter').value, docType: document.getElementById('scanTypeFilter').value };
  }
  async function loadScans(){
    const f = scanFilters();
    const params = new URLSearchParams({ limit:SCAN_LIMIT, offset:scanOffset });
    if(f.q) params.set('q', f.q);
    if(f.band) params.set('band', f.band);
    if(f.docType) params.set('docType', f.docType);
    try{
      const data = await VeriScanx.api('/api/scans?'+params.toString());
      const isAdmin = user.role==='admin';
      document.getElementById('scanActionsHead').hidden = !isAdmin;
      document.getElementById('scansTbody').innerHTML = data.items.length ? data.items.map(s=>`
        <tr>
          <td class="mono tnum">${new Date(s.createdAt).toLocaleString()}</td>
          <td>${s.travelerName}</td>
          <td><span class="doc-tag"><span class="doc-dot" style="background:var(${DOC_TYPE_VAR[s.docType]||'--cat-5'})"></span>${s.docType||'—'}</span></td>
          <td>${s.nationality||'—'}</td>
          <td class="mono tnum">${s.riskScore}</td>
          <td>${statusPill(s.riskBand)}</td>
          <td class="mono">#${s.officerId||'—'}</td>
          ${isAdmin ? `<td><button class="icon-btn" data-del="${s.id}" title="Delete scan">${ICON.trash}</button></td>` : ''}
        </tr>`).join('') : `<tr><td colspan="8"><p class="empty-note">No scans match these filters.</p></td></tr>`;
      document.getElementById('scanPagerInfo').textContent = data.total ? `${scanOffset+1}–${Math.min(scanOffset+SCAN_LIMIT,data.total)} of ${data.total}` : '0 results';
      document.getElementById('scanPrev').disabled = scanOffset===0;
      document.getElementById('scanNext').disabled = scanOffset+SCAN_LIMIT>=data.total;
      document.querySelectorAll('[data-del]').forEach(btn=>{
        btn.addEventListener('click', async ()=>{
          if(!confirm('Delete this scan record?')) return;
          try{ await VeriScanx.api('/api/scans/'+btn.dataset.del, {method:'DELETE'}); toast('Scan deleted.'); loadScans(); }
          catch(err){ toast(err.message, true); }
        });
      });
    }catch(err){ toast(err.message, true); }
  }
  document.getElementById('scanSearch').addEventListener('input', ()=>{
    clearTimeout(scanDebounce); scanDebounce = setTimeout(()=>{ scanOffset=0; loadScans(); }, 300);
  });
  document.getElementById('scanBandFilter').addEventListener('change', ()=>{ scanOffset=0; loadScans(); });
  document.getElementById('scanTypeFilter').addEventListener('change', ()=>{ scanOffset=0; loadScans(); });
  document.getElementById('scanPrev').addEventListener('click', ()=>{ scanOffset=Math.max(0,scanOffset-SCAN_LIMIT); loadScans(); });
  document.getElementById('scanNext').addEventListener('click', ()=>{ scanOffset+=SCAN_LIMIT; loadScans(); });

  /* ================= OFFICERS (admin) ================= */
  async function loadOfficers(){
    try{
      const data = await VeriScanx.api('/api/officers');
      document.getElementById('officersTbody').innerHTML = data.items.map(o=>`
        <tr>
          <td>${o.name}</td>
          <td class="mono">${o.username}</td>
          <td style="text-transform:capitalize;">${o.role}</td>
          <td>${o.active ? '<span class="pill" style="background:var(--good-soft);color:var(--good);">'+ICON.check+'Active</span>' : '<span class="pill" style="background:var(--critical-soft);color:var(--critical);">'+ICON.x+'Disabled</span>'}</td>
          <td class="mono">${new Date(o.createdAt).toLocaleDateString()}</td>
          <td class="row-actions">
            <button class="icon-btn" data-edit="${o.id}" title="Edit">${ICON.edit}</button>
            ${o.id!==user.id ? `<button class="icon-btn" data-del="${o.id}" title="Delete">${ICON.trash}</button>` : ''}
          </td>
        </tr>`).join('');
      document.querySelectorAll('#officersTbody [data-edit]').forEach(btn=>{
        btn.addEventListener('click', ()=> openOfficerModal(data.items.find(o=>String(o.id)===btn.dataset.edit)));
      });
      document.querySelectorAll('#officersTbody [data-del]').forEach(btn=>{
        btn.addEventListener('click', async ()=>{
          if(!confirm('Delete this officer account?')) return;
          try{ await VeriScanx.api('/api/officers/'+btn.dataset.del, {method:'DELETE'}); toast('Officer removed.'); loadOfficers(); }
          catch(err){ toast(err.message, true); }
        });
      });
    }catch(err){ toast(err.message, true); }
  }
  document.getElementById('addOfficerBtn').addEventListener('click', ()=> openOfficerModal(null));
  function openOfficerModal(officer){
    const editing = !!officer;
    openModal(`
      <h3>${editing?'Edit officer':'Add officer'}</h3>
      <form class="modal-form" id="officerForm">
        <div class="field"><label>Full name</label><input id="ofName" required value="${editing?officer.name:''}"/></div>
        <div class="field"><label>Username</label><input id="ofUsername" required ${editing?'disabled':''} value="${editing?officer.username:''}"/></div>
        <div class="field"><label>Role</label>
          <select id="ofRole"><option value="officer" ${editing&&officer.role==='officer'?'selected':''}>Officer</option><option value="admin" ${editing&&officer.role==='admin'?'selected':''}>Admin</option></select>
        </div>
        <div class="field"><label>${editing?'New password (leave blank to keep)':'Password'}</label><input id="ofPassword" type="password" ${editing?'':'required'} minlength="6"/></div>
        ${editing ? `<div class="checkbox-row"><input type="checkbox" id="ofActive" ${officer.active?'checked':''}/><label for="ofActive">Account active</label></div>` : ''}
        <div class="modal-actions">
          <button type="button" class="btn btn-ghost btn-sm" id="modalCancel">Cancel</button>
          <button type="submit" class="btn btn-primary btn-sm">${editing?'Save changes':'Create officer'}</button>
        </div>
      </form>`);
    document.getElementById('modalCancel').addEventListener('click', closeModal);
    document.getElementById('officerForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const body = { name: document.getElementById('ofName').value.trim(), role: document.getElementById('ofRole').value };
      const pw = document.getElementById('ofPassword').value;
      if(pw) body.password = pw;
      try{
        if(editing){
          body.active = document.getElementById('ofActive').checked;
          await VeriScanx.api('/api/officers/'+officer.id, {method:'PATCH', body});
          toast('Officer updated.');
        } else {
          body.username = document.getElementById('ofUsername').value.trim();
          await VeriScanx.api('/api/officers', {method:'POST', body});
          toast('Officer created.');
        }
        closeModal(); loadOfficers();
      }catch(err){ toast(err.message, true); }
    });
  }

  /* ================= BLACKLIST (admin) ================= */
  async function loadBlacklist(){
    try{
      const data = await VeriScanx.api('/api/blacklist');
      document.getElementById('blacklistTbody').innerHTML = data.items.length ? data.items.map(b=>`
        <tr>
          <td class="mono">${b.docNumber}</td>
          <td>${b.reason||'—'}</td>
          <td class="mono">${new Date(b.createdAt).toLocaleDateString()}</td>
          <td><button class="icon-btn" data-del="${b.id}" title="Remove">${ICON.trash}</button></td>
        </tr>`).join('') : `<tr><td colspan="4"><p class="empty-note">Blacklist is empty.</p></td></tr>`;
      document.querySelectorAll('#blacklistTbody [data-del]').forEach(btn=>{
        btn.addEventListener('click', async ()=>{
          if(!confirm('Remove this entry from the blacklist?')) return;
          try{ await VeriScanx.api('/api/blacklist/'+btn.dataset.del, {method:'DELETE'}); toast('Entry removed.'); loadBlacklist(); }
          catch(err){ toast(err.message, true); }
        });
      });
    }catch(err){ toast(err.message, true); }
  }
  document.getElementById('addBlacklistBtn').addEventListener('click', ()=>{
    openModal(`
      <h3>Add blacklist entry</h3>
      <form class="modal-form" id="blForm">
        <div class="field"><label>Document number</label><input id="blDoc" required/></div>
        <div class="field"><label>Reason</label><input id="blReason" placeholder="e.g. Reported stolen"/></div>
        <div class="modal-actions">
          <button type="button" class="btn btn-ghost btn-sm" id="modalCancel">Cancel</button>
          <button type="submit" class="btn btn-primary btn-sm">Add entry</button>
        </div>
      </form>`);
    document.getElementById('modalCancel').addEventListener('click', closeModal);
    document.getElementById('blForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      try{
        await VeriScanx.api('/api/blacklist', {method:'POST', body:{ docNumber: document.getElementById('blDoc').value.trim(), reason: document.getElementById('blReason').value.trim() }});
        toast('Added to blacklist.'); closeModal(); loadBlacklist();
      }catch(err){ toast(err.message, true); }
    });
  });

  /* ================= NATIONAL REGISTRY ================= */
  let registryOffset = 0;
  const REGISTRY_LIMIT = 12;
  let registryDebounce;
  function genderPill(g){
    if (!g) return '<span style="color:var(--ink-3);">—</span>';
    return g;
  }
  async function loadRegistry(){
    const params = new URLSearchParams({ limit:REGISTRY_LIMIT, offset:registryOffset });
    const q = document.getElementById('registrySearch').value.trim();
    if (q) params.set('q', q);
    try{
      const data = await VeriScanx.api('/api/registry?'+params.toString());
      const isAdmin = user.role==='admin';
      document.getElementById('registryActionsHead').hidden = !isAdmin;
      document.getElementById('registryTbody').innerHTML = data.items.length ? data.items.map(r=>`
        <tr>
          <td>${r.photo ? `<img src="${r.photo}" alt="" style="width:32px;height:32px;border-radius:50%;object-fit:cover;display:block;">` : `<div style="width:32px;height:32px;border-radius:50%;background:var(--surface-2);"></div>`}</td>
          <td>${r.name}</td>
          <td class="mono">${r.docNumber}</td>
          <td>${genderPill(r.gender)}</td>
          <td>${[r.city, r.state].filter(Boolean).join(', ') || '—'}</td>
          <td class="mono tnum" style="font-size:11.5px;color:var(--ink-3);">${r.dob||'—'}</td>
          ${isAdmin ? `<td><button class="icon-btn" data-del="${r.id}" title="Remove record">${ICON.trash}</button></td>` : ''}
        </tr>`).join('') : `<tr><td colspan="7"><p class="empty-note">No registry records match.</p></td></tr>`;
      document.getElementById('registryPagerInfo').textContent = data.total ? `${registryOffset+1}–${Math.min(registryOffset+REGISTRY_LIMIT,data.total)} of ${data.total}` : '0 results';
      document.getElementById('registryPrev').disabled = registryOffset===0;
      document.getElementById('registryNext').disabled = registryOffset+REGISTRY_LIMIT>=data.total;
      document.querySelectorAll('#registryTbody [data-del]').forEach(btn=>{
        btn.addEventListener('click', async ()=>{
          if(!confirm('Remove this record from the national registry?')) return;
          try{ await VeriScanx.api('/api/registry/'+btn.dataset.del, {method:'DELETE'}); toast('Record removed.'); loadRegistry(); }
          catch(err){ toast(err.message, true); }
        });
      });
    }catch(err){ toast(err.message, true); }
  }
  document.getElementById('registrySearch').addEventListener('input', ()=>{
    clearTimeout(registryDebounce); registryDebounce = setTimeout(()=>{ registryOffset=0; loadRegistry(); }, 300);
  });
  document.getElementById('registryPrev').addEventListener('click', ()=>{ registryOffset=Math.max(0,registryOffset-REGISTRY_LIMIT); loadRegistry(); });
  document.getElementById('registryNext').addEventListener('click', ()=>{ registryOffset+=REGISTRY_LIMIT; loadRegistry(); });
  document.getElementById('addRegistryBtn').addEventListener('click', ()=> openRegistryModal());
  function openRegistryModal(){
    let photoDataUrl = '';
    openModal(`
      <h3>Add registry record</h3>
      <form class="modal-form" id="regForm">
        <div class="field"><label>Full name</label><input id="regName" required/></div>
        <div class="field"><label>Document number</label><input id="regDoc" required/></div>
        <div class="field"><label>Date of birth</label><input id="regDob" type="date"/></div>
        <div class="field"><label>Gender</label>
          <select id="regGender"><option value="">—</option><option>Male</option><option>Female</option><option>Other</option></select>
        </div>
        <div class="field"><label>City</label><input id="regCity"/></div>
        <div class="field"><label>State</label><input id="regState"/></div>
        <div class="field"><label>Photo (optional)</label><input id="regPhoto" type="file" accept="image/*"/></div>
        <div class="modal-actions">
          <button type="button" class="btn btn-ghost btn-sm" id="modalCancel">Cancel</button>
          <button type="submit" class="btn btn-primary btn-sm">Add record</button>
        </div>
      </form>`);
    document.getElementById('modalCancel').addEventListener('click', closeModal);
    document.getElementById('regPhoto').addEventListener('change', (e)=>{
      const file = e.target.files[0];
      if (!file) { photoDataUrl = ''; return; }
      const reader = new FileReader();
      reader.onload = ()=> { photoDataUrl = reader.result; };
      reader.readAsDataURL(file);
    });
    document.getElementById('regForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      try{
        await VeriScanx.api('/api/registry', {method:'POST', body:{
          name: document.getElementById('regName').value.trim(),
          docNumber: document.getElementById('regDoc').value.trim(),
          dob: document.getElementById('regDob').value || null,
          gender: document.getElementById('regGender').value || null,
          city: document.getElementById('regCity').value.trim() || null,
          state: document.getElementById('regState').value.trim() || null,
          photo: photoDataUrl || null
        }});
        toast('Registry record added.'); closeModal(); loadRegistry();
      }catch(err){ toast(err.message, true); }
    });
  }

  /* ================= ACCOUNT ================= */
  document.getElementById('pwForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    try{
      await VeriScanx.api('/api/auth/change-password', {method:'POST', body:{
        oldPassword: document.getElementById('pwOld').value, newPassword: document.getElementById('pwNew').value
      }});
      toast('Password updated.'); e.target.reset();
    }catch(err){ toast(err.message, true); }
  });

  /* ---------- boot ---------- */
  setView(window.location.hash.slice(1) || 'dashboard');
})();
