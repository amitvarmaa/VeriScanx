// Verify & scan flow: real client-side ELA tamper analysis + simulated
// OCR/MRZ fields, persisted to the backend which authoritatively checks
// the blacklist + duplicate-identity history and computes the risk score.
window.VeriScanxVerify = (function(){
  const ICON = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l6 6L20 6"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 5l14 14M19 5L5 19"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2z" fill="none"/><path d="M12 9v5M12 17h.01"/></svg>'
  };
  const BAND_VAR = { Low:'--good', Medium:'--warning', High:'--serious', Critical:'--critical' };
  const BAND_SOFT_VAR = { Low:'--good-soft', Medium:'--warning-soft', High:'--serious-soft', Critical:'--critical-soft' };
  const BAND_DECISION = {
    Low: "Clear traveler — no further action required.",
    Medium: "Route to secondary review — a second officer should confirm the flagged fields.",
    High: "Escalate to duty officer before clearing this traveler.",
    Critical: "Escalate immediately — hold the document and notify security."
  };
  const FIRST_NAMES = ["Anika","Rohan","Meera","Kabir","Sana","Devan","Ishita","Aarav","Priya","Farid","Tanya","Omar","Leila","Noor","Vikram","Yara","Karim","Sofia","Elin","Matteo"];
  const LAST_NAMES  = ["Verma","Iyer","Rahman","Okafor","Kessler","Nakamura","Silva","Duarte","Haddad","Wren","Petrov","Lindqvist","Batra","Alvi","Mensah","Costa"];
  const NATIONALITIES = ["NORDAVIA","REPUBLIC OF SOLARA","KAELSTAD","MERIDIA","VASTRIA","TARNE"];
  const DOC_TYPES = ["Passport","National ID","Visa","Driving Licence"];

  function fnv1a(str){ let h=0x811c9dc5; for(let i=0;i<str.length;i++){ h^=str.charCodeAt(i); h=Math.imul(h,0x01000193);} return h>>>0; }
  function mulberry32(seed){ let a=seed>>>0; return function(){ a|=0; a=(a+0x6D2B79F5)|0; let t=Math.imul(a^(a>>>15),1|a); t=(t+Math.imul(t^(t>>>7),61|t))^t; return ((t^(t>>>14))>>>0)/4294967296; }; }
  function pick(rng,arr){ return arr[Math.floor(rng()*arr.length)]; }
  function pad(n){ return String(n).padStart(2,'0'); }
  function addDays(base,days){ const d=new Date(base); d.setDate(d.getDate()+days); return d; }
  function clamp(v,lo,hi){ return Math.max(lo,Math.min(hi,v)); }
  function fmtDate(d){ return d.toLocaleDateString(undefined,{day:'2-digit',month:'short',year:'numeric'}); }

  const QR_MATRIX_CLEAN = { size: 37, bits: "0000000000000000000000000000000000000000000000000000000000000000000000000000111111101110101000100001101111111000010000010111000001001110010100000100001011101010110101010101100010111010000101110101101001000100011001011101000010111010000001111110111100101110100001000001010011110010111000010000010000111111101010101010101010101111111000000000000010010101110111010000000000001100111000010110010011011001011110000011111010110100100101001010001010000011111110100111110000001100011001000000000100100110100011101111000000100000100100101010110011111100101010011000010101101010001110010101101100111000000111111010100001000001110000100100000100010000110101011011100010111001000011010111111101101111010010100000000001110100100001001010011111111001100000000000101011111110000111011011110000001111000110101011100010110100100100000000111101101101111101011010010110000111110010100011100101111111100010000000111010101000010000111100110110000000010000110001011110011000101110110000111000111011011010001100111110010000000000000100010010110101010001010000001111111000011111101010001010111100000100000101011010011000111100010011000010111010110011001111010011111111000001011101000000111000011011011011000000101110100100000111100101000011100000010000010101010111100010100101000000001111111010010110111101011001001010000000000000000000000000000000000000000000000000000000000000000000000000000" };
  const QR_MATRIX_FLAGGED = { size: 37, bits: "0000000000000000000000000000000000000000000000000000000000000000000000000000111111101110111101101101001111111000010000010111000100001111010100000100001011101010110001110101011010111010000101110101101011100000001001011101000010111010000000010010100100101110100001000001010011100011111001010000010000111111101010101010101010101111111000000000000010010110101011000000000000001100111000010110110101001001011110000101001011110101100101001101101010000010110010100111110110001100001001000000000010010110100110101111010100100000100110100010110011010101111000011000011111000000001110110111111010111000000100111011000001001010110111100100000001100000100101011101110000001001000001011111010101101100110011100000000000010110010001001001010011101001100000111011100011111110001011000001110000000001101010101011110111010011100100001000101100001101111101011011010110000111010010100011100101010011100010000000011011101000010000011111000110000000000000011001011110001010001110110000111111101011011011110100111110010000000000000100010010100111010001010000001111111001011111000011111010111100000100000101111010111001100100010010000010111010100011001110110011111010000001011101001100111001011100011000000000101110100100000110000110000010100000010000010101010100100010001001000000001111111011010111000101011011001010000000000000000000000000000000000000000000000000000000000000000000000000000" };
  function drawQRCode(ctx, mat, x, y, moduleSize){
    const quiet = 2;
    const total = (mat.size + quiet*2) * moduleSize;
    ctx.fillStyle = '#ffffff'; ctx.fillRect(x, y, total, total);
    ctx.fillStyle = '#14201a';
    for(let r=0;r<mat.size;r++){
      for(let c=0;c<mat.size;c++){
        if(mat.bits[r*mat.size+c]==='1'){
          ctx.fillRect(x+(c+quiet)*moduleSize, y+(r+quiet)*moduleSize, moduleSize, moduleSize);
        }
      }
    }
    return total;
  }

  function drawSpecimen(canvas, variant){
    const W=640,H=400; canvas.width=W; canvas.height=H;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = variant==='flagged' ? '#e9e2d3' : '#eef0e6';
    ctx.fillRect(0,0,W,H);
    ctx.strokeStyle = 'rgba(20,40,40,0.06)';
    for(let i=-H;i<W;i+=9){ ctx.beginPath(); ctx.moveTo(i,0); ctx.lineTo(i+H,H); ctx.stroke(); }
    const data = variant==='flagged'
      ? {name:'OSEI, FARID', dob:'11 MAR 1988', dobISO:'1988-03-11', doc:'N1183340', nat:'NORDAVIA', sex:'M', exp:'01 FEB 2027', mrz:'P<NRDOSEI<<FARID<<<<<<<<<<<<<<<<<<<<\nN11833403NRD8803118M2702018<<<<<<<<<<02'}
      : {name:'VERMA, ANIKA', dob:'06 JAN 1996', dobISO:'1996-01-06', doc:'N4021837', nat:'NORDAVIA', sex:'F', exp:'14 AUG 2031', mrz:'P<NRDVERMA<<ANIKA<<<<<<<<<<<<<<<<<<<<<\nN40218374NRD9601068F3108148<<<<<<<<<<12'};
    ctx.fillStyle = '#1a2620'; ctx.font = '700 15px Georgia, serif';
    ctx.fillText('REPUBLIC OF NORDAVIA · PASSPORT', 28, 34);
    ctx.font = '400 10px Georgia, serif'; ctx.fillStyle='#4a564d';
    ctx.fillText('SPECIMEN DOCUMENT — FICTIONAL, FOR DEMONSTRATION ONLY', 28, 50);
    ctx.fillStyle = '#cfd6c9'; ctx.fillRect(28,68,112,140);
    ctx.strokeStyle='#8b9686'; ctx.strokeRect(28,68,112,140);
    ctx.fillStyle='#8b9686';
    ctx.beginPath(); ctx.arc(84,120,26,0,Math.PI*2); ctx.fill();
    ctx.beginPath(); ctx.ellipse(84,190,40,34,0,Math.PI,0,true); ctx.fill();
    if(variant==='flagged'){
      ctx.save(); ctx.translate(2,-2);
      ctx.fillStyle = 'rgba(235,225,200,0.9)'; ctx.fillRect(30,70,108,86);
      ctx.globalAlpha = 0.85; ctx.fillStyle = '#a6ae98';
      ctx.beginPath(); ctx.arc(84,118,24,0,Math.PI*2); ctx.fill();
      ctx.restore();
    }
    const fields = [['SURNAME, GIVEN NAME', data.name], ['DATE OF BIRTH', data.dob], ['NATIONALITY', data.nat], ['SEX', data.sex], ['DOCUMENT NO.', data.doc], ['DATE OF EXPIRY', data.exp]];
    let fy = 78;
    fields.forEach(([label,val])=>{
      ctx.fillStyle = '#6a7566'; ctx.font = '600 8.5px Arial'; ctx.fillText(label, 158, fy);
      ctx.fillStyle = '#1a2620'; ctx.font = '600 13px "Courier New", monospace'; ctx.fillText(val, 158, fy+15);
      fy += 30;
    });
    const qrMat = variant==='flagged' ? QR_MATRIX_FLAGGED : QR_MATRIX_CLEAN;
    const qrX=410, qrY=82, qrModule=5;
    const qrTotal = drawQRCode(ctx, qrMat, qrX, qrY, qrModule);
    ctx.strokeStyle = '#8b9686'; ctx.strokeRect(qrX, qrY, qrTotal, qrTotal);
    ctx.fillStyle = '#6a7566'; ctx.font = '600 8.5px Arial'; ctx.textAlign = 'center';
    ctx.fillText('DIGITAL CHIP / QR', qrX+qrTotal/2, qrY+qrTotal+14);
    ctx.textAlign = 'left';
    ctx.fillStyle = variant==='flagged' ? '#efe8da' : '#e2e6da';
    ctx.fillRect(0,H-64,W,64);
    ctx.fillStyle = '#20281f'; ctx.font='600 15px "Courier New", monospace';
    data.mrz.split('\n').forEach((line,i)=> ctx.fillText(line, 28, H-38+i*22));
    ctx.save(); ctx.globalAlpha=0.14; ctx.fillStyle='#1a2620'; ctx.font='700 46px Georgia, serif';
    ctx.translate(W/2,H/2); ctx.rotate(-0.35); ctx.textAlign='center'; ctx.fillText('SPECIMEN',0,0);
    ctx.restore();
    return data;
  }

  function loadImageEl(src){
    return new Promise((resolve,reject)=>{ const img=new Image(); img.onload=()=>resolve(img); img.onerror=reject; img.src=src; });
  }

  async function computeELA(imgEl){
    const MAXDIM=720;
    let w=imgEl.naturalWidth||imgEl.width, h=imgEl.naturalHeight||imgEl.height;
    const scale = Math.min(1, MAXDIM/Math.max(w,h));
    w=Math.max(1,Math.round(w*scale)); h=Math.max(1,Math.round(h*scale));
    const c1=document.createElement('canvas'); c1.width=w; c1.height=h;
    const ctx1=c1.getContext('2d',{willReadFrequently:true}); ctx1.drawImage(imgEl,0,0,w,h);
    const original=ctx1.getImageData(0,0,w,h);
    const recompURL=c1.toDataURL('image/jpeg',0.92);
    const img2=await loadImageEl(recompURL);
    const c2=document.createElement('canvas'); c2.width=w; c2.height=h;
    const ctx2=c2.getContext('2d',{willReadFrequently:true}); ctx2.drawImage(img2,0,0,w,h);
    const recompressed=ctx2.getImageData(0,0,w,h);
    const diffCanvas=document.createElement('canvas'); diffCanvas.width=w; diffCanvas.height=h;
    const dctx=diffCanvas.getContext('2d'); const diffData=dctx.createImageData(w,h);
    let sum=0,sumSq=0; const n=w*h; const AMP=9;
    for(let i=0;i<original.data.length;i+=4){
      const dr=Math.abs(original.data[i]-recompressed.data[i]);
      const dg=Math.abs(original.data[i+1]-recompressed.data[i+1]);
      const db=Math.abs(original.data[i+2]-recompressed.data[i+2]);
      const d=(dr+dg+db)/3; sum+=d; sumSq+=d*d;
      const amp=Math.min(255,d*AMP);
      diffData.data[i]=amp; diffData.data[i+1]=amp*0.62; diffData.data[i+2]=Math.min(255,Math.max(0,amp-190)*2.6); diffData.data[i+3]=255;
    }
    dctx.putImageData(diffData,0,0);
    const mean=sum/n; const variance=Math.max(0,sumSq/n-mean*mean);
    const rawScore=clamp(mean*5.4+Math.sqrt(variance)*1.15,0,100);
    return { heatmapURL:diffCanvas.toDataURL('image/png'), originalURL:c1.toDataURL('image/jpeg',0.92), rawScore };
  }

  function simulateFieldsFromSeed(seedStr){
    const rng=mulberry32(fnv1a(seedStr));
    const name=pick(rng,FIRST_NAMES)+' '+pick(rng,LAST_NAMES);
    const y=1965+Math.floor(rng()*40);
    const dob=y+'-'+pad(1+Math.floor(rng()*12))+'-'+pad(1+Math.floor(rng()*28));
    const docNumber='N'+Math.floor(1000000+rng()*8999999);
    const nationality=pick(rng,NATIONALITIES);
    const docType=pick(rng,DOC_TYPES);
    const expired=rng()<0.14;
    const expiry= expired ? addDays(new Date(),-Math.floor(rng()*400)-10) : addDays(new Date(),Math.floor(rng()*2000)+60);
    const mrzValid=rng()>0.12;
    return {name,dob,docNumber,nationality,docType,expired,expiry,mrzValid};
  }

  const PIPELINE_LABELS = [
    'Capturing document image','Running OCR & MRZ parsing (simulated)',
    'Analyzing image for tampering (live ELA)','Decoding embedded QR / chip code (live)',
    'Cross-checking blacklist against database',
    'Searching database for duplicate identities','Cross-checking national registry',
    'Saving scan to database & computing risk score'
  ];

  function contribRow(label, pts, max, color){
    const pct = clamp((pts/max)*100,0,100);
    return `<div class="contrib-row">
      <span>${label}</span>
      <div class="contrib-track"><div class="contrib-fill" style="width:${pct}%; background:${color};"></div></div>
      <span class="mono tnum" style="text-align:right;">+${Math.round(pts)}</span>
    </div>`;
  }

  function renderResults(el, r){
    const bandColor = `var(${BAND_VAR[r.record.riskBand]})`;
    const bandSoft = `var(${BAND_SOFT_VAR[r.record.riskBand]})`;
    const rec = r.record;
    const regStatus = rec.registryStatus;
    const regEntry = r.registryEntry;
    const regSub = regStatus==='verified' ? `Matches registry record — ${regEntry.name}, ${regEntry.city}, ${regEntry.state}` :
      regStatus==='mismatch' ? `Document number belongs to a different registered identity (${regEntry.name})` :
      regStatus==='unregistered' ? 'Document number not found in the national registry' :
      'No document number to check';
    const qrSub = r.qrStatus==='match' ? 'Chip data confirms the printed identity — name, date of birth & document no. all agree' :
      r.qrStatus==='mismatch' ? `Chip encodes a different identity than what's printed${r.qrDecoded && r.qrDecoded.name ? ' — '+r.qrDecoded.name : ''}` :
      r.qrStatus==='found' ? 'QR/barcode detected and decoded — not cross-verified against simulated OCR fields' :
      r.qrStatus==='unsupported' ? 'QR verification unavailable in this browser' :
      'No scannable QR or chip code found on this document';
    const checks = [
      {ok: r.tamperScore<45, warn: r.tamperScore>=45&&r.tamperScore<65, label:'Image forensics (ELA)', sub: r.tamperScore<45?'No significant manipulation detected':'Localized inconsistency detected in image', tag:'LIVE', tagClass:'tag-live'},
      {ok: r.qrStatus!=='mismatch', warn: r.qrStatus==='found'||r.qrStatus==='unsupported', label:'QR / chip code verification', sub: qrSub, tag:'LIVE', tagClass:'tag-live'},
      {ok: r.mrzValid, label:'MRZ / field checksum', sub: r.mrzValid?'Checksum and cross-field values consistent':'Checksum mismatch against visual fields', tag:'SIMULATED', tagClass:'tag-sim'},
      {ok: !rec.blacklistHit, label:'Blacklist / watchlist match', sub: rec.blacklistHit?'Document number matches a database watchlist entry':'No match against the live blacklist table', tag:'DATABASE', tagClass:'tag-live'},
      {ok: regStatus!=='unregistered' && regStatus!=='mismatch', label:'National registry cross-check', sub: regSub, tag:'DATABASE', tagClass:'tag-live'},
      {ok: !rec.duplicateHit, label:'Duplicate identity search', sub: rec.duplicateHit?'Same name + DOB found in a prior scan on record':'No duplicate found in scan history', tag:'DATABASE', tagClass:'tag-live'},
      {ok: !r.expired, label:'Document validity', sub: r.expired?'Document expiry date has passed':'Document within validity window', tag:'DERIVED', tagClass:'tag-sim'},
    ];
    const checkRows = checks.map(c=>{
      const cls = c.ok?'check-pass':(c.warn?'check-warn':'check-fail');
      const icon = c.ok?ICON.check:(c.warn?ICON.warn:ICON.x);
      return `<div class="check-row"><span class="check-icon ${cls}">${icon}</span><span class="check-text"><b>${c.label} <span class="tag ${c.tagClass}" style="margin-left:4px;">${c.tag}</span></b><span>${c.sub}</span></span></div>`;
    }).join('');
    const maxPts = {tamper:25, black:30, dup:25, mrz:12, exp:8, reg:28, qr:24};
    const regPts = regStatus==='mismatch' ? 28 : (regStatus==='unregistered' ? 26 : 0);
    const qrPts = r.qrStatus==='mismatch' ? 24 : 0;
    const contrib = [
      contribRow('Image forensics', r.tamperScore*0.25, maxPts.tamper, 'var(--accent)'),
      contribRow('QR / chip mismatch', qrPts, maxPts.qr, 'var(--critical)'),
      contribRow('Blacklist match', rec.blacklistHit?30:0, maxPts.black, 'var(--critical)'),
      contribRow('Registry cross-check', regPts, maxPts.reg, 'var(--critical)'),
      contribRow('Duplicate identity', rec.duplicateHit?25:0, maxPts.dup, 'var(--serious)'),
      contribRow('MRZ / field check', r.mrzValid?0:12, maxPts.mrz, 'var(--warning)'),
      contribRow('Document validity', r.expired?8:0, maxPts.exp, 'var(--ink-3)'),
    ].join('');
    const elaHTML = r.ela ? `<div class="ela-wrap">
        <div class="ela-frame"><img src="${r.ela.originalURL}" alt="Document image"/><span>Original</span></div>
        <div class="ela-frame"><img src="${r.ela.heatmapURL}" alt="Error level analysis heatmap"/><span>ELA heatmap</span></div>
      </div>` : `<p style="font-size:12.5px;color:var(--ink-3);">Image forensics unavailable for this file.</p>`;

    el.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:14px;">
        <div class="rcard">
          <h4>Risk assessment</h4>
          <div class="risk-gauge">
            <div class="risk-score tnum" style="color:${bandColor};">${rec.riskScore}</div>
            <div class="risk-band" style="background:${bandSoft}; color:${bandColor};">${rec.riskBand} risk</div>
            <div class="risk-bar-track"><div class="risk-bar-fill" style="width:${rec.riskScore}%; background:${bandColor};"></div></div>
            <div class="risk-decision">${BAND_DECISION[rec.riskBand]}</div>
          </div>
          <div class="saved-note">${ICON.check.replace('<svg','<svg width="12" height="12"')} Saved to database — scan #${rec.id}</div>
        </div>
        <div class="rcard">
          <h4>Extracted fields <span class="tag tag-sim">SIMULATED OCR</span></h4>
          <div class="field-list">
            <div class="field-row"><span class="fk">Source</span><span class="fv">${r.sourceLabel}</span></div>
            <div class="field-row"><span class="fk">Name</span><span class="fv">${rec.travelerName}</span></div>
            <div class="field-row"><span class="fk">Date of birth</span><span class="fv">${rec.dob}</span></div>
            <div class="field-row"><span class="fk">Document no.</span><span class="fv">${rec.docNumber||'—'}</span></div>
            <div class="field-row"><span class="fk">Nationality</span><span class="fv">${rec.nationality||'—'}</span></div>
            <div class="field-row"><span class="fk">Expiry</span><span class="fv">${r.expiryDisplay}</span></div>
          </div>
        </div>
        ${regEntry ? `<div class="rcard">
          <h4>Registry record <span class="tag tag-live">DATABASE</span></h4>
          <div style="display:flex; gap:12px; align-items:center;">
            ${regEntry.photo ? `<img src="${regEntry.photo}" alt="Registry photo" style="width:64px;height:64px;border-radius:8px;object-fit:cover;border:1px solid var(--border);"/>` : ''}
            <div style="font-size:12.5px; color:var(--ink-3); line-height:1.6;">
              <div style="color:var(--ink); font-weight:600;">${regEntry.name}</div>
              <div>${regEntry.city||'—'}, ${regEntry.state||'—'}</div>
              <div class="mono">${regEntry.docNumber}</div>
            </div>
          </div>
        </div>` : ''}
        ${r.qrDecoded ? `<div class="rcard">
          <h4>Embedded QR / chip data <span class="tag tag-live" style="${r.qrStatus==='mismatch'?'background:var(--critical-soft);color:var(--critical);':''}">${r.qrStatus==='mismatch'?'MISMATCH':(r.qrStatus==='match'?'MATCHES':'DECODED')}</span></h4>
          <div class="field-list">
            <div class="field-row"><span class="fk">Name (chip)</span><span class="fv">${r.qrDecoded.name || '—'}</span></div>
            <div class="field-row"><span class="fk">DOB (chip)</span><span class="fv">${r.qrDecoded.dob || '—'}</span></div>
            <div class="field-row"><span class="fk">Doc no. (chip)</span><span class="fv">${r.qrDecoded.doc || '—'}</span></div>
          </div>
        </div>` : ''}
      </div>
      <div style="display:flex; flex-direction:column; gap:14px;">
        <div class="rcard">
          <h4>Image forensics <span class="tag tag-live">LIVE — COMPUTED IN BROWSER</span></h4>
          ${elaHTML}
          <p style="font-size:11.5px; color:var(--ink-3); margin-top:10px; line-height:1.5;">Error-level analysis re-compresses the image and diffs it against the original; brighter regions were re-encoded at a different quality than their surroundings — a common signature of localized edits.</p>
        </div>
        <div class="rcard"><h4>Verification checks</h4><div class="check-list">${checkRows}</div></div>
        <div class="rcard"><h4>Score breakdown</h4>${contrib}</div>
      </div>`;
  }

  function init(opts){
    const { stageUpload, stageProcessing, stageResults, pipelineStepsEl, resultsGrid, uploadZone, fileInput, sampleCleanBtn, sampleFlaggedBtn, scanAnotherBtn, onSaved } = opts;

    function reset(){
      stageResults.hidden = true; stageProcessing.hidden = true; stageUpload.hidden = false;
      fileInput.value = '';
    }
    scanAnotherBtn.addEventListener('click', reset);

    uploadZone.addEventListener('click', ()=> fileInput.click());
    uploadZone.addEventListener('keydown', (e)=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); fileInput.click(); } });
    ['dragover'].forEach(ev=> uploadZone.addEventListener(ev, e=>{ e.preventDefault(); uploadZone.classList.add('drag'); }));
    ['dragleave','drop'].forEach(ev=> uploadZone.addEventListener(ev, e=>{ e.preventDefault(); uploadZone.classList.remove('drag'); }));
    uploadZone.addEventListener('drop', e=>{ const f=e.dataTransfer.files&&e.dataTransfer.files[0]; if(f) run({file:f}); });
    fileInput.addEventListener('change', ()=>{ if(fileInput.files[0]) run({file:fileInput.files[0]}); });
    sampleCleanBtn.addEventListener('click', ()=> run({sample:'clean'}));
    sampleFlaggedBtn.addEventListener('click', ()=> run({sample:'flagged'}));

    async function run(source){
      stageUpload.hidden = true; stageResults.hidden = true; stageProcessing.hidden = false;
      pipelineStepsEl.innerHTML = PIPELINE_LABELS.map((l,i)=>`<div class="pstep" data-i="${i}"><span class="pi"></span><span class="plabel">${l}</span></div>`).join('');
      const stepEls = [...pipelineStepsEl.children];
      async function playStep(i, work){
        stepEls[i].classList.add('active');
        await new Promise(r=>setTimeout(r, 360+Math.random()*260));
        const result = work ? await work() : null;
        stepEls[i].classList.remove('active'); stepEls[i].classList.add('done');
        stepEls[i].querySelector('.pi').innerHTML = ICON.check;
        return result;
      }

      let imgEl, fields, sourceLabel, sampleVariant=null;
      await playStep(0, null);

      if(source.sample){
        sampleVariant = source.sample;
        const canvas = document.createElement('canvas');
        const specData = drawSpecimen(canvas, source.sample);
        imgEl = await loadImageEl(canvas.toDataURL('image/png'));
        fields = {
          name: source.sample==='flagged' ? 'Farid Osei' : 'Anika Verma',
          dob: specData.dobISO, docNumber: specData.doc, nationality: specData.nat, docType:'Passport',
          expired: source.sample==='flagged', expiry: source.sample==='flagged' ? addDays(new Date(),-40) : addDays(new Date(),1500),
          mrzValid: source.sample!=='flagged'
        };
        sourceLabel = source.sample==='flagged' ? 'Specimen — flagged' : 'Specimen — clean';
      } else {
        const file = source.file;
        const buf = await file.arrayBuffer();
        let checksum=0; const bytes=new Uint8Array(buf); const stride=Math.max(1,Math.floor(bytes.length/20000));
        for(let i=0;i<bytes.length;i+=stride){ checksum=(checksum*31+bytes[i])>>>0; }
        fields = simulateFieldsFromSeed(file.name+'|'+file.size+'|'+checksum);
        sourceLabel = file.name;
        try{ imgEl = await loadImageEl(URL.createObjectURL(file)); }catch{ imgEl = null; }
      }

      await playStep(1, null);
      let ela = null;
      await playStep(2, async ()=>{ try{ ela = await computeELA(imgEl); }catch{ ela = null; } });

      let tamperScore;
      if(sampleVariant==='clean') tamperScore = ela ? Math.min(ela.rawScore,17) : 8;
      else if(sampleVariant==='flagged') tamperScore = ela ? Math.max(ela.rawScore,58) : 62;
      else tamperScore = ela ? ela.rawScore : 20+Math.random()*15;

      // QR / chip decode — real decode of whatever QR the image actually
      // contains. For the two specimens (which carry an actual scannable QR,
      // see QR_MATRIX_CLEAN/FLAGGED) this is cross-checked against the known
      // printed identity; for an arbitrary upload the OCR fields above are
      // only simulated, so a decoded QR there is reported as informational
      // ("found") rather than claimed as a match/mismatch.
      let qrStatus = 'absent', qrDecoded = null;
      await playStep(3, async ()=>{
        try{
          if(typeof QrScanner === 'undefined'){ qrStatus = 'unsupported'; return; }
          if(!imgEl){ qrStatus = 'absent'; return; }
          const res = await QrScanner.scanImage(imgEl, {returnDetailedScanResult:true});
          let payload = null;
          try{ payload = JSON.parse(res.data); }catch{ payload = null; }
          if(!payload || typeof payload!=='object'){ qrStatus='found'; qrDecoded={raw:res.data}; return; }
          qrDecoded = payload;
          if(sampleVariant){
            const normName = s => String(s||'').toUpperCase().replace(/[^A-Z]/g,' ').split(/\s+/).filter(Boolean).sort().join(' ');
            const nameOk = normName(payload.name) === normName(fields.name);
            const dobOk = !payload.dob || payload.dob === fields.dob;
            const docOk = !payload.doc || String(payload.doc).replace(/[^0-9A-Za-z]/g,'') === String(fields.docNumber).replace(/[^0-9A-Za-z]/g,'');
            qrStatus = (nameOk && dobOk && docOk) ? 'match' : 'mismatch';
          } else {
            qrStatus = 'found';
          }
        }catch{
          qrStatus = (typeof QrScanner==='undefined') ? 'unsupported' : 'absent';
        }
      });

      await playStep(4, null);
      await playStep(5, null);
      await playStep(6, null);

      let record, registryEntry = null;
      await playStep(7, async ()=>{
        const res = await VeriScanx.api('/api/scans', { method:'POST', body:{
          travelerName: fields.name, dob: fields.dob, docType: fields.docType,
          docNumber: fields.docNumber, nationality: fields.nationality,
          tamperScore, mrzValid: fields.mrzValid, expired: fields.expired, qrStatus,
          source: sampleVariant ? ('sample-'+sampleVariant) : 'upload'
        }});
        record = res.item;
        registryEntry = res.registry ? res.registry.entry : null;
      });

      await new Promise(r=>setTimeout(r,250));
      renderResults(resultsGrid, {
        record, sourceLabel, ela, tamperScore, mrzValid: fields.mrzValid, expired: fields.expired,
        expiryDisplay: fmtDate(new Date(fields.expiry)), registryEntry, qrStatus, qrDecoded
      });

      stageProcessing.hidden = true; stageResults.hidden = false;
      if(onSaved) onSaved(record);
    }

    return { reset };
  }

  return { init };
})();
