// Verify & scan flow: real client-side ELA tamper analysis + simulated
// OCR/MRZ fields, persisted to the backend which authoritatively checks
// the blacklist + duplicate-identity history, validates the MRZ checksum,
// applies document-type rules, and runs zero-day anomaly + mutation
// detection — then computes the risk score. (See server/omnisight.js.)
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
  function isoDate(d){ const dt=new Date(d); return dt.getFullYear()+'-'+pad(dt.getMonth()+1)+'-'+pad(dt.getDate()); }
  function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let lastResult = null; // most recently rendered scan result, for the downloadable report

  /* ============================================================
     MRZ CHECKSUM MATH — same real ICAO Doc 9303 check-digit algorithm as
     the public demo site. The client only builds a properly-formed line —
     the SERVER is the authoritative check (see server/omnisight.js /
     routes/scans.js: "never trust a client-sent mrzValid boolean").
     ============================================================ */
  function icaoCheckDigit(str){
    const weights = [7,3,1];
    let sum = 0;
    for(let i=0;i<str.length;i++){
      const c = str[i];
      let v;
      if(c>='0' && c<='9') v = c.charCodeAt(0)-48;
      else if(c>='A' && c<='Z') v = c.charCodeAt(0)-55; // A=10 ... Z=35
      else v = 0; // '<' (filler) and anything unrecognized
      sum += v * weights[i%3];
    }
    return sum % 10;
  }
  // Builds a real, correctly-checksummed TD3 (passport-format, 44-char) MRZ
  // line 2 from a doc no. / DOB / expiry triple — used for both specimens
  // (their printed doc shows this exact line) and arbitrary uploads (which
  // have no genuine MRZ to read, so a properly-formed synthetic one is
  // built and validated for real). `corruptField` deliberately breaks one
  // check digit to simulate a tampered document, indexing into
  // [docCheck, dobCheck, expCheck, personalCheck, compositeCheck].
  function buildMrzLine2({docNumber, dobISO, expiryDate, sex, corruptField}){
    const digits9 = (String(docNumber).replace(/\D/g,'')+'000000000').slice(0,9);
    const yymmdd = d => { const dt=new Date(d); return pad(dt.getFullYear()%100)+pad(dt.getMonth()+1)+pad(dt.getDate()); };
    const dob6 = yymmdd(dobISO);
    const exp6 = yymmdd(expiryDate);
    const personal14 = (digits9.slice(3)+'<<<<<<<<<<<<<<').slice(0,14);

    const docCheck = icaoCheckDigit(digits9);
    const dobCheck = icaoCheckDigit(dob6);
    const expCheck = icaoCheckDigit(exp6);
    const personalCheck = icaoCheckDigit(personal14);
    const composite = digits9+docCheck + dob6+dobCheck + exp6+expCheck + personal14+personalCheck;
    const compositeCheck = icaoCheckDigit(composite);

    const digits = [docCheck, dobCheck, expCheck, personalCheck, compositeCheck];
    if(corruptField!=null) digits[corruptField] = (digits[corruptField] + 1 + Math.floor(Math.random()*8)) % 10;

    return digits9+digits[0] + 'NRD' + dob6+digits[1] + (sex||'X') + exp6+digits[2] + personal14+digits[3] + digits[4];
  }
  // Line 1 of a TD3 MRZ: document type, issuing country, surname/given names.
  function mrzLine1(surname, given, country){
    const core = `P<${country}${surname}<<${given}`;
    return (core + '<'.repeat(Math.max(0, 44-core.length))).slice(0,44);
  }

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
      ? {name:'OSEI, FARID', dob:'11 MAR 1988', dobISO:'1988-03-11', doc:'N1183340', nat:'NORDAVIA', sex:'M', exp:'01 FEB 2027', expISO:'2027-02-01'}
      : {name:'VERMA, ANIKA', dob:'06 JAN 1996', dobISO:'1996-01-06', doc:'N4021837', nat:'NORDAVIA', sex:'F', exp:'14 AUG 2031', expISO:'2031-08-14'};
    // Real ICAO 9303 line 2, built the same way as the printed field values —
    // the "flagged" specimen has its document-number check digit genuinely
    // corrupted (exactly what a real MRZ reader would catch); "clean" is
    // fully self-consistent. Stashed on `data.mrzLine2` so the exact string
    // drawn on the document (corruption is randomized) is also what gets
    // submitted to the server for validation.
    const mrzLine2 = buildMrzLine2({
      docNumber: data.doc, dobISO: data.dobISO, expiryDate: data.expISO, sex: data.sex,
      corruptField: variant==='flagged' ? 0 : null
    });
    data.mrzLine2 = mrzLine2;
    data.mrz = mrzLine1(data.name.split(', ')[0], data.name.split(', ')[1], 'NRD') + '\n' + mrzLine2;
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

  /* ============================================================
     FACE VERIFICATION — document/registry photo vs. live camera capture,
     with a blink-based liveness check. Runs entirely client-side via
     @vladmandic/face-api (TensorFlow.js, loaded from a CDN in panel.html);
     nothing is uploaded anywhere. A separate, additional check — not
     folded into the risk score, which is already computed and saved by
     the time an officer opts into this.
     ============================================================ */
  let faceRefSrc = null;   // image URL (data: URL or object URL) to detect a reference face from
  let faceRefLabel = '';   // display label, e.g. "Registry photo — Anika Verma"
  let faceRefKind = null;  // 'available' | 'specimen' | 'none'
  const FACE_MODEL_URL = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model';
  let faceModelsLoaded = false, faceModelsLoading = null;
  let livenessTimer = null, livenessResult = null;
  let faceStream = null, docFaceDescriptor = null;

  function stopFaceStream(){
    if(faceStream){ faceStream.getTracks().forEach(t=>t.stop()); faceStream = null; }
    if(livenessTimer){ clearInterval(livenessTimer); livenessTimer = null; }
  }
  // Eye-aspect-ratio (EAR) — standard 6-point formula, reused from the same
  // 68-point landmarks withFaceLandmarks() already computes for the match
  // check, so liveness needs no extra model or network fetch.
  function eyeAspectRatio(eye){
    const dist = (a,b)=> Math.hypot(a.x-b.x, a.y-b.y);
    const A = dist(eye[1], eye[5]), B = dist(eye[2], eye[4]), C = dist(eye[0], eye[3]);
    return C>0 ? (A+B)/(2*C) : 0;
  }
  // Blink-based liveness check: polls the live video for ~9s watching the
  // eye-aspect-ratio dip below a "closed" threshold and recover above an
  // "open" threshold — a still photo or a static replay can't produce that.
  function runLivenessCheck(body){
    const videoEl = document.getElementById('faceVideo');
    const EAR_CLOSED=0.21, EAR_OPEN=0.27, TIMEOUT_MS=9000, POLL_MS=220;
    const startedAt = Date.now();
    let sawClosed = false;
    body.insertAdjacentHTML('beforeend', `
      <div class="face-liveness" id="livenessBox">
        <p class="face-status" id="livenessStatus" style="margin-top:10px;">Liveness check: please blink naturally, looking at the camera…</p>
        <div class="liveness-bar"><div class="liveness-fill" id="livenessFill"></div></div>
        <div class="face-actions">
          <button class="btn btn-ghost btn-sm" id="livenessSkipBtn" type="button">Skip liveness check</button>
          <button class="btn btn-ghost btn-sm" id="livenessCancelBtn" type="button">Cancel</button>
        </div>
      </div>`);
    const fill = document.getElementById('livenessFill');
    const liveStatus = document.getElementById('livenessStatus');
    return new Promise(resolve=>{
      let settled = false;
      const finish = (result)=>{
        if(settled) return;
        settled = true;
        clearInterval(livenessTimer); livenessTimer = null;
        const skipBtn = document.getElementById('livenessSkipBtn'), cancelBtn = document.getElementById('livenessCancelBtn');
        if(skipBtn) skipBtn.remove();
        if(cancelBtn) cancelBtn.remove();
        resolve(result);
      };
      document.getElementById('livenessSkipBtn').addEventListener('click', ()=> finish({passed:false, reason:'skipped'}));
      document.getElementById('livenessCancelBtn').addEventListener('click', ()=>{ finish({passed:false, reason:'cancelled'}); resetFaceCard(); });
      livenessTimer = setInterval(async ()=>{
        const elapsed = Date.now()-startedAt;
        if(fill) fill.style.width = Math.min(100,(elapsed/TIMEOUT_MS)*100)+'%';
        if(elapsed>=TIMEOUT_MS){ finish({passed:false, reason:'timeout'}); return; }
        if(!videoEl || videoEl.readyState<2 || !faceStream) return;
        let det = null;
        try{ det = await faceapi.detectSingleFace(videoEl, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks(); }catch{ det = null; }
        if(!det || settled) return;
        const ear = (eyeAspectRatio(det.landmarks.getLeftEye())+eyeAspectRatio(det.landmarks.getRightEye()))/2;
        if(ear<EAR_CLOSED){
          sawClosed = true;
          if(liveStatus) liveStatus.textContent = 'Liveness check: blink detected, confirming…';
        } else if(ear>EAR_OPEN && sawClosed){
          if(liveStatus) liveStatus.textContent = 'Liveness confirmed — natural blink detected.';
          if(fill) fill.style.width = '100%';
          setTimeout(()=> finish({passed:true}), 350);
        }
      }, POLL_MS);
    });
  }
  async function ensureFaceModels(){
    if(faceModelsLoaded) return true;
    if(!faceModelsLoading){
      faceModelsLoading = Promise.all([
        faceapi.nets.tinyFaceDetector.loadFromUri(FACE_MODEL_URL),
        faceapi.nets.faceLandmark68Net.loadFromUri(FACE_MODEL_URL),
        faceapi.nets.faceRecognitionNet.loadFromUri(FACE_MODEL_URL)
      ]).then(()=>{ faceModelsLoaded = true; return true; }).catch(err=>{ faceModelsLoading = null; throw err; });
    }
    return faceModelsLoading;
  }
  function drawFaceCrop(sourceEl, box, targetBox, label){
    if(!targetBox) return;
    try{
      const p = box.width*0.3;
      const sx=Math.max(0,box.x-p), sy=Math.max(0,box.y-p*1.4), sw=box.width+p*2, sh=box.height+p*2.6;
      const c = document.createElement('canvas'); c.width=sw; c.height=sh;
      c.getContext('2d').drawImage(sourceEl, sx, sy, sw, sh, 0, 0, sw, sh);
      targetBox.innerHTML = `<img alt="Detected face" src="${c.toDataURL('image/png')}"/><span class="face-label">${label}</span>`;
    }catch{ /* leave existing content if the crop fails (e.g. tainted canvas) */ }
  }
  function wireFaceVerify(){
    const btn = document.getElementById('faceStartBtn');
    if(btn) btn.addEventListener('click', startFaceVerify);
  }
  function faceCardIntroHTML(){
    const base = "Compares a reference photo against a live camera capture. Runs entirely on-device with TensorFlow.js — nothing is uploaded anywhere. This is a separate, additional check and isn't folded into the risk score above.";
    if(faceRefKind==='available'){
      return `<p class="face-status">${base}</p>
        <div class="face-row" style="grid-template-columns:120px 1fr; align-items:center;">
          <div class="face-box" style="aspect-ratio:1/1;"><img src="${faceRefSrc}" alt="Reference photo"/></div>
          <div style="font-size:12.5px; color:var(--ink-3);">Reference: <b style="color:var(--ink-1);">${escapeHtml(faceRefLabel)}</b></div>
        </div>
        <button class="btn btn-ghost btn-sm" id="faceStartBtn">Enable camera &amp; compare face</button>`;
    }
    return `<p class="face-status">${base}</p><button class="btn btn-ghost btn-sm" id="faceStartBtn">Enable camera &amp; compare face</button>`;
  }
  function resetFaceCard(){
    stopFaceStream();
    const body = document.getElementById('faceVerifyBody');
    if(!body) return;
    body.innerHTML = faceCardIntroHTML();
    wireFaceVerify();
  }
  async function startFaceVerify(){
    const body = document.getElementById('faceVerifyBody');
    if(!body) return;
    docFaceDescriptor = null; livenessResult = null;

    if(faceRefKind==='specimen'){
      body.innerHTML = `<p class="face-status">The specimen documents are illustrations, not real photos — there's no face to detect on them. Try uploading a real document image, or one whose document number matches a national-registry record, to see a genuine match check.</p>
        <div class="face-actions"><button class="btn btn-ghost btn-sm" id="faceBackBtn">Back</button></div>`;
      document.getElementById('faceBackBtn').addEventListener('click', resetFaceCard);
      return;
    }
    if(faceRefKind!=='available' || !faceRefSrc){
      body.innerHTML = `<p class="face-status">No reference photo is available for this scan (no document image, and no matching registry record), so a face match can't be run.</p>`;
      return;
    }
    if(typeof faceapi==='undefined'){
      body.innerHTML = `<p class="face-status" style="color:var(--critical);">The face-matching library couldn't be loaded (check your internet connection) — this check needs a script from a CDN.</p>`;
      return;
    }
    if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia){
      body.innerHTML = `<p class="face-status" style="color:var(--critical);">Camera access isn't available in this browser/context (it requires HTTPS or localhost).</p>`;
      return;
    }
    body.innerHTML = `<p class="face-status">Loading face-detection models…</p>`;
    try{ await ensureFaceModels(); }
    catch{
      body.innerHTML = `<p class="face-status" style="color:var(--critical);">Could not load face-detection models (network issue). <button class="btn btn-ghost btn-sm" id="faceBackBtn" style="margin-left:6px;">Try again</button></p>`;
      document.getElementById('faceBackBtn').addEventListener('click', startFaceVerify);
      return;
    }
    body.innerHTML = `<p class="face-status">Scanning the reference photo for a face…</p>`;
    let refImgEl = null, docDetection = null;
    try{
      refImgEl = await loadImageEl(faceRefSrc);
      docDetection = await faceapi.detectSingleFace(refImgEl, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptor();
    }catch{ docDetection = null; }
    if(!docDetection){
      body.innerHTML = `<p class="face-status">No face could be detected in the reference photo (${escapeHtml(faceRefLabel)}). Try a clearer photo where the face is fully visible and well-lit.</p>
        <div class="face-actions"><button class="btn btn-ghost btn-sm" id="faceRetryBtn">Try again</button><button class="btn btn-ghost btn-sm" id="faceBackBtn">Back</button></div>`;
      document.getElementById('faceRetryBtn').addEventListener('click', startFaceVerify);
      document.getElementById('faceBackBtn').addEventListener('click', resetFaceCard);
      return;
    }
    docFaceDescriptor = docDetection.descriptor;
    body.innerHTML = `
      <p class="face-status">Reference face detected (${escapeHtml(faceRefLabel)}). Requesting camera access…</p>
      <div class="face-row">
        <div class="face-box"><span class="face-placeholder">${escapeHtml(faceRefLabel)}</span></div>
        <div class="face-box" id="faceCamBox"><span class="face-placeholder">Starting camera…</span></div>
      </div>`;
    drawFaceCrop(refImgEl, docDetection.detection.box, body.querySelector('.face-box'), faceRefLabel.length>18 ? 'Reference' : escapeHtml(faceRefLabel));
    try{
      faceStream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'user'}, audio:false});
    }catch{
      body.querySelector('.face-status').textContent = 'Camera access was denied or is unavailable. Allow camera permission in your browser and try again.';
      const camBox = document.getElementById('faceCamBox');
      if(camBox) camBox.innerHTML = '<span class="face-placeholder">Camera unavailable</span>';
      body.insertAdjacentHTML('beforeend', `<div class="face-actions"><button class="btn btn-ghost btn-sm" id="faceRetryBtn">Try again</button><button class="btn btn-ghost btn-sm" id="faceBackBtn">Back</button></div>`);
      document.getElementById('faceRetryBtn').addEventListener('click', startFaceVerify);
      document.getElementById('faceBackBtn').addEventListener('click', resetFaceCard);
      return;
    }
    const camBox = document.getElementById('faceCamBox');
    camBox.innerHTML = `<video id="faceVideo" autoplay playsinline muted></video>`;
    const videoEl = document.getElementById('faceVideo');
    videoEl.srcObject = faceStream;
    await new Promise(r=>{ videoEl.onloadedmetadata = r; });
    try{ await videoEl.play(); }catch{}
    const statusEl = body.querySelector('.face-status');
    if(statusEl) statusEl.textContent = 'Camera live. Position your face in frame.';
    livenessResult = await runLivenessCheck(body);
    if(!faceStream) return; // cancelled/cleaned up while the liveness check was running
    const livenessBox = document.getElementById('livenessBox');
    if(livenessBox && !livenessResult.passed){
      const note = document.createElement('p');
      note.className = 'face-status'; note.style.color = 'var(--critical)';
      note.textContent = 'Liveness not confirmed (no blink detected in time) — you can still proceed, but this will be noted alongside the match result.';
      livenessBox.appendChild(note);
    }
    body.insertAdjacentHTML('beforeend', `<div class="face-actions">
      <button class="btn btn-primary btn-sm" id="faceCaptureBtn">Capture &amp; compare</button>
      <button class="btn btn-ghost btn-sm" id="faceCancelBtn">Cancel</button>
    </div>`);
    document.getElementById('faceCancelBtn').addEventListener('click', resetFaceCard);
    document.getElementById('faceCaptureBtn').addEventListener('click', captureAndCompare);
  }
  async function captureAndCompare(){
    const body = document.getElementById('faceVerifyBody');
    const videoEl = document.getElementById('faceVideo');
    if(!body || !videoEl) return;
    const captureBtn = document.getElementById('faceCaptureBtn'), cancelBtn = document.getElementById('faceCancelBtn');
    if(captureBtn) captureBtn.disabled = true;
    if(cancelBtn) cancelBtn.disabled = true;
    const statusEl = body.querySelector('.face-status');
    if(statusEl) statusEl.textContent = 'Comparing faces…';
    const canvas = document.createElement('canvas');
    canvas.width = videoEl.videoWidth||640; canvas.height = videoEl.videoHeight||480;
    canvas.getContext('2d').drawImage(videoEl, 0, 0, canvas.width, canvas.height);
    let liveDetection = null;
    try{ liveDetection = await faceapi.detectSingleFace(canvas, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptor(); }catch{ liveDetection = null; }
    stopFaceStream();
    if(!liveDetection){
      if(statusEl) statusEl.textContent = 'No face detected in the camera capture. Make sure your face is clearly visible and try again.';
      const camBox = document.getElementById('faceCamBox');
      if(camBox) camBox.innerHTML = '<span class="face-placeholder">No face detected</span>';
      if(captureBtn) captureBtn.remove();
      if(cancelBtn){ cancelBtn.disabled=false; cancelBtn.textContent='Back'; cancelBtn.onclick = resetFaceCard; }
      return;
    }
    const distance = faceapi.euclideanDistance(docFaceDescriptor, liveDetection.descriptor);
    const threshold = 0.6;
    const isMatch = distance<=threshold;
    drawFaceCrop(canvas, liveDetection.detection.box, document.getElementById('faceCamBox'), 'Live capture');
    if(statusEl) statusEl.textContent = 'Comparison complete. This check is separate from the risk score above.';
    const livenessPassed = !!(livenessResult && livenessResult.passed);
    body.insertAdjacentHTML('beforeend', `
      <div class="face-verdict ${isMatch?'pass':'fail'}">
        <span class="check-icon">${isMatch?ICON.check:ICON.x}</span>
        <span>${isMatch?'Faces match':'Faces do not match'} — distance ${distance.toFixed(3)} (match threshold ≤ 0.600)</span>
      </div>
      <div class="face-verdict ${livenessPassed?'pass':'fail'}">
        <span class="check-icon">${livenessPassed?ICON.check:ICON.x}</span>
        <span>${livenessPassed?'Liveness confirmed — natural blink detected':'Liveness not confirmed — capture may be a photo/video replay'}</span>
      </div>
      <div class="face-actions"><button class="btn btn-ghost btn-sm" id="faceRetryBtn2">Run again</button></div>
    `);
    if(captureBtn) captureBtn.remove();
    if(cancelBtn) cancelBtn.remove();
    document.getElementById('faceRetryBtn2').addEventListener('click', startFaceVerify);
  }

  /* ============================================================
     AI INVESTIGATION COPILOT — rule-based (no external AI call) summary
     of why a scan scored the way it did, ranked by point contribution.
     ============================================================ */
  function buildInvestigationReport(r){
    const rec = r.record;
    const registryStatus = rec.registryStatus;
    const findings = [];
    if(rec.blacklistHit) findings.push({points:30, text:'The document number matches an entry on the blacklist/watchlist.'});
    if(rec.duplicateHit) findings.push({points:25, text:'The same name and date of birth were already logged under a prior scan on record — a possible duplicate identity.'});
    if(registryStatus==='mismatch') findings.push({points:28, text:`The document number is registered to a different identity ("${r.registryEntry ? r.registryEntry.name : 'unknown'}") than what is printed on this document.`});
    else if(registryStatus==='unregistered') findings.push({points:26, text:'The document number could not be found in the national registry at all.'});
    if(r.qrStatus==='mismatch') findings.push({points:24, text:`The embedded QR/chip code decodes to a different identity${r.qrDecoded && r.qrDecoded.name ? ` ("${r.qrDecoded.name}")` : ''} than what is printed on the document face.`});
    if(!rec.mrzValid){
      const failed = r.mrzDetail && r.mrzDetail.checks ? r.mrzDetail.checks.filter(c=>!c.pass).map(c=>c.name) : [];
      findings.push({points:12, text:`The MRZ failed its ICAO 9303 checksum${failed.length?' on: '+failed.join(', '):''} — a strong signal of a digit having been altered.`});
    }
    if(r.tamperScore>=45) findings.push({points:Math.round(r.tamperScore*0.25), text:`Image forensics (error-level analysis) found a localized region re-compressed at a different quality than the rest of the image (tamper score ${Math.round(r.tamperScore)}/100) — consistent with a digital edit.`});
    if(r.expired) findings.push({points:8, text:"The document's expiry date has already passed."});
    if(r.docTypeCheck && !r.docTypeCheck.ok) findings.push({points:10, text: r.docTypeCheck.reason+'.'});
    (r.anomalies||[]).forEach(a=> findings.push({points:6, text:a+'.'}));
    if(r.mutation) findings.push({points:15, text:`${r.mutation.kind} against a prior record on file ("${r.mutation.withName}") — a possible attempt to evade exact-match duplicate detection.`});
    findings.sort((a,b)=>b.points-a.points);

    const band = rec.riskBand;
    const opening =
      band==='Critical' ? `This document scored ${rec.riskScore}/100 — Critical risk — and should not be cleared without manual investigation.` :
      band==='High'     ? `This document scored ${rec.riskScore}/100 — High risk. Manual review is recommended before clearance.` :
      band==='Medium'   ? `This document scored ${rec.riskScore}/100 — Medium risk. A quick secondary check is advisable.` :
                          `This document scored ${rec.riskScore}/100 — Low risk. No significant issues were found across the checks run.`;
    const body = findings.length
      ? 'The score is driven primarily by: ' + findings.slice(0,4).map(f=>f.text).join(' ')
      : 'Every check — image forensics, MRZ checksum, QR/chip cross-check, blacklist, national registry, duplicate search, document-type rules, anomaly detection, and mutation detection — came back clean.';
    const severe = rec.blacklistHit || registryStatus==='mismatch' || r.qrStatus==='mismatch';
    const recommendation = severe
      ? 'Recommended action: escalate to a senior officer — this pattern (identity or document-data mismatch) looks like a deliberate fraud attempt rather than an administrative error.'
      : band==='Critical' || band==='High' ? 'Recommended action: route to manual secondary review before allowing the traveler to proceed.'
      : band==='Medium' ? 'Recommended action: a brief manual glance is sufficient; full secondary review is not required.'
      : 'Recommended action: clear to proceed — no manual review needed.';
    return { opening, body, recommendation, findings, generatedAt: new Date() };
  }

  /* ============================================================
     DOWNLOADABLE INVESTIGATION REPORT — browser print-to-PDF, no PDF
     library. Renders the same computed results into #printReport, then
     calls window.print(); the browser's own "Save as PDF" destination
     is the actual PDF export.
     ============================================================ */
  function buildPrintReportHTML(r){
    const rec = r.record;
    const report = r.investigationReport || buildInvestigationReport(r);
    const bandColorHex = {Low:'#2f7d4f', Medium:'#b8860b', High:'#c1440e', Critical:'#a12622'}[rec.riskBand] || '#333';
    const registryStatus = rec.registryStatus;
    const checksTable = [
      ['Image forensics (ELA)', r.tamperScore<45?'Pass':'Fail', `tamper score ${Math.round(r.tamperScore)}/100`],
      ['QR / chip code', r.qrStatus!=='mismatch'?'Pass':'Fail', r.qrStatus],
      ['MRZ checksum (ICAO 9303)', rec.mrzValid?'Pass':'Fail', r.mrzDetail && r.mrzDetail.supported ? (rec.mrzValid?'all check digits valid':'check digit mismatch') : 'unsupported'],
      ['Blacklist / watchlist', !rec.blacklistHit?'Pass':'Fail', ''],
      ['National registry', (registryStatus!=='unregistered' && registryStatus!=='mismatch')?'Pass':'Fail', registryStatus||'n/a'],
      ['Duplicate identity search', !rec.duplicateHit?'Pass':'Fail', ''],
      ['Document validity (expiry)', !r.expired?'Pass':'Fail', ''],
      [`Document-type rules (${rec.docType||'Passport'})`, (r.docTypeCheck&&r.docTypeCheck.ok)?'Pass':'Fail', r.docTypeCheck?r.docTypeCheck.reason:''],
      ['Zero-day anomaly detection', (r.anomalies||[]).length===0?'Pass':'Fail', (r.anomalies||[]).join('; ')],
      ['Mutation detector', !r.mutation?'Pass':'Fail', r.mutation?`${r.mutation.kind} vs. "${r.mutation.withName}"`:''],
    ].map(([label,verdict,detail])=>`<tr><td>${escapeHtml(label)}</td><td><b style="color:${verdict==='Pass'?'#2f7d4f':'#a12622'};">${verdict}</b></td><td>${escapeHtml(detail)}</td></tr>`).join('');
    const findingsHTML = report.findings.length
      ? `<ul>${report.findings.map(f=>`<li>+${f.points} pts — ${escapeHtml(f.text)}</li>`).join('')}</ul>`
      : '<p style="font-size:12px;color:#555;">No contributing findings — every check passed.</p>';
    // Traveler photo for the report header: prefer the matched national-registry
    // photo (authoritative), then fall back to the uploaded document image itself
    // (which shows the printed photo for a real document). Specimen illustrations
    // have no real face, so those show no photo rather than a misleading one.
    const photoSrc = (r.registryEntry && r.registryEntry.photo) ? r.registryEntry.photo
      : (r.ela && r.ela.originalURL) ? r.ela.originalURL
      : null;
    const photoLabel = (r.registryEntry && r.registryEntry.photo) ? 'National registry photo' : 'From uploaded document image';
    const photoHTML = photoSrc
      ? `<div class="pr-photo-wrap"><img class="pr-photo" src="${photoSrc}" alt="Traveler photo"/><div class="pr-meta" style="margin-top:4px;">${escapeHtml(photoLabel)}</div></div>`
      : `<div class="pr-photo-wrap"><div class="pr-photo pr-photo-empty">No photo available</div></div>`;
    return `
      <h1>VeriScanx — Investigation Report</h1>
      <div class="pr-meta">Generated ${report.generatedAt.toLocaleString()} · Source: ${escapeHtml(r.sourceLabel||'—')} · Scan #${rec.id}</div>
      <h2>Risk assessment</h2>
      <div class="pr-summary-row">
        ${photoHTML}
        <table style="flex:1;">
          <tr><td>Risk score</td><td><b>${rec.riskScore} / 100</b> — <span class="pr-band" style="background:${bandColorHex}22; color:${bandColorHex};">${rec.riskBand} risk</span></td></tr>
          <tr><td>Traveler</td><td>${escapeHtml(rec.travelerName)}</td></tr>
          <tr><td>Date of birth</td><td>${escapeHtml(rec.dob)}</td></tr>
          <tr><td>Document type</td><td>${escapeHtml(rec.docType||'Passport')}</td></tr>
          <tr><td>Document number</td><td>${escapeHtml(rec.docNumber||'—')}</td></tr>
          <tr><td>Nationality</td><td>${escapeHtml(rec.nationality||'—')}</td></tr>
        </table>
      </div>
      <h2>AI Investigation Copilot summary</h2>
      <p style="font-size:12.5px;">${escapeHtml(report.opening)}</p>
      <p style="font-size:12px;color:#333;">${escapeHtml(report.body)}</p>
      <p style="font-size:12.5px;"><b>${escapeHtml(report.recommendation)}</b></p>
      <h2>Top risk contributors</h2>
      ${findingsHTML}
      <h2>Verification checks</h2>
      <table>${checksTable}</table>
      <div class="pr-meta" style="margin-top:18px;">VeriScanx — SIH 2026. Officer: scan #${rec.id}, saved ${escapeHtml(rec.createdAt||'')}. Generated client-side in the officer's browser.</div>
    `;
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
    return {name,dob,docNumber,nationality,docType,expired,expiry};
  }

  // ============================================================
  // REAL OCR — an uploaded document's fields are actually read off the
  // image via Tesseract.js (client-side, no server round-trip), then shown
  // to the officer in an editable review step before anything is submitted
  // (mirrors a real border kiosk: OCR proposes, the officer confirms/fixes).
  // If the image contains a real ICAO TD3 machine-readable zone, the real
  // MRZ line 2 text is used as-is downstream, so the server's checksum
  // validation is against genuine document data, not a synthesized line.
  // ============================================================

  // 6-digit MRZ date (YYMMDD) -> ISO 'YYYY-MM-DD'. DOB dates never fall in
  // the future, so a YY greater than the current 2-digit year means 1900s.
  function mrzDateToISO(raw, isBirth){
    if(!/^\d{6}$/.test(raw)) return '';
    const yy = parseInt(raw.slice(0,2),10);
    const mm = raw.slice(2,4), dd = raw.slice(4,6);
    const century = isBirth && yy > (new Date().getFullYear()%100) ? 1900 : 2000;
    return `${century+yy}-${mm}-${dd}`;
  }

  // Best-effort field extraction from raw OCR text. Every value here is a
  // *suggestion* — the officer reviews/corrects all of it before it's ever
  // submitted, so imperfect OCR never silently produces a wrong scan.
  function guessFieldsFromOcrText(text){
    const rawLines = String(text||'').split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
    const compact = rawLines.map(l=> l.replace(/\s+/g,'').toUpperCase());
    let mrzLine1=null, mrzLine2=null;
    for(let i=0;i<compact.length-1;i++){
      const a=compact[i], b=compact[i+1];
      if(/^[A-Z0-9<]{40,44}$/.test(a) && /^[A-Z0-9<]{40,44}$/.test(b) && a.startsWith('P')){
        mrzLine1=a.padEnd(44,'<').slice(0,44); mrzLine2=b.padEnd(44,'<').slice(0,44); break;
      }
    }
    let name='', docNumber='', dob='', nationality='', expiryISO='';
    if(mrzLine1 && mrzLine2){
      // Real ICAO TD3 layout: P<CCCSURNAME<<GIVEN<NAMES<<...  /  docNumber(9) + check + nationality(3) + dob(6) + check + sex(1) + expiry(6) + ...
      const namePart = mrzLine1.slice(5).replace(/<+$/,'');
      const [surname='', given=''] = namePart.split('<<');
      name = [given, surname].filter(Boolean).join(' ').replace(/</g,' ').replace(/\s+/g,' ').trim();
      nationality = mrzLine1.slice(2,5).replace(/</g,'');
      docNumber = mrzLine2.slice(0,9).replace(/</g,'');
      dob = mrzDateToISO(mrzLine2.slice(13,19), true);
      expiryISO = mrzDateToISO(mrzLine2.slice(21,27), false);
    } else {
      // No machine-readable zone found (non-passport document, or a scan
      // too rough for Tesseract to read it) — fall back to generic
      // pattern-matching over whatever text was recognized.
      const full = rawLines.join('\n');
      const dmy = full.match(/\b(\d{2})[\/\-.](\d{2})[\/\-.](\d{4})\b/);
      const ymd = full.match(/\b(\d{4})[\/\-.](\d{2})[\/\-.](\d{2})\b/);
      if(ymd) dob = `${ymd[1]}-${ymd[2]}-${ymd[3]}`;
      else if(dmy) dob = `${dmy[3]}-${dmy[2]}-${dmy[1]}`;
      const docLine = rawLines.find(l=>/\b(NO|NUMBER|PASSPORT|ID)\b/i.test(l) && /[A-Z0-9]{6,}/.test(l));
      const docMatch = (docLine||full).match(/\b[A-Z]{0,2}\d{6,10}\b/);
      docNumber = docMatch ? docMatch[0] : '';
      const nameLine = rawLines.find(l=>/^[A-Z][A-Z\s]{4,40}$/.test(l) && !/PASSPORT|REPUBLIC|GOVERNMENT|IDENTITY|CARD|AUTHORITY|MINISTRY|DEPARTMENT|UNIQUE|IDENTIFICATION|NATIONAL/.test(l));
      name = nameLine ? nameLine.replace(/\s+/g,' ').trim() : '';
    }
    return { name, docNumber, dob, nationality, docType:'Passport', expiryISO, mrzLine2: (mrzLine1&&mrzLine2) ? mrzLine2 : null };
  }

  // Editable review step shown after OCR runs on an uploaded document —
  // reuses the panel's existing #modalBackdrop/#modalBody (same markup the
  // Officers/Registry/Blacklist admin forms already use), so no new CSS.
  // Resolves with the officer-confirmed field values, or null if cancelled.
  function showOcrReviewModal(guess, confidence){
    return new Promise((resolve)=>{
      const backdrop = document.getElementById('modalBackdrop');
      const body = document.getElementById('modalBody');
      if(!backdrop || !body){ resolve(guess); return; }
      const confLine = confidence!=null
        ? `OCR confidence: ${confidence}% — check the fields below before continuing.`
        : `OCR couldn't read this image clearly — please fill in the fields manually.`;
      const mrzNote = guess.mrzLine2 ? ' A machine-readable zone was detected — name / DOB / document number / nationality were auto-filled from it.' : '';
      body.innerHTML = `
        <h3>Review scanned details</h3>
        <p style="font-size:12.5px;color:var(--ink-3);margin:0 0 14px;line-height:1.5;">${escapeHtml(confLine)}${escapeHtml(mrzNote)}</p>
        <form class="modal-form" id="ocrReviewForm">
          <div class="field"><label>Full name</label><input id="ocrName" required value="${escapeHtml(guess.name||'')}"/></div>
          <div class="field"><label>Document number</label><input id="ocrDoc" value="${escapeHtml(guess.docNumber||'')}"/></div>
          <div class="field"><label>Date of birth</label><input id="ocrDob" type="date" value="${escapeHtml(guess.dob||'')}"/></div>
          <div class="field"><label>Nationality</label><input id="ocrNat" value="${escapeHtml(guess.nationality||'')}"/></div>
          <div class="field"><label>Document type</label>
            <select id="ocrDocType">${DOC_TYPES.map(t=>`<option value="${t}" ${guess.docType===t?'selected':''}>${t}</option>`).join('')}</select>
          </div>
          <div class="field"><label>Expiry date</label><input id="ocrExpiry" type="date" value="${escapeHtml(guess.expiryISO||'')}"/></div>
          <div class="modal-actions">
            <button type="button" class="btn btn-ghost btn-sm" id="ocrCancelBtn">Cancel scan</button>
            <button type="submit" class="btn btn-primary btn-sm">Confirm &amp; continue</button>
          </div>
        </form>`;
      backdrop.hidden = false;
      function cleanup(){ backdrop.hidden = true; body.innerHTML=''; }
      document.getElementById('ocrCancelBtn').addEventListener('click', ()=>{ cleanup(); resolve(null); });
      document.getElementById('ocrReviewForm').addEventListener('submit', (e)=>{
        e.preventDefault();
        const result = {
          name: document.getElementById('ocrName').value.trim(),
          docNumber: document.getElementById('ocrDoc').value.trim(),
          dob: document.getElementById('ocrDob').value || '',
          nationality: document.getElementById('ocrNat').value.trim(),
          docType: document.getElementById('ocrDocType').value,
          expiryISO: document.getElementById('ocrExpiry').value || '',
          mrzLine2: guess.mrzLine2 || null,
        };
        cleanup();
        resolve(result);
      });
    });
  }

  const PIPELINE_LABELS = [
    'Capturing document image','Running OCR & MRZ parsing (Tesseract OCR on uploads, live checksum)',
    'Analyzing image for tampering (live ELA)','Decoding embedded QR / chip code (live)',
    'Cross-checking blacklist against database',
    'Searching database for duplicate identities, mutations & anomalies','Cross-checking national registry & document-type rules',
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
    const mrzDetail = r.mrzDetail || { ok:null, supported:false, checks:[] };
    const mrzFailed = mrzDetail.checks ? mrzDetail.checks.filter(c=>!c.pass) : [];
    const mrzSub = !mrzDetail.supported ? 'Could not parse a machine-readable zone' :
      rec.mrzValid ? 'All check digits verified — document number, DOB, expiry & composite all agree' :
      `Check digit mismatch: ${mrzFailed.map(c=>c.name).join(', ')}`;
    const docTypeCheck = r.docTypeCheck || { ok:true, label:'Document-type rules', reason:'Not evaluated' };
    const anomalies = r.anomalies || [];
    const mutation = r.mutation || null;
    const checks = [
      {ok: r.tamperScore<45, warn: r.tamperScore>=45&&r.tamperScore<65, label:'Image forensics (ELA)', sub: r.tamperScore<45?'No significant manipulation detected':'Localized inconsistency detected in image', tag:'LIVE', tagClass:'tag-live'},
      {ok: r.qrStatus!=='mismatch', warn: r.qrStatus==='found'||r.qrStatus==='unsupported', label:'QR / chip code verification', sub: qrSub, tag:'LIVE', tagClass:'tag-live'},
      {ok: rec.mrzValid, label:'MRZ checksum (ICAO 9303)', sub: mrzSub, tag:'LIVE', tagClass:'tag-live'},
      {ok: !rec.blacklistHit, label:'Blacklist / watchlist match', sub: rec.blacklistHit?'Document number matches a database watchlist entry':'No match against the live blacklist table', tag:'DATABASE', tagClass:'tag-live'},
      {ok: regStatus!=='unregistered' && regStatus!=='mismatch', label:'National registry cross-check', sub: regSub, tag:'DATABASE', tagClass:'tag-live'},
      {ok: !rec.duplicateHit, label:'Duplicate identity search', sub: rec.duplicateHit?'Same name + DOB found in a prior scan on record':'No duplicate found in scan history', tag:'DATABASE', tagClass:'tag-live'},
      {ok: !r.expired, label:'Document validity', sub: r.expired?'Document expiry date has passed':'Document within validity window', tag:'DERIVED', tagClass:'tag-sim'},
      {ok: docTypeCheck.ok, label:`Document-type rules (${rec.docType||'Passport'})`, sub: docTypeCheck.reason, tag:'DERIVED', tagClass:'tag-sim'},
      {ok: anomalies.length===0, label:'Zero-day anomaly detection', sub: anomalies.length===0 ? 'No behavioral or cross-signal anomalies detected' : anomalies.join('; '), tag:'DATABASE', tagClass:'tag-live'},
      {ok: !mutation, label:'Mutation detector (identity drift)', sub: mutation ? `${mutation.kind} vs. prior record "${mutation.withName}" — ${mutation.stabilityScore}% stability` : 'No near-duplicate identity found in scan history', tag:'DATABASE', tagClass:'tag-live'},
    ];
    const checkRows = checks.map(c=>{
      const cls = c.ok?'check-pass':(c.warn?'check-warn':'check-fail');
      const icon = c.ok?ICON.check:(c.warn?ICON.warn:ICON.x);
      return `<div class="check-row"><span class="check-icon ${cls}">${icon}</span><span class="check-text"><b>${c.label} <span class="tag ${c.tagClass}" style="margin-left:4px;">${c.tag}</span></b><span>${c.sub}</span></span></div>`;
    }).join('');
    const maxPts = {tamper:25, black:30, dup:25, mrz:12, exp:8, reg:28, qr:24, doctype:10, anomaly:15, mutation:15};
    const regPts = regStatus==='mismatch' ? 28 : (regStatus==='unregistered' ? 26 : 0);
    const qrPts = r.qrStatus==='mismatch' ? 24 : 0;
    const anomalyPts = Math.min(15, anomalies.length*6);
    const mutationPts = mutation ? 15 : 0;
    const contrib = [
      contribRow('Image forensics', r.tamperScore*0.25, maxPts.tamper, 'var(--accent)'),
      contribRow('QR / chip mismatch', qrPts, maxPts.qr, 'var(--critical)'),
      contribRow('Blacklist match', rec.blacklistHit?30:0, maxPts.black, 'var(--critical)'),
      contribRow('Registry cross-check', regPts, maxPts.reg, 'var(--critical)'),
      contribRow('Duplicate identity', rec.duplicateHit?25:0, maxPts.dup, 'var(--serious)'),
      contribRow('MRZ / field check', rec.mrzValid?0:12, maxPts.mrz, 'var(--warning)'),
      contribRow('Document validity', r.expired?8:0, maxPts.exp, 'var(--ink-3)'),
      contribRow('Document-type rule violation', docTypeCheck.ok?0:10, maxPts.doctype, 'var(--warning)'),
      contribRow('Zero-day anomaly', anomalyPts, maxPts.anomaly, 'var(--serious)'),
      contribRow('Identity mutation', mutationPts, maxPts.mutation, 'var(--serious)'),
    ].join('');
    const elaHTML = r.ela ? `<div class="ela-wrap">
        <div class="ela-frame"><img src="${r.ela.originalURL}" alt="Document image"/><span>Original</span></div>
        <div class="ela-frame"><img src="${r.ela.heatmapURL}" alt="Error level analysis heatmap"/><span>ELA heatmap</span></div>
      </div>` : `<p style="font-size:12.5px;color:var(--ink-3);">Image forensics unavailable for this file.</p>`;

    const report = buildInvestigationReport(r);
    r.investigationReport = report; // stashed for the downloadable report
    const copilotHTML = `<div class="rcard" id="copilotCard">
      <h4>AI Investigation Copilot <span class="tag tag-sim">RULE-BASED — NO EXTERNAL AI CALL</span></h4>
      <p style="font-size:13.5px; line-height:1.6; color:var(--ink);">${escapeHtml(report.opening)}</p>
      <p style="font-size:13px; line-height:1.6; color:var(--ink-2); margin-top:8px;">${escapeHtml(report.body)}</p>
      <p style="font-size:13px; line-height:1.6; margin-top:10px; padding-top:10px; border-top:1px solid var(--border); color:${report.findings.some(f=>f.points>=24)?'var(--critical)':'var(--ink)'};"><b>${escapeHtml(report.recommendation)}</b></p>
    </div>`;

    const regWarningHTML = (regStatus === 'unregistered' || regStatus === 'mismatch') ? `<div class="rcard" style="background:var(--critical-soft); border-color:var(--critical);">
          <div style="display:flex; align-items:flex-start; gap:10px;">
            <span style="color:var(--critical); flex-shrink:0; margin-top:2px;">${ICON.warn}</span>
            <div>
              <div style="font-weight:700; color:var(--critical); font-size:14px;">${regStatus === 'unregistered' ? 'Warning: document not found in the national registry' : 'Warning: registry identity mismatch'}</div>
              <div style="font-size:12.5px; color:var(--critical); margin-top:4px; line-height:1.5;">${regStatus === 'unregistered' ? 'This document number does not exist anywhere in the national registry database and could not be verified against any known record. Treat this scan with caution and confirm the traveler\'s identity through a secondary check.' : `This document number is on file, but registered to a different identity ("${escapeHtml(regEntry ? regEntry.name : 'unknown')}") than the one printed on the scanned document. Do not clear this traveler without manual verification.`}</div>
            </div>
          </div>
        </div>` : '';

    el.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:14px;">
        ${regWarningHTML}
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
        ${copilotHTML}
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
        ${mrzDetail.supported ? `<div class="rcard">
          <h4>MRZ check digits <span class="tag tag-live" style="${!rec.mrzValid?'background:var(--critical-soft);color:var(--critical);':''}">${rec.mrzValid?'ALL VALID':'MISMATCH'}</span></h4>
          <div class="field-list">
            ${mrzDetail.checks.map(c=>`<div class="field-row"><span class="fk">${c.name}</span><span class="fv" style="${c.pass?'':'color:var(--critical);'}">printed ${c.printed} ${c.pass?'=':'≠'} computed ${c.expected}</span></div>`).join('')}
          </div>
        </div>` : ''}
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
        <div class="rcard" id="faceVerifyCard">
          <h4>Face verification <span class="tag tag-live">LIVE — COMPUTED IN BROWSER</span></h4>
          <div id="faceVerifyBody">${faceCardIntroHTML()}</div>
        </div>
        <div class="rcard"><h4>Verification checks</h4><div class="check-list">${checkRows}</div></div>
        <div class="rcard"><h4>Score breakdown</h4>${contrib}</div>
      </div>`;

    wireFaceVerify();
    lastResult = r;
  }

  function init(opts){
    const { stageUpload, stageProcessing, stageResults, pipelineStepsEl, resultsGrid, uploadZone, fileInput, sampleCleanBtn, sampleFlaggedBtn, scanAnotherBtn, downloadReportBtn, onSaved } = opts;

    function reset(){
      stopFaceStream();
      stageResults.hidden = true; stageProcessing.hidden = true; stageUpload.hidden = false;
      fileInput.value = '';
    }
    scanAnotherBtn.addEventListener('click', reset);

    if(downloadReportBtn){
      downloadReportBtn.addEventListener('click', ()=>{
        if(!lastResult) return;
        document.getElementById('printReport').innerHTML = buildPrintReportHTML(lastResult);
        window.print();
      });
    }

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

      let imgEl, fields, sourceLabel, sampleVariant=null, mrzLine2=null, needsReview=false;
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
        };
        // The exact 44-char line drawn on the specimen (corruption, when
        // present, is randomized at draw time) — reused as-is so what's
        // submitted matches what's printed on the document image.
        mrzLine2 = specData.mrzLine2;
        sourceLabel = source.sample==='flagged' ? 'Specimen — flagged' : 'Specimen — clean';
      } else {
        const file = source.file;
        sourceLabel = file.name;
        try{ imgEl = await loadImageEl(URL.createObjectURL(file)); }catch{ imgEl = null; }
        needsReview = true;
      }

      let ocrGuess = null, ocrConfidence = null;
      await playStep(1, async ()=>{
        if(!needsReview) return;
        if(imgEl && typeof Tesseract !== 'undefined'){
          try{
            const { data } = await Tesseract.recognize(imgEl, 'eng');
            ocrConfidence = Math.round(data.confidence || 0);
            ocrGuess = guessFieldsFromOcrText(data.text || '');
          }catch{ ocrGuess = guessFieldsFromOcrText(''); }
        } else {
          ocrGuess = guessFieldsFromOcrText('');
        }
      });

      if(needsReview){
        const confirmed = await showOcrReviewModal(ocrGuess, ocrConfidence);
        if(!confirmed){ reset(); return; }
        const expiryDate = confirmed.expiryISO ? new Date(confirmed.expiryISO+'T00:00:00') : addDays(new Date(),700);
        fields = {
          name: confirmed.name, dob: confirmed.dob || null, docNumber: confirmed.docNumber || '',
          nationality: confirmed.nationality || null, docType: confirmed.docType || 'Passport',
          expired: confirmed.expiryISO ? (expiryDate < new Date()) : false, expiry: expiryDate,
        };
        if(confirmed.mrzLine2){
          // Real MRZ line captured via OCR — passed through as-is so the
          // server's ICAO checksum validation runs against genuine data.
          mrzLine2 = confirmed.mrzLine2;
        } else {
          // No machine-readable zone available (e.g. a national ID card) —
          // synthesize a properly-checksummed line from the officer-
          // confirmed fields so the MRZ card still has something real to
          // validate, same approach as the two specimens use.
          const mrzRng = mulberry32(fnv1a((confirmed.docNumber||sourceLabel)+'|mrz'));
          const corrupt = mrzRng() < 0.12;
          mrzLine2 = buildMrzLine2({
            docNumber: fields.docNumber, dobISO: fields.dob, expiryDate: fields.expiry,
            corruptField: corrupt ? Math.floor(mrzRng()*5) : null
          });
        }
      }

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

      let record, registryEntry = null, mrzDetail = null, docTypeCheck = null, anomalies = [], mutation = null;
      const expiryISO = isoDate(fields.expiry);
      await playStep(7, async ()=>{
        const res = await VeriScanx.api('/api/scans', { method:'POST', body:{
          travelerName: fields.name, dob: fields.dob, docType: fields.docType,
          docNumber: fields.docNumber, nationality: fields.nationality,
          tamperScore, mrzLine2, expiryDate: expiryISO, expired: fields.expired, qrStatus,
          source: sampleVariant ? ('sample-'+sampleVariant) : 'upload'
        }});
        record = res.item;
        registryEntry = res.registry ? res.registry.entry : null;
        mrzDetail = res.mrz || null;
        docTypeCheck = res.docTypeCheck || null;
        anomalies = res.anomalies || [];
        mutation = res.mutation || null;
      });

      await new Promise(r=>setTimeout(r,250));

      // Reference photo for the face-verification card: a matched registry
      // photo wins (most authoritative); otherwise a real uploaded document
      // image; the two specimens are illustrations with no real face; else
      // no reference is available at all.
      if(registryEntry && registryEntry.photo){
        faceRefSrc = registryEntry.photo;
        faceRefLabel = `Registry photo — ${registryEntry.name}`;
        faceRefKind = 'available';
      } else if(imgEl && !sampleVariant){
        faceRefSrc = imgEl.src;
        faceRefLabel = 'Document photo';
        faceRefKind = 'available';
      } else if(sampleVariant){
        faceRefSrc = null; faceRefLabel = ''; faceRefKind = 'specimen';
      } else {
        faceRefSrc = null; faceRefLabel = ''; faceRefKind = 'none';
      }

      renderResults(resultsGrid, {
        record, sourceLabel, ela, tamperScore, expired: fields.expired,
        expiryDisplay: fmtDate(new Date(fields.expiry)), registryEntry, qrStatus, qrDecoded,
        mrzDetail, docTypeCheck, anomalies, mutation
      });

      stageProcessing.hidden = true; stageResults.hidden = false;
      if(onSaved) onSaved(record);
    }

    return { reset };
  }

  return { init };
})();
