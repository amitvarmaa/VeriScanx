// Small hand-rolled SVG charts — no external chart library.
window.VeriScanxCharts = (function(){
  const BAND_VAR = { Low:'--good', Medium:'--warning', High:'--serious', Critical:'--critical' };

  function fmtDate(iso){
    const d = new Date(iso+'T00:00:00');
    return d.toLocaleDateString(undefined,{day:'2-digit',month:'short'});
  }

  function renderVolume(el, volume14){
    const W=520,H=190,pad={l:28,r:10,t:12,b:24};
    const vals = volume14.map(d=>d.count);
    const max = Math.max(...vals,1)*1.15;
    const x = i => pad.l + (i/(volume14.length-1||1))*(W-pad.l-pad.r);
    const y = v => H-pad.b - (v/max)*(H-pad.t-pad.b);
    const linePts = volume14.map((d,i)=>`${x(i)},${y(d.count)}`).join(' ');
    const areaPts = `${x(0)},${H-pad.b} ${linePts} ${x(volume14.length-1)},${H-pad.b}`;
    const gridYs = [0,0.5,1].map(f=> pad.t + f*(H-pad.t-pad.b));
    let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;overflow:visible;" role="img" aria-label="Scan volume over the last 14 days">
      <defs><linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--seq-500)" stop-opacity="0.32"/>
        <stop offset="100%" stop-color="var(--seq-500)" stop-opacity="0"/>
      </linearGradient></defs>`;
    gridYs.forEach(gy=> svg += `<line x1="${pad.l}" y1="${gy}" x2="${W-pad.r}" y2="${gy}" stroke="var(--grid-line)" stroke-width="1"/>`);
    svg += `<polygon points="${areaPts}" fill="url(#volGrad)"/>`;
    svg += `<polyline points="${linePts}" fill="none" stroke="var(--seq-500)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
    if(volume14.length){
      const last = volume14[volume14.length-1];
      svg += `<circle cx="${x(volume14.length-1)}" cy="${y(last.count)}" r="4" fill="var(--seq-500)" stroke="var(--surface)" stroke-width="2"/>`;
    }
    volume14.forEach((d,i)=>{ svg += `<circle data-i="${i}" cx="${x(i)}" cy="${y(d.count)}" r="9" fill="transparent" class="vhit"/>`; });
    if(volume14.length){
      svg += `<text x="${pad.l}" y="${H-6}" font-family="var(--font-mono)" font-size="9.5" fill="var(--ink-3)">${fmtDate(volume14[0].date)}</text>`;
      svg += `<text x="${W-pad.r}" y="${H-6}" text-anchor="end" font-family="var(--font-mono)" font-size="9.5" fill="var(--ink-3)">${fmtDate(volume14[volume14.length-1].date)}</text>`;
    }
    svg += `</svg><div class="tooltip" id="volTip"></div>`;
    el.innerHTML = svg;
    const tip = el.querySelector('#volTip');
    el.querySelectorAll('.vhit').forEach(c=>{
      c.addEventListener('mouseenter', ()=>{
        const i = +c.dataset.i; const d = volume14[i];
        tip.textContent = fmtDate(d.date)+' — '+d.count+' scans';
        tip.classList.add('show');
      });
      c.addEventListener('mousemove', (e)=>{
        const rect = el.getBoundingClientRect();
        tip.style.left = (e.clientX-rect.left)+'px';
        tip.style.top = (e.clientY-rect.top)+'px';
      });
      c.addEventListener('mouseleave', ()=> tip.classList.remove('show'));
    });
  }

  function renderBand(el, bandCounts){
    const bands = ['Low','Medium','High','Critical'];
    const counts = bands.map(b=> bandCounts[b]||0);
    const max = Math.max(...counts,1);
    const W=380,H=170,barH=24,gap=18,top=8;
    const trackX=78, trackW=W-trackX-38;
    let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;" role="img" aria-label="Scans by risk band">`;
    bands.forEach((b,i)=>{
      const y = top + i*(barH+gap);
      const barW = Math.max(4, (counts[i]/max)*trackW);
      svg += `<text x="0" y="${y+barH/2+4}" font-family="var(--font-body)" font-size="12" fill="var(--ink-2)">${b}</text>`;
      svg += `<rect x="${trackX}" y="${y}" width="${trackW}" height="${barH}" rx="5" fill="var(--grid-line)"/>`;
      svg += `<rect x="${trackX}" y="${y}" width="${barW}" height="${barH}" rx="5" fill="var(${BAND_VAR[b]})"/>`;
      svg += `<text x="${W-4}" y="${y+barH/2+4}" text-anchor="end" font-family="var(--font-mono)" font-size="12" fill="var(--ink)" class="tnum">${counts[i]}</text>`;
    });
    svg += `</svg>`;
    el.innerHTML = svg;
  }

  function renderReasons(el, topReasons){
    if(!topReasons.length){ el.innerHTML = '<p class="empty-note">No flag reasons in the last 14 days.</p>'; return; }
    const max = Math.max(...topReasons.map(r=>r.count),1);
    el.innerHTML = topReasons.map(r=>`
      <div style="margin-top:12px;">
        <div style="display:flex;justify-content:space-between;font-size:13px;"><span>${r.label}</span><span class="mono tnum">${r.count}</span></div>
        <div style="height:7px;border-radius:999px;background:var(--surface-2);overflow:hidden;margin-top:5px;">
          <div style="height:100%;width:${(r.count/max)*100}%;background:var(--accent);border-radius:999px;"></div>
        </div>
      </div>`).join('');
  }

  return { renderVolume, renderBand, renderReasons };
})();
