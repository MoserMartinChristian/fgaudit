// Renders scenes.json into PNG frames (10 fps) with Playwright.
// Usage: node render_frames.js <outdir>
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const ROWS = 27;
const scenes = JSON.parse(fs.readFileSync(path.join(__dirname, 'scenes.json'), 'utf8'));
const out = process.argv[2] || path.join(__dirname, 'frames');
fs.mkdirSync(out, { recursive: true });

const css = `
body{margin:0;background:#0d1117;font:14px/1.45 "DejaVu Sans Mono",monospace;color:#d6dde6}
.win{margin:14px;border-radius:10px;overflow:hidden;border:1px solid #30363d;box-shadow:0 8px 30px #0008}
.bar{background:#161b22;padding:8px 12px;color:#8b949e;font-size:13px}
.bar i{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:6px;background:#30363d}
pre{margin:0;padding:12px 16px;height:${ROWS * 20.3}px;white-space:pre;overflow:hidden}
.b{font-weight:bold}.dim{opacity:.6}.red{color:#ff6b6b}.yellow{color:#f2c94c}.cyan{color:#56c8d8}.green{color:#5ad17a}
.white{color:#fff}.bgblue{background:#1f4fa8}.p{color:#5ad17a}.cur{background:#d6dde6;color:#0d1117}
.cap{position:absolute;right:30px;bottom:26px;background:#1f6feb;color:#fff;padding:6px 12px;border-radius:6px;font:600 15px system-ui,sans-serif}`;

function page(lines, caption) {
  return `<!doctype html><meta charset="utf-8"><style>${css}</style><div class="win"><div class="bar"><i></i><i></i><i></i>&nbsp; fgaudit – made-up demo data</div><pre>${lines.join('\n')}</pre></div>${caption ? `<div class="cap">${caption}</div>` : ''}`;
}

const captions = ['Shadowed policies and IP overlaps', 'Change risk before/after', 'Incident timeline from logs'];

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1000, height: 680 } });
  let n = 0;
  const shot = async (lines, cap) => {
    await p.setContent(page(lines, cap));
    await p.screenshot({ path: path.join(out, `f${String(n++).padStart(5, '0')}.png`) });
  };
  for (let s = 0; s < scenes.length; s++) {
    const sc = scenes[s];
    const prompt = '<span class="p">$</span> ';
    for (let i = 0; i <= sc.cmd.length; i += 2) await shot([prompt + sc.cmd.slice(0, i) + '<span class="cur"> </span>'], captions[s]);
    await shot([prompt + sc.cmd], captions[s]);
    let body = sc.lines;
    if (sc.show === 'timeline') {
      const t = body.findIndex(l => l.includes('TIMELINE'));
      const f = body.findIndex(l => l.includes('FINDINGS'));
      body = body.slice(0, 6).concat(body.slice(f, f + 4), [''], body.slice(t));
    }
    const all = [prompt + sc.cmd].concat(body);
    for (let k = 2; k <= Math.min(all.length, ROWS) + 3; k += 3) await shot(all.slice(0, Math.min(k, ROWS)), captions[s]);
    for (let h = 0; h < sc.hold; h++) await shot(all.slice(0, ROWS), captions[s]);
  }
  await b.close();
  console.log(`${n} frames`);
})();
