'use strict';
// Experimento: ¿qué codificador usa el host (hardware o software) según el perfil H.264 que pide el cliente y los fps?
// Imita el orden de codecs de Safari (iPhone) reordenando setCodecPreferences en Edge.
// Uso: node encoder-probe.js        (corre el host real con entrada simulada; no toca el mouse)
const { chromium } = require('playwright');
const { start } = require('./broker');
const { launchHost } = require('./host');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000) {
  const t0 = Date.now();
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) throw new Error('timeout'); await sleep(150); }
}

// profile: null = orden por defecto de Edge; si no, ese profile-level-id de H.264 va primero (como hace Safari con 640c1f)
const CASES = [
  { name: 'como iPhone (640c1f + 42e01f), 60 fps', profile: ['640c1f', '42e01f'], fps: 60 },
  { name: 'como iPhone (640c1f + 42e01f), 30 fps', profile: ['640c1f', '42e01f'], fps: 30 },
  { name: 'solo High 640c1f, 60 fps', profile: ['640c1f'], fps: 60 },
  { name: 'solo Constrained Baseline 42e01f, 60 fps', profile: ['42e01f'], fps: 60 },
];

async function main() {
  const broker = await start();
  const browser = await chromium.launch({ channel: 'msedge' });
  const results = [];
  let host = null;
  try {
    const ctx = await browser.newContext({ viewport: { width: 844, height: 390 } });
    const page = await ctx.newPage();
    await page.addInitScript(() => {
      const orig = RTCRtpTransceiver.prototype.setCodecPreferences;
      RTCRtpTransceiver.prototype.setCodecPreferences = function (codecs) {
        // __h264only: lista de profile-level-id permitidos (en ese orden); los demás H.264 se sacan de la oferta
        const only = window.__h264only;
        if (only) {
          const h = (c) => /h264/i.test(c.mimeType);
          const prof = (c) => ((c.sdpFmtpLine || '').match(/profile-level-id=([0-9a-f]{6})/i) || [])[1];
          const keep = only.flatMap((p) => codecs.filter((c) => h(c) && prof(c) === p));
          codecs = [...keep, ...codecs.filter((c) => !h(c))];
        }
        return orig.call(this, codecs);
      };
    });
    await page.goto('http://localhost:8000/');
    await page.evaluate(() => localStorage.setItem('pcu-config-v1', JSON.stringify({ host: 'localhost', user: 'u', pass: 'p', testUrl: 'ws://127.0.0.1:8888' })));
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.reload();
    await page.evaluate(() => window.PCU.createKey());
    const code = await page.evaluate(() => window.PCU.pairCode());
    host = launchHost({ code, env: { PCU_LOG_STATS: '1' } });
    await host.waitFor(/código/);
    await page.evaluate(() => window.PCU.connect());
    if (await page.isHidden('#settings')) await page.click('#btnSettings');
    await until(() => page.isVisible('#hostCodeBox'));
    await page.click('#btnHostMatch');
    await page.click('#btnBack');
    for (const c of CASES) {
      await page.evaluate((p) => { window.__h264only = p; }, c.profile);
      await page.click('#btnRemote');
      await page.evaluate(() => { window.PCU.R.prepared = null; });
      // forzar una oferta nueva con el orden de codecs de este caso
      await page.click('#rBack');
      await page.click('#btnRemote');
      await until(() => page.evaluate(() => !!window.PCU.R.prepared), 15000);
      await page.evaluate((f) => { window.PCU.cfg().fps = f; }, c.fps);
      const n0 = host.lines.length;
      await page.click('#rConnect');
      await until(() => page.evaluate(() => document.querySelector('#rVideo').videoWidth > 0), 20000);
      // animar algo en la pantalla de la compu no hace falta: el codificador se elige al arrancar
      await sleep(7000);
      const st = host.lines.slice(n0).filter((l) => /stats \{/.test(l)).map((l) => JSON.parse(l.replace(/^.*stats /, ''))).at(-1);
      const sdpProfile = await page.evaluate(() => {
        const sdp = window.PCU.R.live.pc.remoteDescription.sdp;
        const pt = (sdp.match(/^m=video \d+ \S+ (\d+)/m) || [])[1];
        const line = (prefix) => sdp.split(String.fromCharCode(13, 10)).find((l) => l.startsWith(prefix)) || '';
        return `${line('a=rtpmap:' + pt + ' ')} ${line('a=fmtp:' + pt + ' ')}`.trim();
      });
      const offerH264 = await page.evaluate(() => window.PCU.R.live.pc.localDescription.sdp.split(String.fromCharCode(13, 10)).filter((l) => l.startsWith('a=fmtp:') && l.includes('profile-level-id')));
      if (c === CASES[0]) console.log('H.264 en la oferta:', JSON.stringify(offerH264));
      results.push({ caso: c.name, negociado: sdpProfile, codificador: st?.impl, hw: st?.hw, fps: st?.fps, res: st ? `${st.w}×${st.h}` : '' });
      console.log(JSON.stringify(results.at(-1)));
      await page.click('#rEnd');
      await host.waitFor(/fin de sesión/, 10000).catch(() => {});
      await page.click('#rBack');
      await sleep(1000);
    }
  } finally {
    if (host) await host.kill().catch(() => {});
    await browser.close();
    await broker.close();
  }
  console.table(results);
  // Con lo que ofrece el iPhone, el host tiene que usar el codificador por hardware (ver host/src/rtc/rtc.js: offerForHwEncoder)
  const bad = results.slice(0, 3).filter((r) => !r.hw);
  if (bad.length) { console.error('FALLÓ: codificador por software en', bad.map((r) => r.caso).join(' / ')); process.exit(1); }
  console.log('OK: con una oferta tipo iPhone el host usa el codificador por hardware');
}

main().catch((e) => { console.error('FALLÓ:', e.stack || e.message); process.exit(1); });
