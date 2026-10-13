'use strict';
/* global pcu */
const $ = (s) => document.querySelector(s);

function render(s) {
  const st = $('#status');
  st.textContent = s.paired ? `Servidor: ${s.mqtt}` : 'Falta pegar el código de la app';
  st.className = 'status ' + (s.mqtt === 'conectado' ? 'on' : s.paired ? 'off' : '');
  $('#vcode').textContent = s.code;
  $('#pairedInfo').hidden = !s.paired;
  $('#btnSave').textContent = s.paired ? 'Cambiar código' : 'Guardar';
  $('#optLogin').checked = s.startAtLogin;
  $('#optLogin').disabled = !s.canAutostart;
  $('#loginHint').hidden = s.canAutostart;
  $('#lockState').textContent = s.locked ? 'sí' : 'no';
  $('#sessionCard').hidden = !s.session;
  if (s.session) {
    const until = new Date(s.session.exp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const x = s.session.stats;
    const vid = x ? ` · ${x.codec}${x.hw ? ' (hardware)' : ''} ${x.w}×${x.h} ${x.fps} fps ${(x.kbps / 1000).toFixed(1)} Mb/s ${x.route}` : '';
    $('#sessionInfo').textContent = (s.session.connected ? 'Conectada' : 'Conectando…') + ` · vence ${until}` + vid;
  }
  $('#footer').textContent = `Versión ${s.version}`;
}

$('#btnSave').addEventListener('click', async () => {
  const r = await pcu.savePair($('#code').value);
  $('#saveMsg').textContent = r.ok ? '✔ Guardado. Conectando al servidor…' : r.msg;
  $('#saveMsg').className = 'hint ' + (r.ok ? 'ok' : 'err');
  if (r.ok) $('#code').value = '';
});
$('#optLogin').addEventListener('change', (e) => pcu.option('startAtLogin', e.target.checked));
$('#btnEnd').addEventListener('click', () => pcu.endSession());

pcu.onState(render);
pcu.state().then(render);
setInterval(() => pcu.state().then(render), 2000);
