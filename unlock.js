/* ════════════════════════════════════════════════════════════════
   web/unlock.js — 배포본 잠금 해제 로더 (배포 빌드에서만 로드됨)

   배포된 정적 사이트에는 평문 코드·데이터가 없다. 앱 전체(js/*.js +
   data.js + 시세)가 AES-256-GCM으로 암호화된 app.enc 한 덩어리로만
   올라가고, 이 파일이 암호를 받아 복호화한 뒤 전역 스크립트로 주입한다.
   → URL이 유출돼도 암호 없이는 아무것도 읽히지 않는다.

   암호는 성공 시 localStorage에 저장돼 기기당 한 번만 입력하면 된다.
═══════════════════════════════════════════════════════════════════ */
(function () {
  var KEY = 'dash.pass', ITER = 310000;
  var enc = new TextEncoder(), dec = new TextDecoder();

  function b64ToBytes(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* 암호 → PBKDF2 → AES-GCM 키 */
  async function deriveKey(pass, salt) {
    var base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }

  /* 복호화 실패(암호 불일치)는 AES-GCM 인증 태그 검증에서 예외로 떨어진다 */
  async function decrypt(blob, pass) {
    var raw = b64ToBytes(blob);
    var key = await deriveKey(pass, raw.slice(0, 16));
    var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(16, 28) }, key, raw.slice(28));
    return dec.decode(plain);
  }

  /* 복호화된 번들은 <script>.textContent로 주입해야 전역 스코프에 실린다
     (new Function()이면 함수 선언이 전역에 안 잡혀 인라인 onclick이 깨진다) */
  function run(code) {
    var s = document.createElement('script');
    s.textContent = code;
    document.body.appendChild(s);
  }

  /* 잠금화면은 앱 로드 전이라 CSS 변수를 쓸 수 없다 — 저장된 테마/OS 설정을 직접 읽어 맞춘다 */
  var savedTheme = localStorage.getItem('theme');
  var light = savedTheme ? savedTheme === 'light'
    : window.matchMedia('(prefers-color-scheme: light)').matches;
  var C = light
    ? { bg:'#f5f7fb', text:'#151b2b', muted:'#525d75', field:'#ffffff', line:'#dde3ed', accent:'#1d4ed8' }
    : { bg:'#0b0f1a', text:'#e2e8f5', muted:'#8896b3', field:'#1a2236', line:'#252e45', accent:'#4f8ef7' };

  var style = document.createElement('style');
  style.textContent =
    '#lockScreen{position:fixed;inset:0;z-index:9999;background:' + C.bg + ';display:flex;' +
    'align-items:center;justify-content:center;padding:24px}' +
    '#lockBox{width:100%;max-width:330px;text-align:center}' +
    '#lockBox img{width:72px;height:72px;border-radius:18px;margin-bottom:18px}' +
    '#lockBox h1{font-size:17px;font-weight:800;letter-spacing:-.3px;margin-bottom:6px}' +
    '#lockBox p{font-size:12.5px;color:' + C.muted + ';line-height:1.6;margin-bottom:20px}' +
    '#lockPass{width:100%;box-sizing:border-box;background:' + C.field + ';border:1px solid ' + C.line + ';' +
    'border-radius:12px;color:' + C.text + ';font-size:16px;padding:13px 14px;text-align:center;' +
    'letter-spacing:2px;outline:none}' +
    '#lockPass:focus{border-color:' + C.accent + '}' +
    '#lockBtn{width:100%;margin-top:10px;background:' + C.accent + ';border:none;border-radius:12px;' +
    'color:#fff;font-size:14px;font-weight:700;padding:14px;cursor:pointer}' +
    '#lockBtn:disabled{opacity:.55;cursor:default}' +
    '#lockMsg{min-height:18px;margin-top:12px;font-size:12px;color:#f87171}' +
    '#lockBox h1{color:' + C.text + '}';
  document.head.appendChild(style);

  var box = document.createElement('div');
  box.id = 'lockScreen';
  box.innerHTML =
    '<div id="lockBox">' +
    '<img src="icon-192.png" alt="">' +
    '<h1>자산 대시보드</h1>' +
    '<p>이 페이지의 내용은 암호화되어 있습니다.<br>암호를 입력하면 이 기기에서는 다음부터 자동으로 열립니다.</p>' +
    '<input id="lockPass" type="password" inputmode="text" autocomplete="current-password" placeholder="암호">' +
    '<button id="lockBtn">잠금 해제</button>' +
    '<div id="lockMsg"></div>' +
    '</div>';
  document.body.appendChild(box);

  var input = box.querySelector('#lockPass'),
      btn = box.querySelector('#lockBtn'),
      msg = box.querySelector('#lockMsg');

  var blobPromise = fetch('app.enc').then(function (r) {
    if (!r.ok) throw new Error('app.enc ' + r.status);
    return r.text();
  });

  async function tryUnlock(pass, fromCache) {
    btn.disabled = true;
    msg.style.color = C.muted;
    msg.textContent = '잠금 해제 중…';
    try {
      var code = await decrypt(await blobPromise, pass);
      localStorage.setItem(KEY, pass);
      box.remove();
      run(code);
      return true;
    } catch (e) {
      if (fromCache) localStorage.removeItem(KEY);   // 저장된 암호가 더 이상 안 맞음(재빌드 등)
      msg.style.color = '#f87171';
      msg.textContent = '암호가 맞지 않습니다.';
      btn.disabled = false;
      input.value = '';
      input.focus();
      return false;
    }
  }

  btn.addEventListener('click', function () { if (input.value) tryUnlock(input.value, false); });
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter' && input.value) tryUnlock(input.value, false); });

  var saved = localStorage.getItem(KEY);
  if (saved) tryUnlock(saved, true); else input.focus();
})();
