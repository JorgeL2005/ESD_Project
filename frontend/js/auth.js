document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const loginMsg = document.getElementById('loginMsg');
  const regMsg = document.getElementById('regMsg');
  const regPrivateKey = document.getElementById('regPrivateKey');

  // Intentar recuperar credenciales almacenadas para autocompletar el formulario
  (async () => {
    try {
      if (navigator.credentials && navigator.credentials.get) {
        const cred = await navigator.credentials.get({ password: true, mediation: 'optional' });
        if (cred && cred.type === 'password') {
          if (document.getElementById('loginUsername')) document.getElementById('loginUsername').value = cred.id || '';
          if (document.getElementById('loginPrivateKey')) document.getElementById('loginPrivateKey').value = cred.password || '';
        }
      }
    } catch (e) {
      // silent fail — no credential API support or user dismissed UI
      console.debug('Credential retrieval not available or denied', e);
    }
  })();

  // Toggle show/hide private key
  const showToggle = document.getElementById('showPrivateKey');
  if (showToggle) {
    showToggle.addEventListener('change', () => {
      const pk = document.getElementById('loginPrivateKey');
      if (!pk) return;
      pk.type = showToggle.checked ? 'text' : 'password';
    });
  }

  if (loginForm) loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginMsg.textContent = '';
    try {
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPrivateKey').value; // reused field name for password

      const res = await fetch('/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) { throw new Error(data.detail || 'Login inválido'); }
      saveToken(data.access_token, username, 'unknown');
      const meRes = await fetch('/auth/me', { headers: { 'Authorization': 'Bearer ' + data.access_token } });
      const meData = await meRes.json();
      if (meRes.ok && meData.role) {
        saveToken(data.access_token, meData.username || username, meData.role);
      }
      loginMsg.textContent = 'Login exitoso';
      const role = getRole();
      if (role === 'admin') {
        window.location.href = '/static/admin.html';
      } else if (role === 'auditor') {
        window.location.href = '/static/audit.html';
      } else {
        window.location.href = '/static/vote.html';
      }
    } catch (err) {
      loginMsg.textContent = err.message;
    }
  });

  // Lost key modal behavior
  const lostKeyLink = document.getElementById('lostKeyLink');
  const lostKeyModal = document.getElementById('lostKeyModal');
  const closeLostKey = document.getElementById('closeLostKey');
  if (lostKeyLink && lostKeyModal) {
    lostKeyLink.addEventListener('click', (ev) => {
      ev.preventDefault();
      lostKeyModal.style.display = 'flex';
      lostKeyModal.setAttribute('aria-hidden', 'false');
    });
  }
  if (closeLostKey && lostKeyModal) {
    closeLostKey.addEventListener('click', (ev) => {
      ev.preventDefault();
      lostKeyModal.style.display = 'none';
      lostKeyModal.setAttribute('aria-hidden', 'true');
    });
  }

  if (registerForm) registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    regMsg.textContent = '';
    if (regPrivateKey) regPrivateKey.value = '';
    try {
      const username = document.getElementById('regUsername').value;
      const role = document.getElementById('regRole').value;
      const res = await fetch('/auth/register', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, role })
      });
      const data = await res.json();
      if (!res.ok) { throw new Error(data.detail || 'Error al registrar'); }
      regMsg.textContent = data.message + ' Copie y guarde su clave privada.';
      if (regPrivateKey) regPrivateKey.value = data.private_key_pem;
      const blob = new Blob([data.private_key_pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      // Guardar como .txt según solicitud del usuario
      a.download = `${data.username || 'private'}_key.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      // Auto-login: usar el flujo por firma con la clave privada recién generada
      const privatePem = data.private_key_pem;
      // solicitar challenge
      const chRes = await fetch('/auth/challenge?username=' + encodeURIComponent(username));
      const chData = await chRes.json();
      if (!chRes.ok) { throw new Error(chData.detail || 'No se pudo obtener challenge'); }
      const challengeHex = chData.challenge_b64;
      const pemToArrayBuffer = (pem) => {
        const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g, '');
        const bin = atob(b64);
        const len = bin.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
        return bytes.buffer;
      };
      const importPrivateKey = async (pem) => {
        const pkBuf = pemToArrayBuffer(pem);
        return await crypto.subtle.importKey(
          'pkcs8', pkBuf,
          { name: 'RSA-PSS', hash: 'SHA-256' },
          false, ['sign']
        );
      };
      const hexToBuffer = (hex) => {
        if (hex.length % 2) hex = '0' + hex;
        const len = hex.length / 2;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = parseInt(hex.substr(i*2,2),16);
        return bytes.buffer;
      };
      const bufToHex = (buf) => {
        const b = new Uint8Array(buf);
        return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
      };
      const key = await importPrivateKey(privatePem);
      const signed = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, key, hexToBuffer(challengeHex));
      const sigHex = bufToHex(signed);
      const loginRes = await fetch('/auth/login-sig', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, signature_b64: sigHex })
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok) { throw new Error(loginData.detail || 'Error tras registro'); }
      saveToken(loginData.access_token, username, 'unknown');
      const meRes = await fetch('/auth/me', { headers: { 'Authorization': 'Bearer ' + loginData.access_token } });
      const meData = await meRes.json();
      if (meRes.ok && meData.role) {
        saveToken(loginData.access_token, meData.username || username, meData.role);
      }
      const finalRole = getRole();
      if (finalRole === 'admin') {
        window.location.href = '/static/admin.html';
      } else if (finalRole === 'auditor') {
        window.location.href = '/static/audit.html';
      } else {
        window.location.href = '/static/vote.html';
      }
    } catch (err) {
      regMsg.textContent = err.message;
    }
  });
});
