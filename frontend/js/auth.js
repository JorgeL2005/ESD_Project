document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const loginMsg = document.getElementById('loginMsg');
  const regMsg = document.getElementById('regMsg');
  const regPrivateKey = document.getElementById('regPrivateKey');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginMsg.textContent = '';
    try {
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;
      const res = await fetch('/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      if (!res.ok) { throw new Error('Login inválido'); }
      const data = await res.json();
      // Guardar token y consultar /auth/me para obtener el rol
      saveToken(data.access_token, username, 'unknown');
      const meRes = await fetch('/auth/me', { headers: { 'Authorization': 'Bearer ' + data.access_token } });
      const meData = await meRes.json();
      if (meRes.ok && meData.role) {
        saveToken(data.access_token, meData.username || username, meData.role);
      }
      loginMsg.textContent = 'Login exitoso';
      // Redirigir según rol
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

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    regMsg.textContent = '';
    regPrivateKey.value = '';
    try {
      const username = document.getElementById('regUsername').value;
      const password = document.getElementById('regPassword').value;
      const role = document.getElementById('regRole').value;
      const res = await fetch('/auth/register', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
      });
      const data = await res.json();
      if (!res.ok) { throw new Error(data.detail || 'Error al registrar'); }
      regMsg.textContent = data.message + ' Copie y guarde su clave privada.';
      regPrivateKey.value = data.private_key_pem;
    } catch (err) {
      regMsg.textContent = err.message;
    }
  });
});