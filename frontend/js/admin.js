document.addEventListener('DOMContentLoaded', () => {
  const userLabel = document.getElementById('userLabel');
  const roleLabel = document.getElementById('roleLabel');
  const msg = document.getElementById('adminMsg');
  const body = document.getElementById('resultsBody');
  const btn = document.getElementById('loadResults');

  userLabel.textContent = getUsername() || '-';
  roleLabel.textContent = getRole() || '-';
  if (!ensureRoleOrRedirect(['admin'])) return;

  btn.addEventListener('click', async () => {
    msg.textContent = '';
    body.innerHTML = '';
    const token = getToken();
    if (!token) { msg.textContent = 'Debe iniciar sesión'; return; }
    try {
      const res = await fetch('/admin/results', { headers: { 'Authorization': 'Bearer ' + token } });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'No autorizado');
      for (const r of data.results) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${r.id}</td><td>${r.vote_hash_hex}</td><td>${r.plaintext}</td><td>${r.timestamp}</td>`;
        body.appendChild(tr);
      }
    } catch (err) {
      msg.textContent = err.message;
    }
  });

  // Formulario de creación de usuario (administrador)
  const createForm = document.getElementById('createUserForm');
  const createMsg = document.getElementById('createMsg');
  const createdPrivateKey = document.getElementById('createdPrivateKey');
  if (createForm) createForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    createMsg.textContent = '';
    createdPrivateKey.value = '';
    const username = document.getElementById('createUsername').value;
    const role = document.getElementById('createRole').value;
    const password = document.getElementById('createPassword') ? document.getElementById('createPassword').value : undefined;
    const token = getToken();
    if (!token) { createMsg.textContent = 'Debe iniciar sesión como admin'; return; }
    try {
      if (!password) { createMsg.textContent = 'La contraseña inicial es obligatoria.'; return; }
      const body = { username, role, password };
      const res = await fetch('/auth/register', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        // Mensaje claro si el usuario ya existe
        if (data && data.detail && data.detail.toLowerCase().includes('ya existe')) {
          createMsg.textContent = `El usuario '${username}' ya existe.`;
        } else {
          throw new Error(data.detail || 'Error creando usuario');
        }
        return;
      }
      createMsg.textContent = 'Usuario creado: ' + data.username + '. Guarde la clave privada y entréguesela al usuario.';
      createdPrivateKey.value = data.private_key_pem || '';

      // Descargar automáticamente la clave privada como archivo de texto
      try {
        const pem = data.private_key_pem || '';
        if (pem) {
          const blob = new Blob([pem], { type: 'text/plain;charset=utf-8' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          // Save as .txt per user request
          a.download = `${data.username || username}_private.txt`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }
      } catch (e) {
        // no bloquear si la descarga falla
        console.warn('No se pudo descargar automáticamente la clave privada', e);
      }
    } catch (err) {
      createMsg.textContent = err.message;
    }
  });

  // Intento de solicitar al gestor de contraseñas del navegador que guarde la credencial
  const saveCredentialBtn = document.getElementById('saveCredentialBtn');
  function buildCredentialForm(username, password) {
    // Crear un formulario temporal con atributos autocomplete
    const form = document.createElement('form');
    form.style.display = 'none';
    form.method = 'post';
    form.action = '#';
    const userInput = document.createElement('input');
    userInput.type = 'text';
    userInput.name = 'username';
    userInput.autocomplete = 'username';
    userInput.value = username;
    const passInput = document.createElement('input');
    passInput.type = 'password';
    passInput.name = 'password';
    passInput.autocomplete = 'new-password';
    passInput.value = password;
    form.appendChild(userInput);
    form.appendChild(passInput);
    document.body.appendChild(form);
    return { form, userInput, passInput };
  }

  // Show save button when createdPrivateKey has content (observe changes)
  const observer = new MutationObserver(() => {
    if (createdPrivateKey && createdPrivateKey.value && saveCredentialBtn) {
      saveCredentialBtn.style.display = 'inline-block';
    }
  });
  if (createdPrivateKey) observer.observe(createdPrivateKey, { attributes: true, childList: true, subtree: true });

  if (saveCredentialBtn) saveCredentialBtn.addEventListener('click', (ev) => {
    ev.preventDefault();
    const username = document.getElementById('createUsername').value || '';
    const password = createdPrivateKey.value || '';
    if (!password) return;
    // 1) Intentar Credential Management API (mejor opción si está soportada)
    (async () => {
      if (window.PasswordCredential && navigator.credentials && navigator.credentials.store) {
        try {
          const cred = new PasswordCredential({ id: username || '', password });
          await navigator.credentials.store(cred);
          alert('Intento de guardar la credencial realizado. Revise el gestor de contraseñas del navegador.');
          return;
        } catch (e) {
          console.warn('Credential Management API falló', e);
          // continuar a fallback
        }
      }

      // 2) Fallback: abrir una nueva pestaña y enviar un formulario POST a /auth/save-credential
      // Muchos gestores/Chrome detectan el envío de formularios normales como un inicio de sesión.
      try {
        const w = window.open('', '_blank');
        if (!w) throw new Error('No se pudo abrir nueva pestaña (popup bloqueado)');
        const doc = w.document;
        const form = doc.createElement('form');
        form.method = 'post';
        form.action = '/auth/save-credential';
        const u = doc.createElement('input'); u.type = 'text'; u.name = 'username'; u.value = username || '';
        const p = doc.createElement('input'); p.type = 'password'; p.name = 'password'; p.value = password;
        form.appendChild(u); form.appendChild(p);
        doc.body.appendChild(form);
        // submit desde la nueva pestaña (esto es un gesto de usuario porque viene del click)
        form.submit();
        // Nota: la nueva pestaña mostrará una página mínima indicando que puede cerrarla.
      } catch (e) {
        console.warn('Fallback de formulario en nueva pestaña falló', e);
        // Último recurso: crear un formulario invisible en la misma ventana y submit
        try {
          const { form } = buildCredentialForm(username, password);
          form.querySelector('input[name="password"]').focus();
          form.submit();
          setTimeout(() => { try { document.body.removeChild(form); } catch{} }, 1500);
        } catch (ee) {
          console.warn('No se pudo forzar solicitud de guardado de credencial', ee);
          alert('No se pudo solicitar automáticamente al navegador. Copie la clave privada y guárdela en su gestor de contraseñas (ej. Chrome, Bitwarden).');
        }
      }
    })();
  });
});