document.addEventListener('DOMContentLoaded', async () => {
  const userLabel = document.getElementById('userLabel');
  const roleLabel = document.getElementById('roleLabel');
  const voteMsg = document.getElementById('voteMsg');
  const btn = document.getElementById('sendVote');

  userLabel.textContent = getUsername() || '-';
  roleLabel.textContent = getRole() || 'voter';
  if (!ensureRoleOrRedirect(['voter'])) return;

  // Cargar clave pública del sistema
  
  // ========================
// Cargar lista de candidatos
// ========================
async function loadCandidates() {
  const resp = await fetch('/candidates'); 
  const data = await resp.json();

  const sel = document.getElementById('candidateSelect');
  sel.innerHTML = "";

  data.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.id;        // IMPORTANTE: Envías el ID
    opt.textContent = c.name;
    sel.appendChild(opt);
  });
}

await loadCandidates();
 let systemPubPem = null;
  try {
    const res = await fetch('/keys/system-public');
    const data = await res.json();
    systemPubPem = data.public_key_pem;
  } catch (err) {
    voteMsg.textContent = 'No se pudo obtener la clave pública del sistema';
    return;
  }

  // Intentar recuperar credenciales almacenadas (PEM) para autocompletar área de clave si está disponible
  // Intentar recuperar credenciales almacenadas (PEM) para autocompletar área de clave si está disponible.
  // If found, inject the textarea into the DOM; if not found, do not show any UI for the key.
  (async () => {
    try {
      if (navigator.credentials && navigator.credentials.get) {
        const cred = await navigator.credentials.get({ password: true, mediation: 'optional' });
        if (cred && cred.type === 'password') {
          const kc = document.getElementById('keyContainer');
          if (kc) {
            // create textarea only when credential is available
            const ta = document.createElement('textarea');
            ta.id = 'userPrivatePem';
            ta.rows = 6;
            ta.placeholder = '-----BEGIN PRIVATE KEY-----\n...';
            ta.value = cred.password || '';
            kc.appendChild(ta);
            kc.style.display = 'block';
          }
        }
      }
    } catch (e) {
      console.debug('Credential retrieval not available in vote page', e);
    }
  })();

  // Allow user to paste their PRIMARY KEY manually if they choose
  const pasteBtn = document.getElementById('pasteKeyBtn');
  if (pasteBtn) {
    pasteBtn.addEventListener('click', () => {
      const kc = document.getElementById('keyContainer');
      if (!kc) return;
      let ta = document.getElementById('userPrivatePem');
      if (!ta) {
        ta = document.createElement('textarea');
        ta.id = 'userPrivatePem';
        ta.rows = 6;
        ta.placeholder = 'Pegue su PRIMARY KEY (PKCS8 PEM) aquí';
        kc.appendChild(ta);
      }
      // toggle visibility
      kc.style.display = (kc.style.display === 'block') ? 'none' : 'block';
      if (kc.style.display === 'block') ta.focus();
    });
  }

  // File upload: single file
  const uploadFileBtn = document.getElementById('uploadFileBtn');
  const uploadKeyInput = document.getElementById('uploadKeyInput');
  if (uploadFileBtn && uploadKeyInput) {
    uploadFileBtn.addEventListener('click', () => uploadKeyInput.click());
    uploadKeyInput.addEventListener('change', (ev) => {
      const f = ev.target.files && ev.target.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result || '');
        handlePemText(text);
      };
      reader.readAsText(f, 'utf-8');
    });
  }

  // Directory upload removed — keep single-file upload for compatibility

  function handlePemText(text) {
    if (!text || typeof text !== 'string') return;
    const begin = '-----BEGIN PRIVATE KEY-----';
    const end = '-----END PRIVATE KEY-----';
    if (!text.includes(begin) || !text.includes(end)) {
      voteMsg.textContent = 'El archivo no contiene una clave privada en formato PEM válido.';
      return;
    }
    // Ensure textarea exists and populate it
    const kc = document.getElementById('keyContainer');
    if (!kc) return;
    let ta = document.getElementById('userPrivatePem');
    if (!ta) {
      ta = document.createElement('textarea');
      ta.id = 'userPrivatePem';
      ta.rows = 6;
      ta.placeholder = '-----BEGIN PRIVATE KEY-----\n...';
      kc.appendChild(ta);
    }
    ta.value = text.trim();
    kc.style.display = 'block';
    ta.focus();
    voteMsg.textContent = '';
  }

  btn.addEventListener('click', async () => {
    voteMsg.textContent = '';
    const token = getToken();
    if (!token) { voteMsg.textContent = 'Debe iniciar sesión'; return; }
    const vote = document.getElementById('candidateSelect').value;
    const privPemEl = document.getElementById('userPrivatePem');
    const privPem = privPemEl ? privPemEl.value.trim() : '';
    if (!vote) { voteMsg.textContent = 'Ingrese su voto'; return; }
    if (!privPem) { voteMsg.textContent = "Haga clic en 'Mostrar / Ingresar clave privada' y pegue o cargue su PRIMARY KEY para firmar el voto."; return; }

    try {
      // Solicitar token de boleta de un solo uso
      const issueRes = await fetch('/auth/issue-ballot', { headers: { 'Authorization': 'Bearer ' + token }, method: 'POST' });
      const issueData = await issueRes.json();
      if (!issueRes.ok) throw new Error(issueData.detail || 'No se pudo obtener token de boleta');

      const publicKey = await importSystemPublicKey(systemPubPem);
      const encrypted_b64 = await encryptWithSystemPublicKey(publicKey, vote);
      // Firma sobre el ciphertext (bytes)
      const ciphertextBytes = Uint8Array.from(atob(encrypted_b64), c => c.charCodeAt(0));
      const privateKey = await importUserPrivateKey(privPem);
      const signature_b64 = await signData(privateKey, ciphertextBytes);

      const res = await fetch('/vote', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Ballot-Token': issueData.ballot_token },
        body: JSON.stringify({ encrypted_vote_b64: encrypted_b64, signature_b64 })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Error al emitir voto');
      voteMsg.textContent = 'Voto emitido. Hash: ' + data.vote_hash_hex;
    } catch (err) {
      voteMsg.textContent = err.message;
    }
  });
});
