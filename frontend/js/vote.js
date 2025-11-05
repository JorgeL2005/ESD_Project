document.addEventListener('DOMContentLoaded', async () => {
  const userLabel = document.getElementById('userLabel');
  const roleLabel = document.getElementById('roleLabel');
  const voteMsg = document.getElementById('voteMsg');
  const btn = document.getElementById('sendVote');

  userLabel.textContent = getUsername() || '-';
  roleLabel.textContent = getRole() || 'voter';
  if (!ensureRoleOrRedirect(['voter'])) return;

  // Cargar clave pública del sistema
  let systemPubPem = null;
  try {
    const res = await fetch('/keys/system-public');
    const data = await res.json();
    systemPubPem = data.public_key_pem;
  } catch (err) {
    voteMsg.textContent = 'No se pudo obtener la clave pública del sistema';
    return;
  }

  btn.addEventListener('click', async () => {
    voteMsg.textContent = '';
    const token = getToken();
    if (!token) { voteMsg.textContent = 'Debe iniciar sesión'; return; }
    const vote = document.getElementById('voteInput').value;
    const privPem = document.getElementById('userPrivatePem').value;
    if (!vote) { voteMsg.textContent = 'Ingrese su voto'; return; }
    if (!privPem) { voteMsg.textContent = 'Pegue su clave privada'; return; }

    try {
      const publicKey = await importSystemPublicKey(systemPubPem);
      const encrypted_b64 = await encryptWithSystemPublicKey(publicKey, vote);
      // Firma sobre el ciphertext (bytes)
      const ciphertextBytes = Uint8Array.from(atob(encrypted_b64), c => c.charCodeAt(0));
      const privateKey = await importUserPrivateKey(privPem);
      const signature_b64 = await signData(privateKey, ciphertextBytes);

      const res = await fetch('/vote', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
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