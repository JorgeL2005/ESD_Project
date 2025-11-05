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
});