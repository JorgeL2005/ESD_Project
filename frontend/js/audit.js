document.addEventListener('DOMContentLoaded', () => {
  const userLabel = document.getElementById('userLabel');
  const roleLabel = document.getElementById('roleLabel');
  const msg = document.getElementById('auditMsg');
  const body = document.getElementById('ledgerBody');
  const loadBtn = document.getElementById('loadLedger');

  userLabel.textContent = getUsername() || '-';
  roleLabel.textContent = getRole() || '-';
  if (!ensureRoleOrRedirect(['auditor','admin'])) return;

  async function loadLedger() {
    msg.textContent = '';
    body.innerHTML = '';
    const token = getToken();
    if (!token) { msg.textContent = 'Debe iniciar sesión'; return; }
    const page = parseInt(document.getElementById('pageInput').value, 10);
    const pageSize = parseInt(document.getElementById('pageSizeInput').value, 10);
    try {
      const res = await fetch(`/ledger?page=${page}&page_size=${pageSize}`, {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'No autorizado');
      for (const item of data.items) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${item.id}</td><td>${item.vote_hash_hex}</td><td>${item.prev_hash_hex || ''}</td><td>${new Date(item.timestamp).toLocaleString()}</td>`;
        body.appendChild(tr);
      }
      msg.textContent = `Página ${data.page} / ${(Math.ceil(data.total / data.page_size))}`;
    } catch (err) {
      msg.textContent = err.message;
    }
  }

  loadBtn.addEventListener('click', loadLedger);
});