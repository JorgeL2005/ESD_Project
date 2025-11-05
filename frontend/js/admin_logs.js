document.addEventListener('DOMContentLoaded', () => {
  const userLabel = document.getElementById('userLabel');
  const roleLabel = document.getElementById('roleLabel');
  const msg = document.getElementById('logsMsg');
  const body = document.getElementById('logsBody');
  const btn = document.getElementById('loadLogs');

  userLabel.textContent = getUsername() || '-';
  roleLabel.textContent = getRole() || '-';
  if (!ensureRoleOrRedirect(['admin'])) return;

  btn.addEventListener('click', async () => {
    msg.textContent = '';
    body.innerHTML = '';
    const token = getToken();
    if (!token) { msg.textContent = 'Debe iniciar sesión'; return; }
    const page = parseInt(document.getElementById('pageInput').value, 10);
    const pageSize = parseInt(document.getElementById('pageSizeInput').value, 10);
    try {
      const res = await fetch(`/admin/logs?page=${page}&page_size=${pageSize}`, { headers: { 'Authorization': 'Bearer ' + token } });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'No autorizado');
      for (const r of data.items) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${r.id}</td><td>${r.username || ''}</td><td>${r.action}</td><td>${r.ip || ''}</td><td>${new Date(r.timestamp).toLocaleString()}</td>`;
        body.appendChild(tr);
      }
      msg.textContent = `Página ${data.page} / ${Math.ceil(data.total / data.page_size)}`;
    } catch (err) {
      msg.textContent = err.message;
    }
  });
});