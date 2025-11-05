document.addEventListener('DOMContentLoaded', () => {
  const userLabel = document.getElementById('userLabel');
  const roleLabel = document.getElementById('roleLabel');
  const msg = document.getElementById('sqlMsg');
  const runBtn = document.getElementById('runQuery');
  const columnsRow = document.getElementById('columnsRow');
  const rowsBody = document.getElementById('rowsBody');

  userLabel.textContent = getUsername() || '-';
  roleLabel.textContent = getRole() || '-';
  if (!ensureRoleOrRedirect(['admin'])) return;

  runBtn.addEventListener('click', async () => {
    msg.textContent = '';
    columnsRow.innerHTML = '';
    rowsBody.innerHTML = '';
    const token = getToken();
    if (!token) { msg.textContent = 'Debe iniciar sesión'; return; }
    const query = document.getElementById('sqlQuery').value;
    try {
      const res = await fetch('/admin/sql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ query })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Consulta inválida');
      // columnas
      for (const c of data.columns) {
        const th = document.createElement('th');
        th.textContent = c;
        columnsRow.appendChild(th);
      }
      // filas
      for (const row of data.rows) {
        const tr = document.createElement('tr');
        tr.innerHTML = row.map(cell => `<td>${cell === null ? '' : cell}</td>`).join('');
        rowsBody.appendChild(tr);
      }
      msg.textContent = `Filas: ${data.rows.length}`;
    } catch (err) {
      msg.textContent = err.message;
    }
  });
});