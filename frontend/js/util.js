const API_BASE = '';

function saveToken(token, username, role) {
  localStorage.setItem('token', token);
  localStorage.setItem('username', username);
  localStorage.setItem('role', role);
}

function getToken() { return localStorage.getItem('token'); }
function getUsername() { return localStorage.getItem('username'); }
function getRole() { return localStorage.getItem('role'); }

function requireRole(roles) {
  const role = getRole();
  return roles.includes(role);
}

function ensureRoleOrRedirect(roles) {
  const role = getRole();
  if (!role) {
    window.location.href = '/';
    return false;
  }
  if (!roles.includes(role)) {
    // Redirigir a la página adecuada
    if (role === 'admin') {
      window.location.href = '/static/admin.html';
    } else if (role === 'auditor') {
      window.location.href = '/static/audit.html';
    } else {
      window.location.href = '/static/vote.html';
    }
    return false;
  }
  return true;
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const binaryString = atob(b64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

async function importSystemPublicKey(spkiPem) {
  const keyData = pemToArrayBuffer(spkiPem);
  return await crypto.subtle.importKey(
    'spki',
    keyData,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

async function importUserPrivateKey(pkcs8Pem) {
  const keyData = pemToArrayBuffer(pkcs8Pem);
  return await crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function encryptWithSystemPublicKey(publicKey, message) {
  const enc = new TextEncoder();
  const data = enc.encode(message);
  const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
}

async function signData(privateKey, dataBytes) {
  const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, dataBytes);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}