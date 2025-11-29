# Informe de Cambios y Estado — Proyecto Votación Digital Segura

Fecha: 28 de noviembre de 2025

Resumen
-------
Este documento resume los cambios realizados en el repositorio `ESD_Project` y recoge:
- objetivos del sistema,
- decisiones de seguridad y criptografía,
- lista de archivos modificados y nuevas utilidades,
- instrucciones para probar y pasos siguientes.

Se basa en el contenido del `README.md` y en los cambios implementados en esta sesión de desarrollo.

Objetivos del proyecto
----------------------
- Proveer un sistema de votación digital con: registro controlado, autenticación, firma y cifrado de votos, ledger encadenado y auditoría.
- Separación de roles: `voter`, `auditor`, `admin`.
- UX para entrega segura de la clave privada del votante (PRIMARY KEY) y opciones para guardar/descargar dicha clave.

Cambios principales (resumen de esta sesión)
-------------------------------------------
1. Autenticación
- Se aplicó y estabilizó el modelo de autenticación con contraseñas hasheadas usando PBKDF2-SHA256.
# Informe de Cambios y Estado — Proyecto Votación Digital Segura

Fecha: 28 de noviembre de 2025

Resumen
-------
Documento integral que reúne el contenido del `README.md` y añade todas las modificaciones aplicadas durante la sesión de desarrollo: cambios en autenticación, nuevas utilidades, mejoras de UX, incorporación de PoW parcial, correcciones en scripts y medidas de seguridad adicionales.

Contenido principal
------------------
- Resumen ejecutivo
- Contexto, objetivos y alcance
- Arquitectura técnica
- Funcionalidades implementadas (endpoints clave)
- Cambios recientes y su impacto en seguridad (PoW, auth, frontend, scripts)
- Listado de archivos modificados
- Cómo probar localmente
- Riesgos, mitigaciones y recomendaciones
- Próximos pasos sugeridos

1) Resumen ejecutivo
--------------------
Aplicación web para emisión de votos cifrados, con roles (`voter`, `auditor`, `admin`), ledger encadenado y auditoría. Criptografía aplicada: PBKDF2-SHA256 para contraseñas, RSA-OAEP para cifrado de votos, RSA-PSS para firmas, SHA-256 para hashes del ledger, JWT (HS256) para sesiones.

2) Contexto y problema
----------------------
Garantizar un flujo de votación digital que preserve confidencialidad, integridad y trazabilidad (auditabilidad) sin revelar la identidad del votante junto con su voto (separación entre emisión de token de boleta y el envío del voto).

3) Objetivos y alcance
----------------------
- Registro administrado por la autoridad (admin) y entrega de PRIMARY KEY al usuario.
- Emisión de votos cifrados y firmados por el votante.
- Ledger encadenado con hashes SHA-256 para detectar alteraciones.
- Herramientas para auditoría y administración (visor de logs, visor SQL readonly, resultados descifrados para admin).

4) Arquitectura técnica
----------------------
- Backend: FastAPI + SQLAlchemy + SQLite (`data/app.db`).
- Frontend: HTML/CSS/JS en `frontend/` con WebCrypto para firma/operaciones cliente.
- Criptografía: `cryptography` y utilitarios propios en `backend/crypto_utils.py`.
- Almacenamiento seguro de secretos: `secrets/jwt_secret.txt`, claves del sistema en `keys/`.

5) Funcionalidades implementadas (endpoints clave)
-------------------------------------------------
- `POST /auth/register` — registro administrado (admin). Requiere `password`, genera par RSA, devuelve `private_key_pem` para descarga (admin entrega la clave al usuario).
- `POST /auth/login` — login por contraseña (PBKDF2-SHA256) → emite JWT HS256.
- `GET /auth/me` — retorna `username` y `role` desde token.
- `POST /auth/issue-ballot` — emite token de boleta de un uso (JWT tipo `ballot` con `jti`), persistiendo `BallotToken` con la clave pública del usuario; permite verificar firma del voto sin exponer directamente la identidad durante el envío.
- `POST /vote` — recibe `encrypted_vote_b64` y `signature_b64` con `X-Ballot-Token`; verifica firma RSA-PSS usando la clave pública ligada al token y almacena el voto cifrado y el hash encadenado.
- `GET /ledger` — listado paginado de items del ledger para auditoría (auditor/admin).
- `GET /admin/results`, `GET /admin/logs`, `POST /admin/sql` — herramientas administrativas con control de acceso.

6) Cambios relevantes y mejoras de seguridad
-------------------------------------------
Los cambios realizados fortalecen la seguridad y la usabilidad del sistema:

- Autenticación y contraseñas:
  - Migración definitiva a `PBKDF2-SHA256` con 310000 rondas (compatibilidad y robustez).
  - `RegisterRequest.password` ahora obligatorio y validado en backend.
  - `scripts/create_admin.py` solicita contraseña interactiva, la confirma y la hashea antes de guardar.

- Registro administrado y UX de claves:
  - El registro de usuarios es administrado; la `private_key_pem` generada se devuelve para descarga como `.txt` y se recomienda entrega física.
  - Frontend intenta solicitar al navegador guardar la credencial (Credential Management API) y ofrece un fallback con un POST a `/auth/save-credential`.

- Manejo de PRIMARY KEY en frontend (votación):
  - Opciones para pegar la PRIMARY KEY o cargar un archivo `.txt`/`.pem` con la clave en PEM completa.
  - Validación mínima por marcadores PEM; la `textarea` solo se muestra si el usuario lo solicita o una credencial está disponible.

- Ledger y PoW:
  - Ledger encadenado con SHA-256 para integridad.
  - Implementación de PoW ligera (nonce y `pow_hash_hex`) para incluir una prueba de trabajo en registros de `Vote` cuando se requiera.

- Scripts y mantenimiento:
  - `create_admin.py` y `set_user_passwords.py` actualizados para operar correctamente desde la raíz del proyecto; el primero ahora guarda `private_key` como `.txt` y registra auditoría.

- Internacionalización/UX:
  - Interfaz visible traducida al español; se preserva la expresión técnica `PRIMARY KEY` por petición expresada.

- Auditoría y controles:
  - `AuditLog` registra eventos importantes; logout borra credenciales locales y solicita prevenir accesos silenciosos.

7) Lista de archivos modificados (resumen por carpeta)
---------------------------------------------------
- backend/
  - `auth.py`, `schemas.py`, `crypto_utils.py`, `models.py` (campos PoW añadidos), `database.py`.
- frontend/
  - `index.html`, `admin.html`, `admin_logs.html`, `admin_sql.html`, `vote.html`, `audit.html`, `register.html`.
  - `js/*`: `auth.js`, `admin.js`, `vote.js`, `util.js`, `admin_logs.js`, `admin_sql.js`, `audit.js`.
- scripts/
  - `create_admin.py`, `set_user_passwords.py` (ajustes de import y ejecución), posibles utilidades de backup.
- otros
  - `informe.md` (este archivo), `README.md`, `keys/`, `secrets/`, `data/app.db` (eliminado en sesión de pruebas).

8) Cómo probar localmente (paso a paso)
-------------------------------------
1. Preparar entorno y dependencias:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Inicializar la base de datos (crear tablas):

```bash
python3 -c "from backend.database import init_db; init_db(); print('DB inicializada')"
```

3. Crear admin (interactivo):

```bash
python3 scripts/create_admin.py --username municipal_admin
```

4. Iniciar servidor:

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

5. Pruebas en navegador:
- `http://127.0.0.1:8001/` → Inicio de sesión.
- `http://127.0.0.1:8001/static/admin.html` → Crear usuarios (admin).
- `http://127.0.0.1:8001/static/vote.html` → Pegar o cargar PRIMARY KEY y enviar voto.

9) Validaciones de PEM en frontend
----------------------------------
- Se validan los marcadores `-----BEGIN PRIVATE KEY-----` y `-----END PRIVATE KEY-----`.
- Recomendación: añadir importación WebCrypto para validar estructura de clave antes de firmar.

10) Riesgos, mitigaciones y recomendaciones
-------------------------------------------
- Riesgos principales: compromiso de claves privadas, exposición de `jwt_secret`, compromiso de `system_private`.
- Recomendaciones: forzar cambio de contraseña en primer login, rotar claves del sistema por campaña, usar HSM/KMS para `system_private`, exigir HTTPS en producción y proteger backups.

11) PoW (Proof-of-Work): descripción y efecto en seguridad
-------------------------------------------------------
Implementación ligera: uso de `nonce_int` y `pow_hash_hex` en `Vote` para permitir inclusión de PoW cuando se requiera. Mejora la dificultad para alterar retroactivamente el ledger local, con coste computacional adicional.

12) Registro de cambios y notas operativas
----------------------------------------
- `data/app.db` se ha eliminado para reinicio durante pruebas; re-inicializar antes de uso productivo.
- `scripts/set_user_passwords.py` realiza una migración temporal (username→password) si se necesita recuperar accesos; forzar cambio posterior.

13) Próximos pasos recomendados (priorizados)
-------------------------------------------
1. Validación WebCrypto en `frontend/js/vote.js`.
2. Políticas de contraseña y forzar cambio inicial.
3. Backups verificados y automatizados para `data/`, `keys/`, `secrets/`.
4. Pruebas de integración automatizadas.
5. Migración a HSM/KMS y Alembic para migraciones.

14) Comandos útiles
------------------
- Inicializar DB:
```bash
python3 -c "from backend.database import init_db; init_db(); print('DB inicializada')"
```
- Crear admin:
```bash
python3 scripts/create_admin.py --username municipal_admin
```
- Iniciar servidor:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```
- Ejecutar migración temporal de contraseñas:
```bash
python3 scripts/set_user_passwords.py
```

15) Documentación y entrega
---------------------------
Este `informe.md` complementa el `README.md` y documenta todas las decisiones, los cambios aplicados y su impacto en seguridad. Puede usarse para la Entrega 1 y como base para la planificación de la Entrega 2.

¿Quieres que también genere un `CHANGELOG.md` con diffs por archivo (lista de cambios aplicados en esta sesión)?
