# Sistema de Votación Digital Segura — Informe de Entrega 1

## Resumen Ejecutivo
- Se implementó una aplicación Web que permite registrar, autenticar y emitir votos cifrados, con auditoría y administración segura.
- La seguridad se basa en criptografía moderna: PBKDF2-SHA256 para contraseñas, RSA-OAEP para cifrado de votos, RSA-PSS para firmas, y un ledger encadenado con SHA-256.
- Se incorporó autenticación basada en JWT con control de roles (`voter`, `auditor`, `admin`), registros de auditoría y herramientas administrativas (visualización de logs y visor SQL de solo lectura).
- Se resolvieron problemas iniciales con `bcrypt` migrando a `PBKDF2-SHA256` y se corrigió el manejo del `Authorization` en los endpoints.

## Contexto y Problema
- Problema del mundo real: garantizar elecciones digitales seguras, preservando confidencialidad del voto, integridad, trazabilidad auditable y separación de funciones por rol.
- El sistema busca un equilibrio entre anonimato del voto y verificabilidad del proceso, con capacidades administrativas y de auditoría.

## Objetivos y Alcance
- Permitir que usuarios se registren y obtengan un par de claves RSA (privada para el usuario, pública almacenada en el sistema).
- Emitir votos cifrados con la clave pública del sistema, firmados por el usuario para garantizar autenticidad.
- Registrar un ledger encadenado por hashes para asegurar inmutabilidad y rastreo de orden de votos.
- Proveer vistas y endpoints para auditores (ledger) y administradores (descifrado, logs, consultas SQL de solo lectura).

## Arquitectura Técnica
- Backend: FastAPI + SQLAlchemy + SQLite.
- Frontend: HTML/CSS/JS estático servido por FastAPI (`frontend/*`).
- Criptografía: `cryptography` (RSA-OAEP, RSA-PSS, SHA-256), `passlib` (PBKDF2-SHA256), `python-jose` (JWT HS256).
- Almacenamiento: `data/app.db` (SQLite), claves del sistema en `keys/`, secretos en `secrets/`.
- Certificados TLS opcionales en `certs/` para servir HTTPS local.

## Estructura de Archivos Relevante
- `backend/auth.py`: Registro, login, `/auth/me`, hashing y emisión de JWT.
- `backend/main.py`: Rutas de voto, ledger, administración (resultados, logs, SQL) y archivos estáticos.
- `backend/crypto_utils.py`: Utilitarios criptográficos, claves del sistema, SHA-256, descifrado RSA-OAEP, generación de par de claves de usuario.
- `backend/models.py`: Modelos `User`, `Vote`, `AuditLog`.
- `backend/schemas.py`: Esquemas Pydantic para requests/responses.
- `frontend/*`: Vistas y lógica de cliente, incluyendo cifrado y firma antes de enviar votos.
- `keys/system_private.pem`, `keys/system_public.pem`: Par RSA del sistema.
- `secrets/jwt_secret.txt`: Secreto para firmar JWT HS256.
- `certs/server.crt`, `certs/server.key`: Certificado y llave para HTTPS local.

## Funcionalidades Implementadas
- Registro (`POST /auth/register`):
  - Valida rol (`voter`, `auditor`, `admin`).
  - Genera par de claves RSA del usuario (privada devuelta al cliente, pública almacenada).
  - Hashea contraseña con PBKDF2-SHA256.
  - Registra `AuditLog` de la acción.
- Login (`POST /auth/login`):
  - Verifica credenciales con PBKDF2-SHA256.
  - Emite JWT HS256 (expira a las 8 horas) con `sub` y `role`.
  - Registra `AuditLog` de la acción.
- Identidad (`GET /auth/me`):
  - Retorna `username` y `role` según token.
- Votación (`POST /vote`):
  - Requiere rol `voter` y que el usuario no haya votado.
  - Verifica firma RSA-PSS del usuario sobre el ciphertext.
  - Almacena el voto cifrado (Base64), firma y hash SHA-256 del ciphertext, encadenado con el hash previo.
  - Registra `AuditLog` y marca `has_voted`.
- Ledger (`GET /ledger`):
  - Paginado y visible para `auditor` y `admin`.
  - Muestra `id`, `vote_hash_hex`, `prev_hash_hex`, `timestamp`.
- Resultados admin (`GET /admin/results`):
  - `admin` puede descifrar votos con la clave privada del sistema.
  - Muestra texto plano, hash y timestamp.
- Logs admin (`GET /admin/logs`):
  - `admin` lista auditoría paginada (acción, IP, usuario, timestamp).
- SQL admin (`POST /admin/sql`):
  - `admin` ejecuta consultas `SELECT` seguras de solo lectura, retornando columnas y filas.

## Seguridad Aplicada
- Datos en reposo:
  - Contraseñas con PBKDF2-SHA256 (310,000 iteraciones, sal aleatoria gestionada por `passlib`).
  - Claves RSA del sistema almacenadas en `keys/` (sin contraseñas por simplicidad en esta entrega).
  - Base de datos SQLite en `data/app.db`.
  - Auditoría de acciones en `audit_logs`.
- Datos en tránsito:
  - Soporte para HTTPS local usando `certs/server.crt` y `certs/server.key` (opcional en desarrollo).
- Gestión de accesos:
  - Token JWT HS256 firmado con secreto en `secrets/jwt_secret.txt`.
  - Control de roles en backend (`require_role`) y frontend (`ensureRoleOrRedirect`).
  - Lectura explícita de `Authorization: Bearer` en endpoints sensibles.
- Registro y trazabilidad:
  - `AuditLog`: registra `register`, `login`, `vote_submitted` con IP y timestamp.
  - Ledger encadenado con `prev_hash_hex` para detectar alteraciones.

## Criptografía y Configuraciones
- Contraseñas: `PBKDF2-SHA256` con `rounds=310000` (resuelve incompatibilidad de `bcrypt` y evita límite de 72 bytes).
- Votos: Cifrado `RSA-OAEP` (MGF1 con SHA-256) con clave pública del sistema.
- Firmas: `RSA-PSS` con SHA-256 y `saltLength=32` sobre el ciphertext.
- Ledger: `SHA-256` del ciphertext, encadenado por `prev_hash_hex`.
- JWT: `HS256`, expiración 8 horas.

## Modelos y Datos
- `User`: `username`, `password_hash`, `role`, `public_key_pem`, `has_voted`.
- `Vote`: `encrypted_vote_b64`, `signature_b64`, `vote_hash_hex`, `prev_hash_hex`, `timestamp`.
- `AuditLog`: `user_id`, `action`, `ip`, `timestamp`.

## Flujo de Usuario
- Registro: Usuario define rol, recibe su clave privada PEM para almacenar de forma segura.
- Login: Obtiene JWT; el frontend consulta `/auth/me` y redirige según rol.
- Votación (voter): Pega su clave privada; el frontend cifra con la clave pública del sistema y firma el ciphertext, envía a `/vote`.
- Auditoría (auditor/admin): Visualiza ledger paginado.
- Administración (admin): Descifra resultados, revisa logs y ejecuta consultas `SELECT` seguras.

## Riesgos y Amenazas
- Robo de clave privada del usuario (si la guarda de forma insegura).
- Compromiso de `system_private.pem` (posible descifrado de todos los votos).
- Exposición del `jwt_secret.txt`, permitiendo tokens forjados.
- Ataques de inyección SQL: mitigados por restricción a `SELECT` y validaciones; aún requiere vigilancia.
- Denegación de servicio por abuso de endpoints.
- Fuga de la base de datos `app.db` (exposición de metadata y auditoría; los votos permanecen cifrados).

## Plan de Respuesta ante Incidentes
- Contención:
  - Rotar `jwt_secret.txt` y revocar tokens activos.
  - Invalidar y regenerar par de claves del sistema, emitir nuevo `system_public.pem` y migrar a nueva campaña.
  - Bloquear cuentas comprometidas y forzar reseteo de contraseñas.
- Erradicación:
  - Analizar logs (`/admin/logs`) para vector de ataque.
  - Aplicar parches y revisiones de configuración.
- Recuperación:
  - Restaurar `data/app.db` desde backups verificados.
  - Revalidar integridad del ledger via hashes encadenados.
- Comunicación:
  - Notificar a afectados, documentar hallazgos y medidas.

## Continuidad, Backups y DRP
- Backups regulares de `data/app.db`, `keys/`, `secrets/` con cifrado del medio de almacenamiento.
- Procedimiento de restauración probado en entorno de staging.
- Separación de ambientes (desarrollo/producción) y rotación de llaves entre campañas electorales.

## Estrategias de Uso Seguro de Datos
- Políticas de manejo de claves privadas por parte del usuario (no compartir, almacenamiento cifrado local).
- Procedimientos de alta/baja de roles y auditorías periódicas.
- Concientización: material breve de buenas prácticas al registrarse.

## Herramientas de Análisis Propuestas (no ejecutadas en esta entrega)
- SAST: Bandit para Python.
- Dependencias: `pip-audit` y `Safety`.
- Análisis de contenedores (si aplica): Trivy.
- Revisión de configuración TLS y encabezados HTTP (security headers).

## Pruebas y Verificación
- Verificación manual de flujos:
  - Registro y recepción de clave privada.
  - Login, lectura de rol con `/auth/me` y redirección.
  - Emisión de voto, verificación de firma y registro en ledger.
  - Visualización de ledger (auditor/admin) y resultados (admin, con descifrado).
  - Administración: logs paginados y consultas `SELECT` en visor SQL.
- Correcciones aplicadas:
  - Migración de `bcrypt` a `PBKDF2-SHA256` por error `bcrypt.__about__` y límite de 72 bytes.
  - Lectura correcta de `Authorization` en endpoints.
  - Implementación de `/auth/me` para reconocimiento de rol y redirección en frontend.

## Lecciones Aprendidas
- Las dependencias criptográficas deben elegirse considerando compatibilidad de entorno (evitar bloqueos como `bcrypt`).
- Es clave unificar la interpretación del token en backend y frontend para evitar incoherencias de sesión.
- Entregar la clave privada al usuario habilita firmas fuertes, pero requiere UX y educación de seguridad para manejo adecuado.

## Retrospectiva del Equipo
- Fortalezas: diseño claro de roles y flujos, criptografía aplicada coherente, auditoría funcional.
- Áreas de mejora: automatizar HTTPS en desarrollo, mejorar validaciones en visor SQL, guías de uso de claves privadas.
- Próximos pasos: modularizar campañas, agregar autenticación reforzada y métricas.

## Recomendaciones Futuras
- Forzar HTTPS y HSTS en despliegue.
- Rotación de claves del sistema por campaña y archivado de campañas cerradas.
- 2FA/TOTP para `admin` y `auditor`.
- Token refresh/rotación y lista de revocación.
- Exportación del ledger (CSV/JSON) y verificación pública (Merkle tree).
- Endpoints de resultados agregados (conteo por opción) sin descifrar globalmente, si el esquema lo permite.

## Roadmap para Entrega 2
- Módulo de campañas electorales (multievento) con aislamiento de claves y datos.
- Panel resumen en `admin.html` (métricas y estado del sistema).
- Exportaciones y verificación pública del ledger.
- Endurecimiento del visor SQL (whitelist de tablas, límites adicionales).
- Políticas de seguridad documentadas y material de concientización para usuarios.

## Instrucciones de Ejecución
- Instalar dependencias:
  - `pip install -r requirements.txt`
- Iniciar servidor HTTP:
  - `uvicorn backend.main:app --host 0.0.0.0 --port 8000`
- Iniciar servidor HTTPS (opcional, si existen `certs/server.crt` y `certs/server.key`):
  - `uvicorn backend.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt`
- Navegar a `http://localhost:8000/` (o `https://localhost:8000/`).

## Referencias Internas
- Clave pública del sistema: `GET /keys/system-public`.
- Endpoints principales: `/auth/register`, `/auth/login`, `/auth/me`, `/vote`, `/ledger`, `/admin/results`, `/admin/logs`, `/admin/sql`.

---

Este informe documenta el estado de la Entrega 1, cubriendo implementación, seguridad, riesgos y plan de mejora. Se recomienda integrarlo a GitHub Pages o Notion para su presentación y seguimiento.
