# Objetivo
Consolidar la segunda entrega resolviendo el feedback (anonimato y uso del ledger) y cubriendo la rúbrica completa: elevar funcionalidad, fortalecer seguridad en reposo/transporte, añadir análisis de seguridad, definir riesgos y plan de respuesta, y documentar recomendaciones futuras.

## Observaciones del feedback
- Anonimato: aclarar modelo de anonimidad (unlinkability en almacenamiento) y añadir mecanismos anti-spoofing sin exponer identidad.
- Ledger: fundamentar como cadena de integridad (append-only hash chain) y evitar confundirlo con PoW; añadir anclaje/verificación eficiente.
- Funcionalidad: evitar revisión voto a voto; ofrecer agregados, filtros y visualizaciones.

## Cambios propuestos (funcionalidad)
1. Endpoint de agregados: `GET /results/summary` con conteos, porcentajes y totales por candidato (para `auditor`/`admin`).
2. Visualización: gráficos en `audit.html` y `admin.html` (barras/pie) consumiendo `results/summary`.
3. Ledger eficiente: paginación ya existente (`/ledger`); añadir export CSV y búsqueda por `vote_hash_hex`.
4. Pruebas manuales guiadas: scripts de datos sintéticos para probar con grandes volúmenes.

## Anonimato y anti-spoofing
1. Modelo de anonimidad: los votos se almacenan sin `user_id` (ver `backend/models.py:21-31`); autenticidad en el momento de emitir via firma con clave del usuario.
2. Token de boleta de un solo uso:
   - Emisión: `POST /auth/issue-ballot` entrega un `ballot_token` (JWT con `jti` aleatorio, sin `sub`) sólo a `voter` autenticado.
   - Uso: `POST /vote` requiere `ballot_token` vigente + firma RSA-PSS del ciphertext con la clave privada del usuario; el backend marca `jti` como usado y no guarda `user_id` junto al voto.
   - Beneficio: reduce el vínculo directo entre identidad y acto de voto; previene spoofing porque se exige posesión de la clave privada.
3. Anti-replay: invalidar `ballot_token` al uso, registrar `vote_hash_hex` y rechazar duplicados.
4. Tiempos y correlación: registrar ventanas de emisión/uso y anonimizar timestamps en reporte público (redacción en README).

## Seguridad de datos (reposo y transporte)
1. En reposo:
   - Votos cifrados ya con `RSA-OAEP`; mantener claves del sistema en `keys/` y reforzar permisos de filesystem.
   - Backups automáticos: script de copia de `data/app.db`, `keys/` y `secrets/` a `backups/` con retención y verificación de integridad (hash/SHA-256).
   - Logs de auditoría: añadir HMAC opcional por entrada para detección de manipulación.
2. En transporte:
   - TLS: generar certificado self-signed (`backend/crypto_utils.py`) y documentar arranque con `--ssl-keyfile/--ssl-certfile`.
   - Seguridad de sesión: expiración JWT, revocación de sesión en logout y rotación del `SECRET_KEY`.
3. Accesos:
   - Roles estrictos ya aplicados (`backend/main.py:82-85`); añadir rate limiting básico y bloqueo por intentos fallidos.

## Estrategias de uso seguro de datos
- Políticas: separación de funciones (votante/auditor/admin), acceso mínimo necesario.
- Procedimientos: manejo de claves privadas de usuario client-side; rotación trimestral de claves del sistema; checklist de despliegue (TLS, backups, rotación de secretos).
- Concientización: guía de buenas prácticas para usuarios y administradores en `README.md` (almacenamiento seguro de claves, phishing, uso de dispositivos confiables).

## Herramientas de análisis de seguridad
1. Análisis estático: integrar `bandit` sobre `backend/` con reporte HTML en `reports/bandit.html`.
2. Dependencias: `pip-audit` o `safety` para CVEs.
3. DAST: ejecutar `OWASP ZAP Baseline Scan` contra `http://127.0.0.1:8000` y publicar hallazgos en `reports/zap.md`.

## Riesgos y entidades afectadas
- Fuga de clave privada del sistema (afecta confidencialidad de todos los votos).
- Compromiso de JWT/credenciales del votante (spoofing y doble voto si no se controla `has_voted`).
- De-anonimización por correlación temporal/red (afecta privacidad del votante).
- Manipulación de base de datos/logs (afecta integridad y trazabilidad).
- DoS contra el servidor (afecta disponibilidad).

## Plan de respuesta ante incidentes
1. Detección: alertas por anomalías en logs y resultados de `bandit/safety/ZAP`.
2. Contención: revocar tokens, aislar servicios, congelar ledger con anclaje del tip actual.
3. Erradicación: parchear vulnerabilidades, rotar `SECRET_KEY` y claves del sistema.
4. Recuperación: restaurar desde backups verificados, revalidar ledger, comunicar a partes interesadas.
5. Postmortem: documentación y acciones correctivas.

## Recomendaciones futuras
- Credenciales ciegas (blind signatures) para tokens realmente unlinkables.
- Mixnets/verifiable shuffles para anonimato en tránsito.
- Cómputo verificable u homomórfico para conteo sin descifrar.
- HSM/TPM para custodiar la clave privada del sistema.
- Anclaje público del ledger (transparency logs o blockchain) para prueba independiente.

## Entregables de la entrega 2
- Código: nuevos endpoints (`/auth/issue-ballot`, `/results/summary`) y mejoras de seguridad (anti-replay, rate limiting).
- UI: gráficas y filtros en `audit.html`/`admin.html`.
- Scripts: `backup` y restauración.
- Reportes: `reports/bandit.html`, `reports/zap.md`, `reports/dependencies.md`.
- Documentación: README actualizado (modelo de anonimato, justificación del ledger, políticas/procedimientos, plan de incidentes).

¿Confirmas este plan para proceder con la implementación paso a paso?