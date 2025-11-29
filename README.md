# Sistema de Votación Digital Segura 🗳️

Este proyecto implementa un sistema de votación electrónica diseñado para garantizar la confidencialidad, integridad y auditabilidad del proceso electoral. Utiliza criptografía asimétrica (RSA), un ledger inmutable basado en Proof of Work (PoW) y protocolos de anonimato mediante Ballot Tokens.

## 📄 Informe Final
**La documentación completa, análisis de diseño y detalles de implementación se encuentran en el archivo:**

👉 **`Entrega_Final_ESD.pdf`**

*(Este archivo se encuentra ubicado en la raíz de este directorio).*

---

## 🚀 Instalación y Configuración

### Prerrequisitos
- Python 3.13.9

### 1. Clonar el repositorio y preparar el entorno
Navega a la carpeta del proyecto:
```bash
git clone https://github.com/JorgeL2005/ESD_Project.git
cd ESD_Project

# (Opcional pero recomendado) Crea un entorno virtual:

# En Windows
python -m venv venv
venv\Scripts\activate

# En Mac/Linux
python3 -m venv venv
source venv/bin/activate
```


### 2. Instalar dependencias

Instala las librerías necesarias (FastAPI, SQLAlchemy, Cryptography, Passlib, etc.):

```bash
pip install -r requirements.txt
```

-----

## ⚙️ Ejecución del Proyecto

### 1. Inicialización y Creación del Administrador

Antes de iniciar el servidor, debes crear la cuenta del **Administrador (Autoridad Electoral)** si esta aún no ha sido creada. Esta cuenta es necesaria para registrar votantes.

Ejecuta el script de creación:

```bash
python scripts/create_admin.py --username municipal_admin
```

### 2\. Iniciar el Servidor

Ejecuta la aplicación utilizando Uvicorn desde la raíz del proyecto:

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

El sistema estará disponible en: **`http://localhost:8000`**

-----

## 📖 Guía de Uso Rápida

### Rol: Administrador (Autoridad Electoral)

1.  Inicia sesión en `http://localhost:8000` con la cuenta creada en el paso anterior.
2.  Navega al panel de administración (`/static/admin.html`).
3.  **Registrar Votante:** Crea un nuevo usuario con rol `voter`.
      - ⚠️ **Importante:** El sistema mostrará la **Clave Privada** del usuario una sola vez. Debes copiarla y entregarla al votante (archivo `.txt` o impresa). El sistema no guarda esta clave.
4.  **Resultados:** Al finalizar, puede ver los resultados descifrados.

### Rol: Votante

1.  Inicia sesión con las credenciales proporcionadas por el administrador.
2.  En la pantalla de voto (`/static/vote.html`), carga o pega tu **Clave Privada (Primary Key)**.
3.  Selecciona tu candidato y envía el voto.
      - *Nota:* El sistema usa un `Ballot Token` para anonimizar tu voto.

### Rol: Auditor

1.  Inicia sesión con una cuenta de rol `auditor` (creada por el admin).
2.  Navega a la auditoría (`/static/audit.html`).
3.  **Verificar Integridad:** Usa el botón para validar matemáticamente que la cadena de bloques (hashes) y el Proof of Work (PoW) son correctos y no han sido manipulados.

-----

## 🛡️ Características Técnicas

  * **Backend:** FastAPI + SQLite.
  * **Seguridad:** RSA-OAEP (Cifrado), RSA-PSS (Firmas), PBKDF2 (Hashing de contraseñas).
  * **Integridad:** Ledger con Proof of Work (SHA-256 + Nonce).
  * **Anonimato:** Desacoplamiento de identidad vía `X-Ballot-Token`.

-----

## 👥 Autores

  * Jorge Alexander Leon Villareyes
  * Diva Stewart Maquera Bobadilla
  * Rodrigo Li Chumpitaz
  * Camila Pamela Acosta Arostegui

**Curso:** Ética y Seguridad de los Datos  
**Universidad de Ingeniería y Tecnología (UTEC)**
