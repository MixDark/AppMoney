# App Money - Gestor de finanzas personales

Una aplicación web para gestionar ingresos, gastos e inversiones de forma segura y eficiente.

## 🚀 Funcionalidades principales

### 1. **Autenticación de usuarios**
- Registro de nuevos usuarios
- Login seguro con validación de contraseña
- Autenticación de dos Factores (2FA) con OTP
- Gestión de sesiones
- Opción de editar perfil y cambiar contraseña
- Recuperación de contraseña con CAPTCHA
- Foto de perfil almacenada en base de datos

### 2. **Autenticación de dos factores (2FA)** ⭐
- Configuración de TOTP (Time-based One-Time Password)
- Generación de código QR para escanear en aplicaciones autenticadoras
- Modal flotante elegante para verificación de código OTP
- Validación con ventanas de tiempo seguras
- Soporte para Google Authenticator, Authy, Microsoft Authenticator

### 3. **Dashboard consolidado**
- Vista general de finanzas (ingresos, gastos, inversiones y saldo)
- Gráfico de distribución (pastel) mostrando proporciones
- Gráfico comparativo (líneas) con evolución temporal
- Historial de transacciones recientes por categoría
- Totales resumidos de cada categoría

### 4. **Registro de transacciones**
- Registro de ingresos, gastos e inversiones
- Campos: tipo, monto, descripción, fecha
- Tabla con todos los registros
- **Editar** transacciones existentes
- **Eliminar** transacciones
- Validación de datos en tiempo real

### 5. **Inversiones**
- Seguimiento separado de inversiones
- Diferenciación clara de ingresos y gastos
- Vista específica de inversiones
- Integración en gráficos y reportes
- Edición de inversiones con botones Guardar y Cancelar en una misma fila

### 6. **Presupuestos mensuales** ⭐
- Definición de presupuestos por categoría con monto límite
- Visualización de progreso de gasto con barra de progreso
- Edición de presupuestos con modal
- Eliminación de presupuestos
- Histórico de presupuestos

### 7. **Reportes mensuales**
- Filtrar transacciones por mes y año
- Tablas detalladas de ingresos, gastos e inversiones
- Totales por categoría
- Saldo calculado automáticamente
 - Exportar a Excel (.xlsx) con formato profesional (título, subtítulo, encabezados, formato de fecha y monto)

### 7. **Edición de perfil**
- Cambio de contraseña
- Validación de contraseña actual
- Confirmación de nueva contraseña
- Información personal editable
- Selección de moneda predeterminada

### 8. **Monedas y formato**
- Selección de moneda por usuario en el perfil; la moneda configurada se aplica en toda la aplicación para mostrar y formatear montos.
- Valores por defecto en formularios de registro: si la `moneda` del usuario es `COP` solo se muestra el valor (20.000); para las demás monedas se muestra con el codigo (USD 30).
- Formateo de montos y visualización con filtros Jinja provistos en `application/filters.py` (`format_currency`, `currency_with_code`).
- Las exportaciones y reportes respetan la moneda del usuario y muestran el código de moneda (p. ej. 30 USD, 30 EUR, 20.000 COP).
- Monedas soportadas (ejemplos): USD, EUR, GBP, CAD, AUD, MXN, COP. Se pueden ampliar desde `application/currencies.py`.

## 🔐 Seguridad (OWASP Top 10)

### Implementadas:
- ✅ **Inyección SQL**: Consultas parametrizadas
- ✅ **Autenticación**: Hashing de contraseñas, validación fuerte
- ✅ **Autenticación multifactor**: TOTP/OTP con código QR
- ✅ **CSRF**: Tokens en formularios
- ✅ **Datos sensibles**: Contraseñas hasheadas, variables de entorno
- ✅ **Control de acceso**: Validación de autorización
- ✅ **Headers de seguridad**: X-Content-Type-Options, X-Frame-Options, etc.
- ✅ **Validación de entrada**: Funciones de validación robustas
- ✅ **Sesiones seguras**: Cookies HttpOnly, SameSite, timeout
- ✅ **Recuperación de contraseña**: Con CAPTCHA y tokens únicos
- ✅ **Rate limiting**: Límite de intentos en autenticación y recuperación

## 📋 Requisitos

- Python 3.8+
- MySQL/MariaDB
- pip (gestor de paquetes de Python)

## 📦 Dependencias

```
Flask==2.3.0
Flask-Login==0.6.2
mysql-connector-python==8.0.33
python-dotenv==1.0.0
Werkzeug==2.3.0
waitress==2.1.2
pyotp==2.9.0
pandas==2.2.0
openpyxl==3.1.5
```

## 🐳 Docker (Producción)

La aplicación se puede desplegar en producción usando Docker y Docker Compose.

### Requisitos
- Docker
- Docker Compose

### Archivos de configuración
- `Dockerfile` - Imagen de la aplicación Python
- `docker-compose.yml` - Orquestación de servicios (app + MySQL)
- `.env.production` - Variables de entorno para producción

### Despliegue con Docker

1. **Configurar variables de entorno de producción**
```bash
cp .env.production .env
```
Editar `.env` con los valores seguros de producción:
```
FLASK_ENV=production
FLASK_SECRET_KEY=tu-clave-secreta-segura
DB_HOST=mysql
DB_USER=tu-usuario-db
DB_PASSWORD=tu-contraseña-db
DB_NAME=app_money
MYSQL_ROOT_PASSWORD=tu-contraseña-root
```

2. **Construir y ejecutar**
```bash
docker-compose up -d --build
```

3. **Ver logs**
```bash
docker-compose logs -f app
```

4. **Detener**
```bash
docker-compose down
```

### Servicios
- **app**: Aplicación Flask en el puerto 7700
- **mysql**: Base de datos MySQL 8 con healthcheck y volumen persistente

## 🔧 Instalación (Desarrollo sin Docker)

1. **Clonar/Descargar el proyecto**
```bash
cd "d:\Proyectos Python - GUI\app_money"
```

2. **Crear entorno virtual** (opcional pero recomendado)
```bash
python -m venv venv
venv\Scripts\activate
```

3. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

4. **Configurar variables de entorno**
```bash
cp .env.development .env
```
Editar `.env` con tus datos locales:
```
FLASK_ENV=development
FLASK_SECRET_KEY=tu-clave-secreta
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=tu-contraseña
DB_NAME=app_money
FLASK_DEBUG=True
SESSION_TIMEOUT=1800
```

5. **Crear base de datos**
```bash
mysql -u root -p < init_db.sql
```

6. **Ejecutar la aplicación**
```bash
python app.py
```

La aplicación estará disponible en `http://localhost:7700`

## 🔐 Configurar autenticación de dos factores (2FA)

1. **Acceder a seguridad**
   - Iniciar sesión normalmente
   - Ir a Configuración → Seguridad

2. **Activar 2FA**
   - Click en el toggle de "Autenticación de dos factores"
   - Se generará un código QR
   - Escanear con tu aplicación autenticadora:
     - Google Authenticator
     - Microsoft Authenticator
     - Authy
     - Otros apps TOTP

3. **Guardar el secreto**
   - También se mostrará el código secreto en caso de que necesites importarlo manualmente
   - Guarda este código en lugar seguro

4. **Usar 2FA**
   - Próximo login pedirá código OTP
   - Ingresa el código de 6 dígitos de tu aplicación
   - El código cambia cada 30 segundos

## 📁 Estructura del proyecto

```
app_money/
├── application/
│   ├── currencies.py          # Lista de monedas soportadas
│   └── filters.py             # Filtros Jinja para formateo
├── interface/
│   ├── templates/
│   │   ├── auth/              # Autenticación
│   │   │   ├── login.html
│   │   │   ├── registrar_usuario.html
│   │   │   ├── recuperar_contraseña.html
│   │   │   ├── resetear_contraseña.html
│   │   │   ├── verificar_captcha.html
│   │   │   └── verificar_otp_recuperacion.html
│   │   ├── dashboard/         # Panel principal
│   │   │   ├── consolidado.html
│   │   │   ├── inversiones.html
│   │   │   ├── perfil.html
│   │   │   └── preferencias.html
│   │   ├── config/            # Configuración
│   │   │   └── presupuestos.html
│   │   ├── forms/             # Formularios
│   │   │   ├── registrar.html
│   │   │   └── editar_registro.html
│   │   ├── reports/           # Reportes
│   │   │   └── reportes.html
│   │   └── layout/
│   │       └── base.html
│   ├── routes/
│   │   └── main.py            # Rutas de la aplicación
│   └── static/                # Archivos estáticos (CSS, JS, imágenes)
├── infrastructure/
│   ├── db.py                  # Conexión a base de datos
│   └── validators.py          # Funciones de validación
├── app.py                     # Aplicación principal
├── init_db.sql                # Script de base de datos
├── Dockerfile                 # Imagen Docker para producción
├── docker-compose.yml         # Orquestación de servicios
├── .env.development           # Variables para desarrollo
├── .env.production            # Variables para producción (Docker)
├── requirements.txt           # Dependencias Python
```

## 🗄️ Base de datos

**Tablas:**

1. **usuarios**
   - id (PK)
   - nombre_usuario
   - password_hash
   - totp_secret
   - MFA
   - ultimo_login
   - nombre_completo
   - email
   - telefono
   - pais
   - ciudad
   - moneda
   - foto_perfil (BLOB)
   - creado_en

2. **ingresos**
   - id (PK)
   - usuario_id (FK)
   - monto
   - descripcion
   - fecha
   - creado_en

3. **gastos**
   - id (PK)
   - usuario_id (FK)
   - monto
   - descripcion
   - fecha
   - creado_en

4. **inversiones**
   - id (PK)
   - usuario_id (FK)
   - monto
   - descripcion
   - fecha
   - creado_en

5. **presupuestos**
   - id (PK)
   - usuario_id (FK)
   - categoria_id (FK)
   - monto_limite
   - gastado
   - creado_en
   - actualizado_en

## 🎨 Diseño

- **Framework**: Tailwind CSS
- **Estilo**: Fluent Design
- **Gráficos**: Chart.js
- **Responsive**: Compatible con móvil y escritorio

## 🔗 Endpoints Principales

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/` | Dashboard consolidado |
| GET/POST | `/login` | Página de login |
| POST | `/verify-otp` | Verificar código OTP (AJAX) |
| POST | `/logout` | Cerrar sesión |
| GET/POST | `/registrar_usuario` | Registrar nuevo usuario |
| GET/POST | `/recuperar_contraseña` | Solicitar recuperación |
| GET/POST | `/resetear_contraseña` | Cambiar contraseña |
| POST | `/verificar_captcha` | Verificar captcha |
| POST | `/verificar_otp_recuperacion` | Verificar OTP |
| GET/POST | `/editar_registro` | Editar transacciones |
| POST | `/eliminar_registro` | Eliminar transacciones |
| GET | `/reportes` | Ver reportes mensuales |
| POST | `/exportar_excel` | Exportar a Excel |
| POST | `/exportar_pdf` | Exportar a PDF |
| GET | `/inversiones` | Ver inversiones |
| GET/POST | `/presupuestos` | Gestionar presupuestos mensuales |
| GET/POST | `/editar_presupuesto/<id>` | Editar presupuesto (AJAX) |
| GET | `/historial_presupuesto/<id>` | Ver histórico de presupuesto |
| GET/POST | `/eliminar_presupuesto/<id>` | Eliminar presupuesto |
| GET/POST | `/editar_perfil` | Editar perfil de usuario |
| GET/POST | `/preferencias` | Configurar preferencias |
| GET/POST | `/seguridad` | Configurar 2FA/MFA |

## 📊 Validaciones

- **Usuario**: 3-50 caracteres, alfanuméricos y guiones
- **Contraseña**: Mínimo 8 caracteres, mayúsculas, minúsculas, números
- **Monto**: Mayor a 0, máximo 999,999,999.99
- **Fecha**: Formato YYYY-MM-DD
- **Descripción**: Máximo 255 caracteres

## 🛠️ Desarrollo

### Agregar nuevas funcionalidades:

1. Crear ruta en `interface/routes/main.py`
2. Crear template en `interface/templates/`
3. Agregar validación si es necesario
4. Actualizar menú de navegación

### Actualizar base de datos:

Editar `init_db.sql` y ejecutar:
```bash
mysql -u root -p app_money < init_db.sql
```

## 📝 Convenciones de código

- Nombres en **español** en templates y mensajes
- Nombres en **inglés** en código backend
- Funciones separadas por categoría
- Comentarios solo en partes complejas
- Validación en cliente (HTML) y servidor (Python)

## 🚨 Troubleshooting

**Error: "No module named 'mysql.connector'"**
```bash
pip install mysql-connector-python
```

**Error: "No module named 'dotenv'"**
```bash
pip install python-dotenv
```

**Error: Conexión a base de datos rechazada**
- Verificar que MySQL está ejecutándose
- Verificar credenciales en `.env`
- Verificar que la base de datos existe

## 📄 Licencia

Este proyecto es publico.

## 👨‍💻 Autor

Desarrollado como gestor de finanzas personales.

---

**Última actualización**: 24 de junio de 2026

