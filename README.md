# App Money - Gestor de Finanzas Personales

Una aplicación web para gestionar ingresos, gastos e inversiones de forma segura y eficiente.

## 🚀 Funcionalidades Principales

### 1. **Autenticación de Usuarios**
- Registro de nuevos usuarios
- Login seguro con validación de contraseña
- Gestión de sesiones
- Opción de editar perfil y cambiar contraseña

### 2. **Dashboard Consolidado**
- Vista general de finanzas (ingresos, gastos, inversiones y saldo)
- Gráfico de distribución (pastel) mostrando proporciones
- Gráfico comparativo (barras) con valores absolutos
- Historial de transacciones recientes por categoría
- Totales resumidos de cada categoría

### 3. **Registro de Transacciones**
- Registro de ingresos, gastos e inversiones
- Campos: tipo, monto, descripción, fecha
- Tabla con todos los registros
- **Editar** transacciones existentes
- **Eliminar** transacciones
- Validación de datos en tiempo real

### 4. **Inversiones**
- Seguimiento separado de inversiones
- Diferenciación clara de ingresos y gastos
- Vista específica de inversiones
- Integración en gráficos y reportes

### 5. **Reportes Mensuales**
- Filtrar transacciones por mes y año
- Tablas detalladas de ingresos, gastos e inversiones
- Totales por categoría
- Saldo calculado automáticamente

### 6. **Edición de Perfil**
- Cambio de contraseña
- Validación de contraseña actual
- Confirmación de nueva contraseña

## 🔐 Seguridad (OWASP Top 10)

### Implementadas:
- ✅ **Inyección SQL**: Consultas parametrizadas
- ✅ **Autenticación**: Hashing de contraseñas, validación fuerte
- ✅ **CSRF**: Tokens en formularios
- ✅ **Datos Sensibles**: Contraseñas hasheadas, variables de entorno
- ✅ **Control de Acceso**: Validación de autorización
- ✅ **Headers de Seguridad**: X-Content-Type-Options, X-Frame-Options, etc.
- ✅ **Validación de Entrada**: Funciones de validación robustas
- ✅ **Sesiones Seguras**: Cookies HttpOnly, SameSite, timeout

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
```

## 🔧 Instalación

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
- Copiar `.env.example` a `.env`
- Editar `.env` con tus datos:
```
FLASK_SECRET_KEY=tu-clave-secreta
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=tu-contraseña
DB_NAME=app_money
FLASK_DEBUG=False
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

La aplicación estará disponible en `http://localhost:5000`

## 📁 Estructura del Proyecto

```
app_money/
├── interface/
│   ├── templates/
│   │   ├── auth/              # Autenticación
│   │   │   ├── login.html
│   │   │   └── registrar_usuario.html
│   │   ├── dashboard/         # Panel principal
│   │   │   ├── consolidado.html
│   │   │   ├── inversiones.html
│   │   │   └── editar_perfil.html
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
├── .env                       # Variables de entorno
├── .env.example               # Ejemplo de .env
└── .gitignore                 # Archivos ignorados por Git
```

## 🗄️ Base de Datos

**Tablas:**

1. **usuarios**
   - id (PK)
   - nombre_usuario
   - password_hash
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

## 🎨 Diseño

- **Framework**: Tailwind CSS
- **Estilo**: Fluent Design (glasmorphism)
- **Gráficos**: Chart.js
- **Responsive**: Compatible con móvil y escritorio

## 🔗 Endpoints Principales

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/` | Dashboard consolidado |
| GET/POST | `/login` | Página de login |
| POST | `/logout` | Cerrar sesión |
| GET/POST | `/registrar` | Registrar transacciones |
| GET/POST | `/editar_registro` | Editar transacciones |
| POST | `/eliminar_registro` | Eliminar transacciones |
| GET | `/reportes` | Ver reportes mensuales |
| GET | `/inversiones` | Ver inversiones |
| GET/POST | `/editar_perfil` | Editar perfil de usuario |

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

## 📝 Convenciones de Código

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

**Última actualización**: 2 de febrero de 2026

