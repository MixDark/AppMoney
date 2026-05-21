# Registro de cambios

Todos los cambios relevantes de este proyecto se documentan en este archivo.

## [1.4.0] - 2026-05-21
### Agregado
- Captcha visual basado en librería para el flujo de recuperación, con imagen generada por servidor y reto de 6 caracteres.
- Verificación OTP en recuperación para usuarios con autenticación de dos pasos habilitada.
- Lógica de limitación de intentos por usuario en la base de datos con tabla `user_rate_limits`.
### Cambiado
- Flujo de recuperación reorganizado para usar tokens persistidos en base de datos y evitar exponer información sensible en la URL.
- Recarga de captcha sin refrescar la página completa mediante llamada `fetch` al backend.
- Mensajes de rate limit unificados en toda la aplicación con un texto breve y consistente.
- Búsqueda de usuario en recuperación más tolerante ante espacios y diferencias de mayúsculas/minúsculas.
### Corregido
- Falsos negativos de "usuario no encontrado" durante la recuperación cuando el usuario sí existía en la base.
- Formularios del flujo de recuperación apuntando a rutas incorrectas al enviar captcha, OTP o cambio de contraseña.
- Exceso de detalle en mensajes de rate limit, reemplazado por un aviso genérico reutilizable.

## [1.3.0] - 2026-05-19
### Agregado
- Conservadas y ampliadas las monedas soportadas; añadidas las más usadas actualmente.
- Nuevo módulo `application/currencies.py` con lista de monedas.
- Nuevos filtros de plantillas en `application/filters.py` para formateo y visualización de moneda con código.
- Helper optimizado para exportación desde el explorador de transacciones sin recalcular paginación completa.
### Cambiado
- Mejora importante de rendimiento: caché de usuario en sesión para evitar lecturas repetidas a la base de datos y pooling de conexiones MySQL en `infrastructure/db.py`.
- Consultas optimizadas: reemplazo de `SELECT *` por proyecciones explícitas y uso de rangos de fecha en lugar de `YEAR()/MONTH()` para permitir el uso de índices.
- Actualización de `infrastructure/init_db.sql` y `infrastructure/schema.py` para añadir índices recomendados en consultas críticas.
### Corregido
- Lentitud al cargar el consolidado y navegar a las diferentes secciones
- Lentitud al iniciar sesión y al navegar grandes listados: reducida mediante menos consultas, transmisión de menor volumen de datos y consultas más selectivas.
- Problemas de rendimiento y errores en las rutas de exportación (`exportar_buscar` y relacionadas) corregidos mediante rutas y consultas optimizadas.

## [1.2.0] - 2026-05-16
### Agregado
- Exportación a Excel (.xlsx) desde el explorador de transacciones con formato profesional (titulo, subtitulo, encabezados, formateo de fechas y montos).
- Selección de categoría en formularios de registro y edición de transacciones (ingresos, gastos, inversiones).
### Cambiado
- Las categorías ahora están asociadas y validadas según el tipo de transacción.
- Edición de transacciones recurrentes mediante modal con normalización de montos (separador decimal coma) y formato consistente.
- Filtro de búsqueda: valores por defecto para `Desde` y `Hasta` al mes actual; corrección de rango para "Este año".
### Corregido
- Error en exportación CSV que causaba TypeError al descargar; reemplazado por exportación a XLSX.
- Problemas de formato y parseo de montos al editar recurrentes y registros.

## [1.1.0] - 2026-05-12
### Agregado
- Nuevos campos de perfil en el registro: nombre_completo, email, telefono, pais, ciudad, moneda.
- Proteccion CSRF con tokens en formularios y validacion en headers para solicitudes fetch.
- Limitacion de intentos en login, verificacion OTP, recuperacion, CAPTCHA y reseteo.
- Foto de perfil almacenada en base de datos como BLOB con endpoint protegido.
### Cambiado
- La foto de perfil ahora se guarda como binario en la base de datos en lugar de rutas de archivo.
- Configuracion segura: FLASK_SECRET_KEY es obligatoria al iniciar.
- Limite de tamano de carga aplicado desde la configuracion.

## [1.0.0] - 2026-05-12
### Agregado
- Lanzamiento inicial.
