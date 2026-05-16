# Registro de cambios

Todos los cambios relevantes de este proyecto se documentan en este archivo.

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
