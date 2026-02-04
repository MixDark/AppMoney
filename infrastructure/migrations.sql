-- Migraciones para nuevas funcionalidades
USE app_money;

-- 2. Categorías personalizables
CREATE TABLE IF NOT EXISTS categorias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    nombre VARCHAR(50) NOT NULL,
    tipo ENUM('ingreso', 'gasto', 'inversion') NOT NULL,
    icono VARCHAR(50),
    color VARCHAR(7),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Agregar categoria_id a las tablas existentes
ALTER TABLE ingresos ADD COLUMN categoria_id INT, ADD FOREIGN KEY (categoria_id) REFERENCES categorias(id) ON DELETE SET NULL;
ALTER TABLE gastos ADD COLUMN categoria_id INT, ADD FOREIGN KEY (categoria_id) REFERENCES categorias(id) ON DELETE SET NULL;
ALTER TABLE inversiones ADD COLUMN categoria_id INT, ADD FOREIGN KEY (categoria_id) REFERENCES categorias(id) ON DELETE SET NULL;

-- 3. Presupuestos y Metas
CREATE TABLE IF NOT EXISTS presupuestos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    categoria_id INT NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    periodo ENUM('mensual', 'anual') DEFAULT 'mensual',
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (categoria_id) REFERENCES categorias(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS metas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    monto_objetivo DECIMAL(10,2) NOT NULL,
    monto_actual DECIMAL(10,2) DEFAULT 0,
    fecha_limite DATE,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- 4. Notificaciones
CREATE TABLE IF NOT EXISTS notificaciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    mensaje TEXT NOT NULL,
    leido BOOLEAN DEFAULT FALSE,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- 5. Transacciones Recurrentes
CREATE TABLE IF NOT EXISTS transacciones_recurrentes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    tipo ENUM('ingreso', 'gasto', 'inversion') NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    categoria_id INT,
    frecuencia ENUM('diario', 'semanal', 'mensual', 'anual') NOT NULL,
    proxima_fecha DATE NOT NULL,
    activo BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (categoria_id) REFERENCES categorias(id) ON DELETE SET NULL
);

-- 11. Gestión de usuarios mejorada (Ajustes a tabla usuarios)
ALTER TABLE usuarios ADD COLUMN foto_perfil VARCHAR(255), ADD COLUMN moneda VARCHAR(3) DEFAULT 'USD';

-- 12. Seguridad adicional
ALTER TABLE usuarios ADD COLUMN ultimo_login DATETIME, ADD COLUMN MFA BOOLEAN DEFAULT FALSE;

-- 13. Agregar campos de perfil completo
ALTER TABLE usuarios MODIFY COLUMN nombre_usuario VARCHAR(100);
ALTER TABLE usuarios ADD COLUMN nombre_completo VARCHAR(100), ADD COLUMN email VARCHAR(100) UNIQUE, ADD COLUMN telefono VARCHAR(20), ADD COLUMN pais VARCHAR(100), ADD COLUMN ciudad VARCHAR(100);
