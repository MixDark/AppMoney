CREATE DATABASE IF NOT EXISTS app_money;
USE app_money;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(32),
    MFA BOOLEAN DEFAULT FALSE,
    ultimo_login DATETIME,
    nombre_completo VARCHAR(255),
    email VARCHAR(255),
    telefono VARCHAR(50),
    pais VARCHAR(100),
    ciudad VARCHAR(100),
    moneda VARCHAR(10) DEFAULT 'USD',
    foto_perfil MEDIUMBLOB,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de ingresos
CREATE TABLE IF NOT EXISTS ingresos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    fecha DATE NOT NULL,
    categoria_id INT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_ingresos_usuario_fecha ON ingresos (usuario_id, fecha, id);
CREATE INDEX idx_ingresos_usuario_categoria ON ingresos (usuario_id, categoria_id, fecha);

-- Tabla de gastos
CREATE TABLE IF NOT EXISTS gastos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    fecha DATE NOT NULL,
    categoria_id INT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_gastos_usuario_fecha ON gastos (usuario_id, fecha, id);
CREATE INDEX idx_gastos_usuario_categoria ON gastos (usuario_id, categoria_id, fecha);

-- Tabla de inversiones
CREATE TABLE IF NOT EXISTS inversiones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    tipo VARCHAR(50) NOT NULL DEFAULT 'otro',
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    fecha DATE NOT NULL,
    categoria_id INT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_inversiones_usuario_fecha ON inversiones (usuario_id, fecha, id);
CREATE INDEX idx_inversiones_usuario_categoria ON inversiones (usuario_id, categoria_id, fecha);

-- Tabla de metas
CREATE TABLE IF NOT EXISTS metas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    nombre VARCHAR(255) NOT NULL,
    monto_objetivo DECIMAL(10,2) NOT NULL,
    monto_actual DECIMAL(10,2) DEFAULT 0,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Tabla de categorías
CREATE TABLE IF NOT EXISTS categorias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    nombre VARCHAR(255) NOT NULL,
    tipo VARCHAR(50),
    color VARCHAR(7),
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_categorias_usuario_tipo ON categorias (usuario_id, tipo);

-- Tabla de presupuestos
CREATE TABLE IF NOT EXISTS presupuestos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    categoria_id VARCHAR(255),
    monto DECIMAL(10,2) NOT NULL,
    gastado DECIMAL(10,2) DEFAULT 0,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_presupuestos_usuario_categoria ON presupuestos (usuario_id, categoria_id);

-- Tabla de transacciones recurrentes
CREATE TABLE IF NOT EXISTS transacciones_recurrentes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    tipo VARCHAR(50),
    descripcion VARCHAR(255),
    monto DECIMAL(10,2) NOT NULL,
    frecuencia VARCHAR(50),
    proxima_fecha DATE,
    activo BOOLEAN DEFAULT TRUE,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_recurrentes_usuario_activo_fecha ON transacciones_recurrentes (usuario_id, activo, proxima_fecha);

-- Tabla de recuperación de contraseña
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    token VARCHAR(100) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    captcha_attempt INT DEFAULT 0,
    verified BOOLEAN DEFAULT FALSE,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX idx_reset_tokens_usuario ON password_reset_tokens (usuario_id, expires_at);
