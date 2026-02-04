CREATE DATABASE IF NOT EXISTS app_money;
USE app_money;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de ingresos
CREATE TABLE IF NOT EXISTS ingresos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    fecha DATE NOT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Tabla de gastos
CREATE TABLE IF NOT EXISTS gastos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    fecha DATE NOT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Tabla de inversiones
CREATE TABLE IF NOT EXISTS inversiones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    monto DECIMAL(10,2) NOT NULL,
    descripcion VARCHAR(255),
    fecha DATE NOT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

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
-- Contraseña: Alice12+
-- Hash generado con werkzeug.security.generate_password_hash()
INSERT INTO usuarios (nombre_usuario, password_hash) VALUES (
    'Esteban',
    'pbkdf2:sha256:1000000$kBsuD8BkyZqtj2z2$8bda538153dbeafce6dc1ec1c5fa8ab34d6c982d88e19aafcb063cc8afd5f23c'
);
