"""Migraciones ligeras para alinear el esquema con el código de la app."""
from infrastructure.db import get_connection


def _column_exists(cursor, table, column):
    cursor.execute(
        """
        SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s
        """,
        (table, column),
    )
    return cursor.fetchone()[0] > 0


def ensure_schema():
    conn = get_connection()
    if conn is None:
        return
    try:
        cursor = conn.cursor()
        for table in ('ingresos', 'gastos', 'inversiones'):
            if not _column_exists(cursor, table, 'categoria_id'):
                cursor.execute(f'ALTER TABLE {table} ADD COLUMN categoria_id INT NULL')
        if not _column_exists(cursor, 'inversiones', 'tipo'):
            cursor.execute(
                "ALTER TABLE inversiones ADD COLUMN tipo VARCHAR(50) NOT NULL DEFAULT 'otro'"
            )

        if not _column_exists(cursor, 'password_reset_tokens', 'otp_verified'):
            cursor.execute(
                "ALTER TABLE password_reset_tokens ADD COLUMN otp_verified BOOLEAN DEFAULT FALSE"
            )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_rate_limits (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                subject_key VARCHAR(191) NOT NULL,
                scope VARCHAR(50) NOT NULL,
                attempts INT DEFAULT 0,
                window_started_at DATETIME DEFAULT NULL,
                blocked_until DATETIME DEFAULT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_rate_limit (subject_key, scope),
                INDEX idx_user_rate_limit_lookup (subject_key, scope, blocked_until)
            )
            """
        )

        # Índices compuestos para acelerar listados, filtros y reportes
        index_statements = [
            ("ingresos", "idx_ingresos_usuario_fecha", "(usuario_id, fecha, id)"),
            ("ingresos", "idx_ingresos_usuario_categoria", "(usuario_id, categoria_id, fecha)"),
            ("gastos", "idx_gastos_usuario_fecha", "(usuario_id, fecha, id)"),
            ("gastos", "idx_gastos_usuario_categoria", "(usuario_id, categoria_id, fecha)"),
            ("inversiones", "idx_inversiones_usuario_fecha", "(usuario_id, fecha, id)"),
            ("inversiones", "idx_inversiones_usuario_categoria", "(usuario_id, categoria_id, fecha)"),
            ("categorias", "idx_categorias_usuario_tipo", "(usuario_id, tipo)"),
            ("presupuestos", "idx_presupuestos_usuario_categoria", "(usuario_id, categoria_id)"),
            ("transacciones_recurrentes", "idx_recurrentes_usuario_activo_fecha", "(usuario_id, activo, proxima_fecha)"),
            ("password_reset_tokens", "idx_reset_tokens_token", "(token)"),
            ("password_reset_tokens", "idx_reset_tokens_usuario", "(usuario_id, expires_at)"),
        ]

        for table, index_name, columns in index_statements:
            cursor.execute(
                """
                SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND INDEX_NAME = %s
                """,
                (table, index_name),
            )
            if cursor.fetchone()[0] == 0:
                cursor.execute(f'CREATE INDEX {index_name} ON {table} {columns}')
        conn.commit()
    except Exception as e:
        print(f"ensure_schema: {e}")
    finally:
        conn.close()
