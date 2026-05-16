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
        conn.commit()
    except Exception as e:
        print(f"ensure_schema: {e}")
    finally:
        conn.close()
