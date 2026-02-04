from infrastructure.db import get_connection

def migrate():
    conn = get_connection()
    if not conn:
        print("No connection")
        return
    try:
        cursor = conn.cursor()
        cursor.execute("DESCRIBE usuarios")
        columns = [col[0] for col in cursor.fetchall()]
        if 'totp_secret' not in columns:
            cursor.execute("ALTER TABLE usuarios ADD COLUMN totp_secret VARCHAR(32)")
            print("Added totp_secret column")
            conn.commit()
        else:
            print("totp_secret already exists")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
