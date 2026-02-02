from interface.routes import register_routes
from flask import Flask, session
from flask_login import LoginManager, UserMixin
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
import os
import sys
import dotenv
import threading
import webbrowser

load_dotenv()

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from infrastructure.db import get_connection

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interface', 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interface', 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-insecure-key')

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('SESSION_TIMEOUT', 1800))

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'

class User(UserMixin):
    def __init__(self, id, nombre_usuario):
        self.id = id
        self.nombre_usuario = nombre_usuario
    
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    try:
        connection = get_connection()
        if connection is None:
            return None
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, nombre_usuario FROM usuarios WHERE id = %s", (int(user_id),))
        usuario = cursor.fetchone()
        cursor.close()
        connection.close()
        if usuario:
            return User(usuario['id'], usuario['nombre_usuario'])
    except Exception as e:
        print(f"Error loading user: {e}")
    return None

# Hacer current_user disponible en todos los templates
@app.context_processor
def inject_user():
    return {'current_user': load_user(session.get('usuario_id')) if 'usuario_id' in session else None}

# Filtro personalizado para formatear montos con separador de miles (.) y decimales (,)
@app.template_filter('format_money')
def format_money(valor):
    """Formatea un número como dinero con formato: 299.000,00"""
    try:
        # Convertir a float y formatear con 2 decimales
        valor_float = float(valor)
        # Usar formato local-friendly
        formatted = f"{valor_float:,.2f}"  # Genera: 299,000.00
        # Intercambiar la coma por punto para miles y punto por coma para decimales
        # Dividir por el último punto (que es el separador de decimales)
        partes = formatted.rsplit('.', 1)  # Divide desde la derecha
        if len(partes) == 2:
            parte_entera, parte_decimal = partes
            parte_entera = parte_entera.replace(',', '.')  # Comas a puntos (miles)
            return f"{parte_entera},{parte_decimal}"  # Resultado: 299.000,00
        else:
            return formatted.replace(',', '.')
    except Exception as e:
        print(f"Error en format_money: {e}")
        return str(valor)

register_routes(app)

# Filtro personalizado para formatear fechas a DD/MM/YYYY
@app.template_filter('format_date')
def format_date(fecha):
    """Formatea una fecha a DD/MM/YYYY (ej: 30/01/2026)"""
    try:
        from datetime import date, datetime
        
        # Si es objeto date o datetime
        if isinstance(fecha, (date, datetime)):
            day = str(fecha.day).zfill(2)
            month = str(fecha.month).zfill(2)
            year = fecha.year
            return f"{day}/{month}/{year}"
        
        # Si es string
        if isinstance(fecha, str):
            # Si es string en formato YYYY-MM-DD
            if 'T' in fecha:
                fecha = fecha.split('T')[0]  # Remover hora si existe
            partes = fecha.split('-')
            if len(partes) == 3:
                year, month, day = partes
                return f"{day}/{month}/{year}"
        
        return str(fecha)
    except Exception as e:
        print(f"Error en format_date: {e}")
        return str(fecha)

def abrir_navegador():
    webbrowser.open_new('http://127.0.0.1:5000/')

if __name__ == "__main__":
    threading.Timer(1.0, abrir_navegador).start()
    app.run(debug=False, use_reloader=False)
