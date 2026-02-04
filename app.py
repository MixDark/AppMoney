"""
App Money - Aplicación de Gestión Financiera
Punto de entrada principal de la aplicación Flask
"""
from flask import Flask
import os
import sys
import threading
import webbrowser
from dotenv import load_dotenv

# Importar configuración y componentes
from application.config import configure_app, configure_security_headers
from application.auth import init_auth
from application.filters import register_template_filters
from interface.routes import register_routes

load_dotenv()
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Configurar rutas de templates y static
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interface', 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interface', 'static')

# Crear aplicación Flask
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Aplicar configuraciones
configure_app(app)
configure_security_headers(app)
init_auth(app)
register_template_filters(app)
register_routes(app)


def abrir_navegador():
    """Abre el navegador automáticamente"""
    webbrowser.open_new('http://127.0.0.1:5000/')


if __name__ == "__main__":
    threading.Timer(1.0, abrir_navegador).start()
    app.run(debug=False, use_reloader=False)

