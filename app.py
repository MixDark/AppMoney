from flask import Flask
import os
import sys
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


def create_app():
    """Factory para crear la aplicación Flask"""
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    
    # Aplicar configuraciones
    configure_app(app)
    configure_security_headers(app)
    init_auth(app)
    register_template_filters(app)
    register_routes(app)
    
    return app


# Crear instancia global de la aplicación
app = create_app()

if __name__ == "__main__":
    # Ejecutar con el servidor Waitress
    from server import run_server
    run_server()
