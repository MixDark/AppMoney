from flask import Flask
import os
import sys
import threading
import webbrowser
from dotenv import load_dotenv
from waitress import serve

# Importar configuración y componentes
from application.config import configure_app, configure_security_headers
from application.auth import init_auth
from application.filters import register_template_filters
from interface.routes import register_routes
from infrastructure.schema import ensure_schema

load_dotenv()
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Configurar rutas de templates y static
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interface', 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interface', 'static')


class Config:
    """Configuración centralizada de la aplicación"""
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    IS_PRODUCTION = FLASK_ENV == 'production'
    
    # Servidor
    SERVER_HOST = os.getenv('SERVER_HOST', '127.0.0.1')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 7700))
    SERVER_THREADS = int(os.getenv('SERVER_THREADS', 2))
    
    # Base de datos
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'app_money')


def create_app():
    """Factory para crear la aplicación Flask"""
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    
    # Aplicar configuraciones
    configure_app(app)
    configure_security_headers(app)
    init_auth(app)
    register_template_filters(app)
    register_routes(app)

    with app.app_context():
        ensure_schema()

    return app


# Crear instancia global de la aplicación
app = create_app()


def abrir_navegador(url):
    """Abre el navegador automáticamente después de 1 segundo"""
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()


def run_server():
    """
    Inicia el servidor Waitress con la aplicación Flask
    Todas las configuraciones se toman desde variables de entorno
    """
    config = Config()
    url = f'http://{config.SERVER_HOST}:{config.SERVER_PORT}/'
    
    print(f"\n{'='*60}")
    print(f"Iniciando servidor Waitress")
    print(f"Dirección: {url}")
    print(f"Threads: {config.SERVER_THREADS}")
    print(f"Entorno: {config.FLASK_ENV}")
    print(f"{'='*60}\n")
    
    # Abrir navegador automáticamente solo en desarrollo
    if not config.IS_PRODUCTION:
        abrir_navegador(url)
    
    try:
        serve(
            app,
            host=config.SERVER_HOST,
            port=config.SERVER_PORT,
            threads=config.SERVER_THREADS,
            _quiet=False
        )
    except KeyboardInterrupt:
        print("Servidor detenido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"Error al iniciar el servidor: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_server()
