"""Configuración de la aplicación Flask"""
import os
from dotenv import load_dotenv

load_dotenv()

def configure_app(app):
    """Configura la aplicación Flask con todas las opciones necesarias"""
    secret_key = os.getenv('FLASK_SECRET_KEY')
    if not secret_key or secret_key == 'default-insecure-key':
        raise RuntimeError('FLASK_SECRET_KEY debe estar configurada con un valor seguro')
    app.config['SECRET_KEY'] = secret_key
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('SESSION_TIMEOUT', 1800))
    app.config['PHOTO_MAX_BYTES'] = int(os.getenv('PHOTO_MAX_BYTES', 8 * 1024 * 1024))
    app.config['MAX_CONTENT_LENGTH'] = app.config['PHOTO_MAX_BYTES']
    app.config['PROFILE_MAX_DIMENSION'] = int(os.getenv('PROFILE_MAX_DIMENSION', 512))
    app.config['PROFILE_WEBP_QUALITY'] = int(os.getenv('PROFILE_WEBP_QUALITY', 82))
    app.config['TEMPLATES_AUTO_RELOAD'] = True


def configure_security_headers(app):
    """Configura headers de seguridad"""
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
