"""Gestión de autenticación y usuario"""
from flask_login import LoginManager, UserMixin
from infrastructure.db import get_connection
from flask import session

login_manager = LoginManager()
login_manager.login_view = 'main.login'


class User(UserMixin):
    """Modelo de usuario para Flask-Login"""
    def __init__(self, id, nombre_usuario, foto_perfil=None, moneda='USD'):
        self.id = id
        self.nombre_usuario = nombre_usuario
        self.foto_perfil = foto_perfil
        self.moneda = moneda
    
    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    """Carga un usuario desde la base de datos"""
    if user_id is None:
        return None
    try:
        connection = get_connection()
        if connection is None:
            return None
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, nombre_usuario, foto_perfil, moneda FROM usuarios WHERE id = %s", (int(user_id),))
        usuario = cursor.fetchone()
        cursor.close()
        connection.close()
        if usuario:
            return User(
                usuario['id'], 
                usuario['nombre_usuario'], 
                usuario['foto_perfil'], 
                usuario['moneda']
            )
    except Exception as e:
        pass
    return None


def init_auth(app):
    """Inicializa la gestión de autenticación en la app"""
    login_manager.init_app(app)
    
    # Inyectar current_user en todos los templates
    @app.context_processor
    def inject_user():
        return {'current_user': load_user(session.get('usuario_id')) if 'usuario_id' in session else None}
