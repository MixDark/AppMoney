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


def _user_from_cache(cached_usuario):
    if not cached_usuario:
        return None
    return User(
        cached_usuario.get('id'),
        cached_usuario.get('nombre_usuario', ''),
        cached_usuario.get('foto_perfil', False),
        (cached_usuario.get('moneda') or 'USD').upper()
    )


@login_manager.user_loader
def load_user(user_id):
    """Carga un usuario desde la base de datos"""
    if user_id is None:
        return None
    cached_usuario = session.get('usuario_cache')
    if cached_usuario and str(cached_usuario.get('id')) == str(user_id):
        return _user_from_cache(cached_usuario)
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
            cached_usuario = {
                'id': usuario['id'],
                'nombre_usuario': usuario['nombre_usuario'],
                'foto_perfil': bool(usuario['foto_perfil']),
                'moneda': (usuario['moneda'] or 'USD').upper(),
            }
            session['usuario_cache'] = cached_usuario
            return User(
                usuario['id'], 
                usuario['nombre_usuario'], 
                usuario['foto_perfil'], 
                (usuario['moneda'] or 'USD').upper()
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
        if 'usuario_id' not in session:
            return {'current_user': None}

        cached_usuario = session.get('usuario_cache')
        if cached_usuario and str(cached_usuario.get('id')) == str(session.get('usuario_id')):
            return {'current_user': _user_from_cache(cached_usuario)}

        return {'current_user': load_user(session.get('usuario_id'))}
