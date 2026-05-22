"""Gestión de autenticación y usuario"""
from flask import url_for
from flask_login import LoginManager, UserMixin
from infrastructure.db import get_connection
from infrastructure.profile_images import has_profile_photo
from flask import session

login_manager = LoginManager()
login_manager.login_view = 'main.login'


def _resolve_foto_perfil_ruta(raw):
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return ''


class User(UserMixin):
    """Modelo de usuario para Flask-Login"""
    def __init__(self, id, nombre_usuario, foto_perfil_ruta='', moneda='USD', legacy_foto=False):
        self.id = id
        self.nombre_usuario = nombre_usuario
        self.foto_perfil_ruta = foto_perfil_ruta or ''
        self._legacy_foto = legacy_foto
        self.moneda = moneda

    def get_id(self):
        return str(self.id)

    @property
    def foto_perfil(self):
        return bool(self.foto_perfil_ruta) or self._legacy_foto

    @property
    def foto_perfil_url(self):
        if self.foto_perfil_ruta:
            return url_for('static', filename=self.foto_perfil_ruta)
        if self._legacy_foto:
            return url_for('main.foto_perfil', usuario_id=self.id)
        return None


def _user_from_cache(cached_usuario):
    if not cached_usuario:
        return None
    return User(
        cached_usuario.get('id'),
        cached_usuario.get('nombre_usuario', ''),
        cached_usuario.get('foto_perfil_ruta', ''),
        (cached_usuario.get('moneda') or 'USD').upper(),
        legacy_foto=bool(cached_usuario.get('foto_perfil')) and not cached_usuario.get('foto_perfil_ruta'),
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
        cursor.execute(
            "SELECT id, nombre_usuario, foto_perfil, moneda FROM usuarios WHERE id = %s",
            (int(user_id),),
        )
        usuario = cursor.fetchone()
        cursor.close()
        connection.close()
        if usuario:
            raw_foto = usuario.get('foto_perfil')
            foto_ruta = _resolve_foto_perfil_ruta(raw_foto)
            legacy_foto = has_profile_photo(raw_foto) and not foto_ruta
            cached_usuario = {
                'id': usuario['id'],
                'nombre_usuario': usuario['nombre_usuario'],
                'foto_perfil': legacy_foto or bool(foto_ruta),
                'foto_perfil_ruta': foto_ruta,
                'moneda': (usuario['moneda'] or 'USD').upper(),
            }
            session['usuario_cache'] = cached_usuario
            return User(
                usuario['id'],
                usuario['nombre_usuario'],
                foto_ruta,
                (usuario['moneda'] or 'USD').upper(),
                legacy_foto=legacy_foto,
            )
    except Exception:
        pass
    return None


def init_auth(app):
    """Inicializa la gestión de autenticación en la app"""
    login_manager.init_app(app)

    @app.context_processor
    def inject_user():
        if 'usuario_id' not in session:
            return {'current_user': None}

        cached_usuario = session.get('usuario_cache')
        if cached_usuario and str(cached_usuario.get('id')) == str(session.get('usuario_id')):
            return {'current_user': _user_from_cache(cached_usuario)}

        return {'current_user': load_user(session.get('usuario_id'))}

    @app.template_global()
    def usuario_foto_url(usuario, usuario_id=None):
        if not usuario:
            return None
        ruta = usuario.get('foto_perfil_ruta') if isinstance(usuario, dict) else getattr(usuario, 'foto_perfil_ruta', '')
        if ruta:
            return url_for('static', filename=ruta)
        uid = usuario_id or (usuario.get('id') if isinstance(usuario, dict) else getattr(usuario, 'id', None))
        tiene_foto = usuario.get('foto_perfil') if isinstance(usuario, dict) else getattr(usuario, 'foto_perfil', False)
        if tiene_foto and uid:
            return url_for('main.foto_perfil', usuario_id=uid)
        return None
