"""Almacenamiento de fotos de perfil en disco (WebP si Pillow está disponible)."""
import os
from io import BytesIO

from flask import current_app

try:
    from PIL import Image, ImageOps
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

PROFILE_RELATIVE_DIR = 'images/profiles'
MIME_BY_EXT = {
    'webp': 'image/webp',
    'jpeg': 'image/jpeg',
    'jpg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
}


def detect_image_type(data):
    if data.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
        return 'gif'
    if data.startswith(b'RIFF') and len(data) > 12 and data[8:12] == b'WEBP':
        return 'webp'
    return None


def get_profiles_directory():
    static_folder = current_app.static_folder
    directory = os.path.join(static_folder, PROFILE_RELATIVE_DIR)
    os.makedirs(directory, exist_ok=True)
    return directory


def profile_relative_path(usuario_id, extension='webp'):
    return f'{PROFILE_RELATIVE_DIR}/{int(usuario_id)}.{extension}'


def profile_absolute_path(usuario_id, extension='webp'):
    return os.path.join(get_profiles_directory(), f'{int(usuario_id)}.{extension}')


def _remove_existing_profile_files(usuario_id):
    directory = get_profiles_directory()
    prefix = f'{int(usuario_id)}.'
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            try:
                os.remove(os.path.join(directory, filename))
            except OSError:
                pass


def _save_webp(image, absolute_path):
    max_dimension = int(current_app.config.get('PROFILE_MAX_DIMENSION', 512))
    quality = int(current_app.config.get('PROFILE_WEBP_QUALITY', 82))

    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGBA')

    image.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)

    if image.mode == 'RGBA':
        background = Image.new('RGB', image.size, (18, 27, 51))
        background.paste(image, mask=image.split()[3])
        image = background
    else:
        image = image.convert('RGB')

    image.save(absolute_path, format='WEBP', quality=quality, method=6)


def _save_raw_file(data, usuario_id, extension):
    _remove_existing_profile_files(usuario_id)
    absolute_path = profile_absolute_path(usuario_id, extension)
    with open(absolute_path, 'wb') as output:
        output.write(data)
    return profile_relative_path(usuario_id, extension)


def save_profile_image_from_upload(file, usuario_id):
    if not file or not file.filename:
        return None, None

    max_bytes = current_app.config.get('PHOTO_MAX_BYTES', 8 * 1024 * 1024)
    data = file.read(max_bytes + 1)
    if len(data) > max_bytes:
        return None, 'La imagen supera el tamaño permitido'

    kind = detect_image_type(data)
    if kind not in {'jpeg', 'png', 'gif', 'webp'}:
        return None, 'Formato de imagen no permitido'

    _remove_existing_profile_files(usuario_id)

    if HAS_PILLOW:
        try:
            image = ImageOps.exif_transpose(Image.open(BytesIO(data)))
            absolute_path = profile_absolute_path(usuario_id, 'webp')
            _save_webp(image, absolute_path)
            return profile_relative_path(usuario_id, 'webp'), None
        except Exception:
            pass

    extension = 'jpg' if kind == 'jpeg' else kind
    return _save_raw_file(data, usuario_id, extension), None


def save_profile_image_from_bytes(blob, usuario_id):
    if not blob:
        return None

    kind = detect_image_type(blob)
    if not kind:
        return None

    _remove_existing_profile_files(usuario_id)

    if HAS_PILLOW:
        try:
            image = ImageOps.exif_transpose(Image.open(BytesIO(blob)))
            absolute_path = profile_absolute_path(usuario_id, 'webp')
            _save_webp(image, absolute_path)
            return profile_relative_path(usuario_id, 'webp')
        except Exception:
            pass

    extension = 'jpg' if kind == 'jpeg' else kind
    return _save_raw_file(blob, usuario_id, extension)


def delete_profile_image_file(relative_path=None, usuario_id=None):
    if usuario_id is not None:
        _remove_existing_profile_files(usuario_id)
        return

    if relative_path and isinstance(relative_path, str):
        static_folder = current_app.static_folder
        absolute_path = os.path.join(static_folder, relative_path.replace('/', os.sep))
        if os.path.isfile(absolute_path):
            try:
                os.remove(absolute_path)
            except OSError:
                pass


def resolve_profile_file(relative_path):
    if not relative_path or not isinstance(relative_path, str):
        return None
    relative_path = relative_path.strip()
    if not relative_path:
        return None
    static_folder = current_app.static_folder
    absolute_path = os.path.normpath(os.path.join(static_folder, relative_path.replace('/', os.sep)))
    profiles_root = os.path.normpath(os.path.join(static_folder, PROFILE_RELATIVE_DIR))
    if not absolute_path.startswith(profiles_root):
        return None
    if os.path.isfile(absolute_path):
        return absolute_path
    return None


def profile_mimetype(relative_path):
    if not relative_path:
        return 'application/octet-stream'
    extension = relative_path.rsplit('.', 1)[-1].lower()
    return MIME_BY_EXT.get(extension, 'application/octet-stream')


def has_profile_photo(value):
    if not value:
        return False
    if isinstance(value, (bytes, bytearray)):
        return len(value) > 0
    return bool(str(value).strip())
