import re
from decimal import Decimal, InvalidOperation

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 50:
        return False, "El usuario debe tener entre 3 y 50 caracteres"
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "El usuario solo puede contener letras, números, guiones bajos y guiones"
    return True, "OK"

def validate_password(password):
    if not password or len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener letras mayúsculas"
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener letras minúsculas"
    if not re.search(r'[0-9]', password):
        return False, "La contraseña debe contener números"
    return True, "OK"

def validate_monto(monto):
    try:
        amount = Decimal(str(monto))
        if amount <= 0:
            return False, "El monto debe ser mayor a 0"
        if amount > Decimal('999999999.99'):
            return False, "El monto es demasiado grande"
        return True, "OK"
    except (InvalidOperation, ValueError):
        return False, "Formato de monto inválido"

def validate_descripcion(descripcion):
    if not descripcion:
        return True, "OK"
    if len(descripcion) > 255:
        return False, "La descripción es demasiado larga"
    return True, "OK"

def validate_fecha(fecha):
    if not fecha:
        return False, "La fecha es requerida"
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', fecha):
        return False, "Formato de fecha inválido"
    return True, "OK"

def validate_tipo(tipo):
    valid_types = ['ingreso', 'gasto', 'inversion']
    if tipo not in valid_types:
        return False, "Tipo inválido"
    return True, "OK"

