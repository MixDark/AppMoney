from datetime import datetime

class Usuario:
    def __init__(self, id: int, nombre_usuario: str, password_hash: str, creado_en: datetime = None):
        self.id = id
        self.nombre_usuario = nombre_usuario
        self.password_hash = password_hash
        self.creado_en = creado_en or datetime.now()
