from datetime import date, datetime

class Ingreso:
    def __init__(self, id: int, usuario_id: int, monto: float, descripcion: str, fecha: date, creado_en: datetime = None):
        self.id = id
        self.usuario_id = usuario_id
        self.monto = monto
        self.descripcion = descripcion
        self.fecha = fecha
        self.creado_en = creado_en or datetime.now()
