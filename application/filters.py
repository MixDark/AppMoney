"""Filtros personalizados para templates"""
from datetime import date, datetime


def register_template_filters(app):
    """Registra todos los filtros personalizados en la app"""
    
    @app.template_filter('format_money')
    def format_money(valor):
        """Formatea un número como dinero: 299.000,00"""
        try:
            valor_float = float(valor)
            formatted = f"{valor_float:,.2f}"
            partes = formatted.rsplit('.', 1)
            if len(partes) == 2:
                parte_entera, parte_decimal = partes
                parte_entera = parte_entera.replace(',', '.')
                return f"{parte_entera},{parte_decimal}"
            else:
                return formatted.replace(',', '.')
        except Exception as e:
            print(f"Error en format_money: {e}")
            return str(valor)

    @app.template_filter('format_date')
    def format_date(fecha):
        """Formatea una fecha a DD/MM/YYYY (ej: 30/01/2026)"""
        try:
            if isinstance(fecha, (date, datetime)):
                day = str(fecha.day).zfill(2)
                month = str(fecha.month).zfill(2)
                year = fecha.year
                return f"{day}/{month}/{year}"
            
            if isinstance(fecha, str):
                if 'T' in fecha:
                    fecha = fecha.split('T')[0]
                partes = fecha.split('-')
                if len(partes) == 3:
                    year, month, day = partes
                    return f"{day}/{month}/{year}"
            
            return str(fecha)
        except Exception as e:
            print(f"Error en format_date: {e}")
            return str(fecha)
