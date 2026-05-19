"""Filtros personalizados para templates"""
from datetime import date, datetime
from application.currencies import get_currency_display, get_default_value, get_currency_info


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
            return str(fecha)

    @app.template_filter('format_currency')
    def format_currency(valor, currency_code='USD'):
        """Formatea un valor con su moneda (ej: $30, 20.000 para COP)"""
        try:
            valor_float = float(valor)
            currency_info = get_currency_info(currency_code)
            show_currency = currency_info.get('show_currency', True)
            symbol = currency_info.get('symbol', currency_code)
            
            if show_currency:
                return f"{symbol} {valor_float:,.2f}"
            else:
                return f"{valor_float:,.0f}"
        except Exception as e:
            return str(valor)

    @app.template_filter('currency_with_code')
    def currency_with_code(valor, currency_code='USD'):
        """Formatea un valor mostrando el código de moneda (ej: USD 30, COP 20.000)"""
        try:
            valor_float = float(valor)
            currency_info = get_currency_info(currency_code)
            show_currency = currency_info.get('show_currency', True)
            
            if currency_code == 'COP':
                # Para COP solo mostrar el valor sin símbolo
                return f"{valor_float:,.0f}"
            else:
                return f"{currency_code} {valor_float:,.2f}"
        except Exception as e:
            return str(valor)

    @app.template_filter('get_default_value')
    def filter_get_default_value(currency_code):
        """Obtiene el valor predeterminado de una moneda"""
        return get_default_value(currency_code)
