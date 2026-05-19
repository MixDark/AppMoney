"""Configuración de monedas y valores predeterminados"""

# Definición de monedas disponibles con sus valores predeterminados
CURRENCIES = {
    'USD': {
        'name': 'Dólar Estadounidense',
        'default_value': 30,
        'symbol': '$'
    },
    'EUR': {
        'name': 'Euro',
        'default_value': 30,
        'symbol': '€'
    },
    'MXN': {
        'name': 'Peso Mexicano',
        'default_value': 30,
        'symbol': '$'
    },
    'ARS': {
        'name': 'Peso Argentino',
        'default_value': 30,
        'symbol': '$'
    },
    'COP': {
        'name': 'Peso Colombiano',
        'default_value': 20000,
        'symbol': '$',
        'show_currency': True
    },
    'CLP': {
        'name': 'Peso Chileno',
        'default_value': 30,
        'symbol': '$'
    },
    'BRL': {
        'name': 'Real Brasileño',
        'default_value': 30,
        'symbol': 'R$'
    },
    'PEN': {
        'name': 'Sol Peruano',
        'default_value': 30,
        'symbol': 'S/'
    },
    'UYU': {
        'name': 'Peso Uruguayo',
        'default_value': 30,
        'symbol': '$'
    },
    'VES': {
        'name': 'Bolívar Venezolano',
        'default_value': 30,
        'symbol': 'Bs'
    },
    'GBP': {
        'name': 'Libra Esterlina',
        'default_value': 30,
        'symbol': '£'
    },
    'JPY': {
        'name': 'Yen Japonés',
        'default_value': 30,
        'symbol': '¥'
    },
    'CHF': {
        'name': 'Franco Suizo',
        'default_value': 30,
        'symbol': 'CHF'
    },
    'CAD': {
        'name': 'Dólar Canadiense',
        'default_value': 30,
        'symbol': '$'
    },
    'AUD': {
        'name': 'Dólar Australiano',
        'default_value': 30,
        'symbol': '$'
    },
    'NZD': {
        'name': 'Dólar Neozelandés',
        'default_value': 30,
        'symbol': '$'
    },
    'CNY': {
        'name': 'Yuan Chino',
        'default_value': 30,
        'symbol': '¥'
    },
    'INR': {
        'name': 'Rupia India',
        'default_value': 30,
        'symbol': '₹'
    },
}

def get_currency_list():
    """Retorna lista de tuplas (codigo, nombre) para formularios"""
    return [(code, f"{code} - {data['name']}") for code, data in sorted(CURRENCIES.items())]

def get_default_value(currency_code):
    """Retorna el valor predeterminado para una moneda"""
    currency = CURRENCIES.get(currency_code, {})
    return currency.get('default_value', 30)

def get_currency_display(currency_code, value):
    """Retorna el formato de visualización para una moneda y valor"""
    currency = CURRENCIES.get(currency_code, {})
    show_currency = currency.get('show_currency', True)
    symbol = currency.get('symbol', currency_code)
    
    if show_currency:
        return f"{symbol} {value}"
    else:
        return str(value)

def get_currency_info(currency_code):
    """Retorna toda la información de una moneda"""
    return CURRENCIES.get(currency_code, {})
