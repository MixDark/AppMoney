from flask import render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask import Blueprint
from functools import wraps
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from infrastructure.db import get_connection
from infrastructure.validators import *
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from io import BytesIO
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
import pyotp

def login_required_custom(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def register_routes(app):
    bp = Blueprint('main', __name__)

    @bp.route('/', methods=['GET'])
    def consolidado():
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        usuario = obtener_usuario_por_id(session['usuario_id'])
        if usuario is None:
            session.clear()
            return redirect(url_for('main.login'))
        
        ingresos = obtener_ingresos(usuario['id'])
        gastos = obtener_gastos(usuario['id'])
        inversiones = obtener_inversiones(usuario['id'])
        
        total_ingresos = float(sum(i['monto'] for i in ingresos) or 0)
        total_gastos = float(sum(g['monto'] for g in gastos) or 0)
        total_inversiones = float(sum(inv['monto'] for inv in inversiones) or 0)
        saldo = total_ingresos - total_gastos - total_inversiones
        
        # Procesar transacciones recurrentes pendientes
        procesar_recurrentes_usuario(usuario['id'])
        
        # Calcular tendencias de los últimos 6 meses
        hoy = datetime.now()
        meses_labels = []
        data_ingresos = []
        data_gastos = []
        data_inversiones = []
        
        for i in range(5, -1, -1):
            fecha_temp = hoy - timedelta(days=i*30)
            anio, mes = fecha_temp.year, fecha_temp.month
            meses_labels.append(fecha_temp.strftime('%b %Y'))
            
            ing_mes = sum(x['monto'] for x in obtener_ingresos_por_mes(usuario['id'], anio, mes)) or 0
            gas_mes = sum(x['monto'] for x in obtener_gastos_por_mes(usuario['id'], anio, mes)) or 0
            inv_mes = sum(x['monto'] for x in obtener_inversiones_por_mes(usuario['id'], anio, mes)) or 0
            
            data_ingresos.append(float(ing_mes))
            data_gastos.append(float(gas_mes))
            data_inversiones.append(float(inv_mes))

        # Comparación con promedios (Mock data for analysis)
        promedio_nacional_gasto = 1500.00
        total_movimientos = total_ingresos + total_gastos + total_inversiones
        
        analysis = {
            'meses_labels': meses_labels,
            'data_ingresos': data_ingresos,
            'data_gastos': data_gastos,
            'data_inversiones': data_inversiones,
            'promedio_nacional_gasto': promedio_nacional_gasto,
            'ahorro_porcentaje': round((saldo / total_ingresos * 100), 1) if total_ingresos > 0 else 0,
            'ingreso_porcentaje': round((total_ingresos / total_movimientos * 100), 1) if total_movimientos > 0 else 0,
            'gasto_porcentaje': round((total_gastos / total_movimientos * 100), 1) if total_movimientos > 0 else 0,
            'inversion_porcentaje': round((total_inversiones / total_movimientos * 100), 1) if total_movimientos > 0 else 0
        }

        return render_template('dashboard/consolidado.html', 
                             usuario=usuario, 
                             ingresos=ingresos[:10], # Limitar para el dashboard
                             gastos=gastos[:10], 
                             inversiones=inversiones[:10],
                             total_ingresos=total_ingresos, 
                             total_gastos=total_gastos, 
                             total_inversiones=total_inversiones, 
                             saldo=saldo,
                             analysis=analysis)

    @bp.route('/login', methods=['GET', 'POST'])
    def login():
        mensaje = None
        mostrar_otp_modal = False
        
        if request.method == 'POST':
            nombre_usuario = request.form.get('nombre_usuario', '').strip()
            password = request.form.get('password', '')
            
            valid, msg = validate_username(nombre_usuario)
            if not valid:
                mensaje = msg
                return render_template('auth/login.html', mensaje=mensaje, mostrar_otp_modal=False)
            
            usuario = obtener_usuario_por_nombre(nombre_usuario)
            
            if not usuario:
                mensaje = 'Usuario no encontrado'
            elif not check_password_hash(usuario['password_hash'], password):
                mensaje = 'Contraseña incorrecta'
            else:
                # Usuario y contraseña son correctos
                # Verificar si tiene MFA habilitado
                if usuario_tiene_mfa_activado(usuario['id']):
                    # Guardar el usuario temporalmente en sesión
                    session['temp_usuario_id'] = usuario['id']
                    session['username_temp'] = usuario['nombre_usuario']
                    mostrar_otp_modal = True
                    return render_template('auth/login.html', 
                                         mostrar_otp_modal=mostrar_otp_modal,
                                         nombre_usuario=nombre_usuario)
                else:
                    # Sin MFA, hacer login directo
                    actualizar_ultimo_login(usuario['id'])
                    session.permanent = True
                    session['usuario_id'] = usuario['id']
                    session.pop('temp_usuario_id', None)
                    session.pop('username_temp', None)
                    return redirect(url_for('main.consolidado'))
        
        return render_template('auth/login.html', mensaje=mensaje, mostrar_otp_modal=False)

    @bp.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('main.login'))

    @bp.route('/verify-otp', methods=['POST'])
    def verify_otp():
        """Verifica el código OTP proporcionado por el usuario"""
        if 'temp_usuario_id' not in session:
            return jsonify({'exito': False, 'mensaje': 'Sesión inválida'}), 400
        
        codigo_otp = request.form.get('codigo_otp', '').strip()
        usuario_id = session['temp_usuario_id']
        
        if not codigo_otp:
            return jsonify({'exito': False, 'mensaje': 'Por favor ingresa el código OTP'}), 400
        
        # Obtener el secreto TOTP del usuario
        totp_secret = obtener_totp_secret_usuario(usuario_id)
        
        if not totp_secret:
            return jsonify({'exito': False, 'mensaje': 'Error: MFA no configurado correctamente'}), 400
        
        # Validar el código OTP
        if validar_totp(totp_secret, codigo_otp):
            # OTP correcto, completar el login
            usuario = obtener_usuario_por_id(usuario_id)
            if usuario:
                actualizar_ultimo_login(usuario_id)
                session.permanent = True
                session['usuario_id'] = usuario_id
                session.pop('temp_usuario_id', None)
                session.pop('username_temp', None)
                return jsonify({'exito': True, 'mensaje': 'OTP verificado correctamente', 'redirect': url_for('main.consolidado')})
            else:
                return jsonify({'exito': False, 'mensaje': 'Error: Usuario no encontrado'}), 400
        else:
            # OTP incorrecto
            return jsonify({'exito': False, 'mensaje': 'Código OTP inválido'}), 401

    @bp.route('/recuperar_contraseña', methods=['GET', 'POST'])
    def recuperar_contraseña():
        mensaje = None
        exito = None
        if request.method == 'POST':
            nombre_usuario = request.form.get('nombre_usuario', '').strip()
            
            valid, msg = validate_username(nombre_usuario)
            if not valid:
                mensaje = msg
                return render_template('auth/recuperar_contraseña.html', mensaje=mensaje)
            
            usuario = obtener_usuario_por_nombre(nombre_usuario)
            
            if not usuario:
                mensaje = 'Usuario no encontrado'
            else:
                # Generar token único
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                
                # Guardar token en BD
                if crear_token_recuperacion(usuario['id'], token, expires_at):
                    # Redirigir al CAPTCHA
                    return redirect(url_for('main.verificar_captcha', token=token))
                else:
                    mensaje = 'Error al procesar tu solicitud'
        
        return render_template('auth/recuperar_contraseña.html', mensaje=mensaje, exito=exito)

    @bp.route('/verificar_captcha', methods=['GET', 'POST'])
    def verificar_captcha():
        token = request.args.get('token') or request.form.get('token')
        mensaje = None
        
        if not token:
            return redirect(url_for('main.recuperar_contraseña'))
        
        # Verificar que el token sea válido
        token_data = obtener_token_recuperacion(token)
        
        if not token_data:
            mensaje = 'Token inválido o expirado'
            return redirect(url_for('main.recuperar_contraseña'))
        
        # Verificar si el token ha expirado
        expires_at = token_data['expires_at']
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        
        if expires_at < datetime.now():
            mensaje = 'El enlace de recuperación ha expirado'
            eliminar_token_recuperacion(token)
            return redirect(url_for('main.recuperar_contraseña'))
        
        # Si el token ya fue verificado, redirigir al reseteo
        if token_data['verified']:
            return redirect(url_for('main.resetear_contraseña', token=token))
        
        # Si ya alcanzó 3 intentos, bloquear
        if token_data['captcha_attempt'] >= 3:
            mensaje = 'Demasiados intentos. Solicita una nueva recuperación'
            eliminar_token_recuperacion(token)
            return redirect(url_for('main.recuperar_contraseña'))
        
        if request.method == 'GET':
            # Generar CAPTCHA (suma simple)
            captcha_num1 = secrets.randbelow(50) + 1
            captcha_num2 = secrets.randbelow(50) + 1
            respuesta_correcta = captcha_num1 + captcha_num2
            
            # Guardar respuesta en sesión
            session[f'captcha_{token}'] = respuesta_correcta
            
            return render_template('auth/verificar_captcha.html', 
                                 token=token, 
                                 captcha_num1=captcha_num1, 
                                 captcha_num2=captcha_num2,
                                 captcha_attempt=token_data['captcha_attempt'])
        
        elif request.method == 'POST':
            respuesta_usuario = request.form.get('captcha_answer', '')
            respuesta_correcta = session.get(f'captcha_{token}')
            
            try:
                respuesta_usuario = int(respuesta_usuario)
            except ValueError:
                respuesta_usuario = None
            
            if respuesta_usuario == respuesta_correcta:
                # CAPTCHA correcto, marcar token como verificado
                actualizar_token_verificado(token)
                session.pop(f'captcha_{token}', None)
                return redirect(url_for('main.resetear_contraseña', token=token))
            else:
                # Incrementar intentos fallidos
                nuevos_intentos = token_data['captcha_attempt'] + 1
                incrementar_intentos_captcha(token, nuevos_intentos)
                
                if nuevos_intentos >= 3:
                    mensaje = 'Demasiados intentos incorrectos. Solicita una nueva recuperación'
                    eliminar_token_recuperacion(token)
                    return redirect(url_for('main.recuperar_contraseña'))
                
                mensaje = 'Respuesta incorrecta. Intenta de nuevo'
                
                # Generar nuevo CAPTCHA
                captcha_num1 = secrets.randbelow(50) + 1
                captcha_num2 = secrets.randbelow(50) + 1
                respuesta_correcta_nueva = captcha_num1 + captcha_num2
                session[f'captcha_{token}'] = respuesta_correcta_nueva
                
                return render_template('auth/verificar_captcha.html', 
                                     token=token, 
                                     captcha_num1=captcha_num1, 
                                     captcha_num2=captcha_num2,
                                     captcha_attempt=nuevos_intentos,
                                     mensaje=mensaje)

    @bp.route('/resetear_contraseña', methods=['GET', 'POST'])
    def resetear_contraseña():
        token = request.args.get('token') or request.form.get('token')
        mensaje = None
        
        if not token:
            mensaje = 'Token inválido'
            return render_template('auth/resetear_contraseña.html', mensaje=mensaje, token='')
        
        # Verificar que el token sea válido
        token_data = obtener_token_recuperacion(token)
        
        if not token_data:
            mensaje = 'Token inválido o expirado'
            return render_template('auth/resetear_contraseña.html', mensaje=mensaje, token='')
        
        # Verificar si el token ha expirado
        expires_at = token_data['expires_at']
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        
        if expires_at < datetime.now():
            mensaje = 'El enlace de recuperación ha expirado'
            eliminar_token_recuperacion(token)
            return render_template('auth/resetear_contraseña.html', mensaje=mensaje, token='')
        
        # Verificar que el CAPTCHA fue verificado
        if not token_data['verified']:
            return redirect(url_for('main.verificar_captcha', token=token))
        
        if request.method == 'POST':
            password_nueva = request.form.get('password_nueva', '')
            password_confirmar = request.form.get('password_confirmar', '')
            
            valid, msg = validate_password(password_nueva)
            if not valid:
                mensaje = msg
                return render_template('auth/resetear_contraseña.html', mensaje=mensaje, token=token)
            
            if password_nueva != password_confirmar:
                mensaje = 'Las contraseñas no coinciden'
                return render_template('auth/resetear_contraseña.html', mensaje=mensaje, token=token)
            
            # Actualizar contraseña
            nueva_password_hash = generate_password_hash(password_nueva)
            if actualizar_password_usuario(token_data['usuario_id'], nueva_password_hash):
                # Eliminar token usado
                eliminar_token_recuperacion(token)
                flash('Contraseña actualizada exitosamente. Inicia sesión con tu nueva contraseña.', 'success')
                return redirect(url_for('main.login'))
            else:
                mensaje = 'Error al actualizar la contraseña'
        
        return render_template('auth/resetear_contraseña.html', mensaje=mensaje, token=token)

    @bp.route('/registrar', methods=['GET', 'POST'])
    @login_required_custom
    def registrar():
        if request.method == 'POST':
            tipo = request.form.get('tipo', '').strip()
            monto_str = request.form.get('monto', '').strip()
            descripcion = request.form.get('descripcion', '').strip()
            fecha = request.form.get('fecha', '').strip()
            usuario_id = session.get('usuario_id')
            
            valid, msg = validate_tipo(tipo)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            valid, msg = validate_monto(monto_str)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            valid, msg = validate_descripcion(descripcion)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            valid, msg = validate_fecha(fecha)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            monto = float(monto_str)
            if tipo == 'ingreso':
                agregar_ingreso(usuario_id, monto, descripcion, fecha)
            elif tipo == 'gasto':
                agregar_gasto(usuario_id, monto, descripcion, fecha)
            elif tipo == 'inversion':
                agregar_inversion(usuario_id, '', monto, descripcion, fecha)
            
            flash(f'{tipo.capitalize()} registrado correctamente', 'success')
            return redirect(url_for('main.consolidado'))
        
        usuario_id = session.get('usuario_id')
        
        ingresos = obtener_ingresos(usuario_id)
        gastos = obtener_gastos(usuario_id)
        inversiones = obtener_inversiones(usuario_id)
        return render_template('forms/registrar.html', ingresos=ingresos, gastos=gastos, inversiones=inversiones)

    @bp.route('/reportes', methods=['GET'])
    def reportes():
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        usuario_id = session['usuario_id']
        mes = request.args.get('mes')
        if mes:
            anio, mes_num = mes.split('-')
            ingresos = obtener_ingresos_por_mes(usuario_id, anio, mes_num)
            gastos = obtener_gastos_por_mes(usuario_id, anio, mes_num)
            inversiones = obtener_inversiones_por_mes(usuario_id, anio, mes_num)
            mes_mostrar = f'{mes_num}/{anio}'
        else:
            hoy = datetime.now()
            anio, mes_num = hoy.year, hoy.month
            ingresos = obtener_ingresos_por_mes(usuario_id, anio, mes_num)
            gastos = obtener_gastos_por_mes(usuario_id, anio, mes_num)
            inversiones = obtener_inversiones_por_mes(usuario_id, anio, mes_num)
            mes_mostrar = f'{mes_num}/{anio}'
        total_ingresos = float(sum(i['monto'] for i in ingresos) or 0)
        total_gastos = float(sum(g['monto'] for g in gastos) or 0)
        total_inversiones = float(sum(inv['monto'] for inv in inversiones) or 0)
        saldo = total_ingresos - total_gastos - total_inversiones
        return render_template('reports/reportes.html', ingresos=ingresos, gastos=gastos, inversiones=inversiones, total_ingresos=total_ingresos, total_gastos=total_gastos, total_inversiones=total_inversiones, saldo=saldo, mes_actual=f'{anio}-{str(mes_num).zfill(2)}', mes_mostrar=mes_mostrar)

    @bp.route('/inversiones', methods=['GET', 'POST'])
    def inversiones():
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        if request.method == 'POST':
            tipo = request.form['tipo']
            monto = float(request.form['monto'])
            descripcion = request.form['descripcion']
            fecha = request.form['fecha']
            usuario_id = session.get('usuario_id')
            if not usuario_id:
                return redirect(url_for('main.login'))
            agregar_inversion(usuario_id, tipo, monto, descripcion, fecha)
            return redirect(url_for('main.inversiones'))
        usuario_id = session['usuario_id']
        inversiones_list = obtener_inversiones(usuario_id)
        total_inversiones = float(sum(i['monto'] for i in inversiones_list) or 0)
        return render_template('dashboard/inversiones.html', inversiones=inversiones_list, total_inversiones=total_inversiones)

    @bp.route('/registrar_usuario', methods=['GET', 'POST'])
    def registrar_usuario():
        mensaje = None
        if request.method == 'POST':
            nombre_usuario = request.form['nombre_usuario']
            password = request.form['password']
            if obtener_usuario_por_nombre(nombre_usuario):
                mensaje = 'El usuario ya existe'
            else:
                password_hash = generate_password_hash(password)
                crear_usuario(nombre_usuario, password_hash)
                return redirect(url_for('main.login'))
        return render_template('auth/registrar_usuario.html', mensaje=mensaje)

    @bp.route('/perfil', methods=['GET', 'POST'])
    @login_required_custom
    def perfil():
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        
        usuario = obtener_usuario_por_id(session['usuario_id'])
        if usuario is None:
            session.clear()
            return redirect(url_for('main.login'))
        
        mensaje = None
        if request.method == 'POST':
            # Actualizar Foto si se envió
            if 'foto_perfil' in request.files and request.files['foto_perfil'].filename:
                file = request.files['foto_perfil']
                if file:
                    from werkzeug.utils import secure_filename
                    filename = secure_filename(file.filename)
                    basedir = os.path.dirname(os.path.abspath(__file__))
                    static_folder = os.path.join(basedir, '..', 'static', 'uploads', 'perfiles')
                    if not os.path.exists(static_folder):
                        os.makedirs(static_folder)
                    
                    ext = os.path.splitext(filename)[1]
                    new_filename = f"user_{usuario['id']}_{int(datetime.now().timestamp())}{ext}"
                    filepath = os.path.join(static_folder, new_filename)
                    file.save(filepath)
                    
                    web_path = f"/static/uploads/perfiles/{new_filename}"
                    actualizar_foto_perfil_db(usuario['id'], web_path)
            
            # Actualizar datos personales
            nombre_completo = request.form.get('nombre_completo', '').strip()
            email = request.form.get('email', '').strip()
            telefono = request.form.get('telefono', '').strip()
            pais = request.form.get('pais', '').strip()
            ciudad = request.form.get('ciudad', '').strip()
            moneda = request.form.get('moneda', 'USD')
            
            resultado = actualizar_perfil_usuario_db(usuario['id'], nombre_completo, email, telefono, pais, ciudad, moneda)
            
            if resultado:
                mensaje = '✅ Perfil actualizado exitosamente'
            else:
                mensaje = '❌ Error al actualizar el perfil'
            
            # Recargar datos del usuario DESPUÉS de actualizar
            usuario = obtener_usuario_por_id(session['usuario_id'])
            
            return render_template('dashboard/perfil.html', usuario=usuario, mensaje=mensaje)
        
        return render_template('dashboard/perfil.html', usuario=usuario, mensaje=mensaje)

    @bp.route('/editar_perfil', methods=['GET', 'POST'])
    def editar_perfil():
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        
        usuario = obtener_usuario_por_id(session['usuario_id'])
        if usuario is None:
            session.clear()
            return redirect(url_for('main.login'))
        mensaje = None
        
        if request.method == 'POST':
            # Verificar si es solo actualización de foto (sin contraseña)
            if 'foto_perfil' in request.files and request.files['foto_perfil'].filename:
                file = request.files['foto_perfil']
                if file:
                    from werkzeug.utils import secure_filename
                    filename = secure_filename(file.filename)
                    # Asegurar que el directorio existe
                    basedir = os.path.dirname(os.path.abspath(__file__))
                    # Ir dos niveles arriba: interface/routes -> interface -> app_money -> interface/static ?
                    # Estructura: d:\Proyectos Python - GUI\app_money\interface\routes\main.py
                    # Static: d:\Proyectos Python - GUI\app_money\interface\static
                    static_folder = os.path.join(basedir, '..', 'static', 'uploads', 'perfiles')
                    if not os.path.exists(static_folder):
                        os.makedirs(static_folder)
                    
                    # Generar nombre único
                    ext = os.path.splitext(filename)[1]
                    new_filename = f"user_{usuario['id']}_{int(datetime.now().timestamp())}{ext}"
                    filepath = os.path.join(static_folder, new_filename)
                    file.save(filepath)
                    
                    # Ruta web relativa
                    web_path = f"/static/uploads/perfiles/{new_filename}"
                    actualizar_foto_perfil_db(usuario['id'], web_path)
                    
                    # Si no hay contraseña actual, asumimos que es solo subida de foto y redirigimos
                    if not request.form.get('password_actual'):
                         flash('Foto de perfil actualizada', 'success')
                         return redirect(url_for('main.editar_perfil'))

            password_actual = request.form.get('password_actual', '')
            password_nueva = request.form.get('password_nueva', '')
            password_confirmar = request.form.get('password_confirmar', '')
            moneda = request.form.get('moneda', 'USD')
            nombre_completo = request.form.get('nombre_completo', '')
            email = request.form.get('email', '')
            telefono = request.form.get('telefono', '')
            pais = request.form.get('pais', '')
            ciudad = request.form.get('ciudad', '')
            
            if not check_password_hash(usuario['password_hash'], password_actual):
                mensaje = 'La contraseña actual es incorrecta para aplicar cambios'
            else:
                # Actualizar datos personales y moneda
                actualizar_perfil_usuario_db(usuario['id'], nombre_completo, email, telefono, pais, ciudad, moneda)
                
                # Actualizar contraseña si se proporcionó
                if password_nueva:
                    valid, msg = validate_password(password_nueva)
                    if not valid:
                        mensaje = msg
                    elif password_nueva != password_confirmar:
                        mensaje = 'Las nuevas contraseñas no coinciden'
                    else:
                        nueva_password_hash = generate_password_hash(password_nueva)
                        actualizar_password_usuario(usuario['id'], nueva_password_hash)
                        mensaje = 'Perfil y contraseña actualizados exitosamente'
                else:
                    mensaje = 'Preferencias actualizadas correctamente'
                
                # Recargar datos del usuario
                usuario = obtener_usuario_por_id(session['usuario_id'])
        
        return render_template('dashboard/editar_perfil.html', usuario=usuario, mensaje=mensaje)

    @bp.route('/editar_registro', methods=['GET', 'POST'])
    @login_required_custom
    def editar_registro():
        usuario_id = session['usuario_id']
        
        if request.method == 'GET':
            registro_id = request.args.get('id')
            tipo = request.args.get('tipo', '').strip()
            
            if not registro_id or not tipo:
                return redirect(url_for('main.registrar'))
            
            registro = None
            if tipo == 'ingreso':
                registro = obtener_ingreso_por_id(registro_id, usuario_id)
            elif tipo == 'gasto':
                registro = obtener_gasto_por_id(registro_id, usuario_id)
            elif tipo == 'inversion':
                registro = obtener_inversion_por_id(registro_id, usuario_id)
            
            if not registro:
                flash('Registro no encontrado', 'error')
                return redirect(url_for('main.registrar'))
            
            return render_template('forms/editar_registro.html', registro=registro, tipo=tipo)
        
        elif request.method == 'POST':
            registro_id = request.form.get('registro_id')
            tipo = request.form.get('tipo', '').strip()
            monto = request.form.get('monto', '').strip()
            descripcion = request.form.get('descripcion', '').strip()
            fecha = request.form.get('fecha', '').strip()
            
            valid, msg = validate_tipo(tipo)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            valid, msg = validate_monto(monto)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            valid, msg = validate_fecha(fecha)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('main.registrar'))
            
            if tipo == 'ingreso':
                actualizar_ingreso(registro_id, usuario_id, monto, descripcion, fecha)
            elif tipo == 'gasto':
                actualizar_gasto(registro_id, usuario_id, monto, descripcion, fecha)
            elif tipo == 'inversion':
                actualizar_inversion(registro_id, usuario_id, monto, descripcion, fecha)
            
            return redirect(url_for('main.registrar'))

    @bp.route('/eliminar_registro', methods=['POST'])
    @login_required_custom
    def eliminar_registro():
        registro_id = request.form.get('registro_id')
        tipo = request.form.get('tipo', '').strip()
        usuario_id = session['usuario_id']
        
        valid, msg = validate_tipo(tipo)
        if not valid:
            flash(msg, 'error')
            return redirect(url_for('main.registrar'))
        
        if tipo == 'ingreso':
            eliminar_ingreso(registro_id, usuario_id)
        elif tipo == 'gasto':
            eliminar_gasto(registro_id, usuario_id)
        elif tipo == 'inversion':
            eliminar_inversion(registro_id, usuario_id)
        
        flash('Registro eliminado exitosamente', 'success')
        return redirect(url_for('main.registrar'))

    @bp.route('/exportar_pdf', methods=['GET'])
    @login_required_custom
    def exportar_pdf():
        mes = request.args.get('mes', datetime.now().strftime('%Y-%m'))
        usuario = obtener_usuario_por_id(session['usuario_id'])
        if usuario is None:
            session.clear()
            return redirect(url_for('main.login'))
        
        # Obtener datos del mes
        anio = int(mes[:4])
        mes_num = int(mes[5:])
        
        ingresos_mes = obtener_ingresos_por_mes(usuario['id'], anio, mes_num)
        gastos_mes = obtener_gastos_por_mes(usuario['id'], anio, mes_num)
        inversiones_mes = obtener_inversiones_por_mes(usuario['id'], anio, mes_num)
        
        # Crear PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch, 
                               title="Reporte financiero", author=usuario['nombre_usuario'])
        elements = []
        
        # Estilos
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=22, textColor=colors.HexColor('#1a1a1a'), spaceAfter=24, alignment=TA_CENTER, fontName='Helvetica-Bold')
        subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#555555'), spaceAfter=6, alignment=TA_LEFT)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1a1a1a'), spaceAfter=10, spaceBefore=12, fontName='Helvetica-Bold', alignment=TA_LEFT)
        
        # Obtener fecha actual formateada
        hoy = datetime.now()
        dias = hoy.strftime('%d')
        meses_es = {'01': 'enero', '02': 'febrero', '03': 'marzo', '04': 'abril', '05': 'mayo', '06': 'junio', '07': 'julio', '08': 'agosto', '09': 'septiembre', '10': 'octubre', '11': 'noviembre', '12': 'diciembre'}
        mes_es = meses_es[hoy.strftime('%m')]
        año = hoy.strftime('%Y')
        fecha_str = f"{dias} de {mes_es} de {año}"
        
        # Título y datos generales
        title = Paragraph("Reporte financiero", title_style)
        elements.append(title)
        
        subtitle1 = Paragraph(f"Fecha: {fecha_str}", subtitle_style)
        elements.append(subtitle1)
        subtitle2 = Paragraph(f"Usuario: {usuario['nombre_usuario']}", subtitle_style)
        elements.append(subtitle2)
        elements.append(Spacer(1, 0.25*inch))
        
        # Función para crear tabla
        def crear_tabla(registros, titulo):
            if not registros:
                elements.append(Paragraph(titulo, heading_style))
                elements.append(Paragraph("<i>No hay registros</i>", styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
                return
            
            elements.append(Paragraph(titulo, heading_style))
            
            data = [['Fecha', 'Descripción', 'Monto']]
            total = 0
            for reg in registros:
                fecha = reg['fecha']
                if isinstance(fecha, datetime):
                    fecha = fecha.strftime('%d/%m/%Y')
                elif not isinstance(fecha, str):
                    fecha = str(fecha)
                data.append([fecha, reg['descripcion'], f"$ {reg['monto']:,.2f}"])
                total += reg['monto']
            
            # Agregar fila de total sin HTML
            data.append(['', 'Total', f"$ {total:,.2f}"])
            
            table = Table(data, colWidths=[1.2*inch, 3*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8e8e8')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1a1a1a')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#f5f5f5')]),
                ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e8e8e8')),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('TOPPADDING', (0, -1), (-1, -1), 12),
            ]))
            
            elements.append(table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Agregar tablas
        crear_tabla(ingresos_mes, "Ingresos")
        crear_tabla(gastos_mes, "Gastos")
        crear_tabla(inversiones_mes, "Inversiones")
        
        
        # Generar PDF
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=f"Reporte_{mes}.pdf")

    @bp.route('/exportar_excel')
    @login_required_custom
    def exportar_excel():
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        
        mes = request.args.get('mes', datetime.now().strftime('%Y-%m'))
        usuario = obtener_usuario_por_id(session['usuario_id'])
        if usuario is None:
            session.clear()
            return redirect(url_for('main.login'))
        
        # Obtener datos
        ingresos = obtener_ingresos_por_mes(usuario['id'], int(mes[:4]), int(mes[5:]))
        gastos = obtener_gastos_por_mes(usuario['id'], int(mes[:4]), int(mes[5:]))
        inversiones = obtener_inversiones_por_mes(usuario['id'], int(mes[:4]), int(mes[5:]))
        
        # Crear workbook
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = 'Reporte'
        
        # Estilos
        title_font = Font(name='Calibri', size=22, bold=True)
        subtitle_font = Font(name='Calibri', size=11, color='555555')
        header_font = Font(name='Calibri', size=13, bold=True)
        data_font = Font(name='Calibri', size=11)
        total_font = Font(name='Calibri', size=11, bold=True)
        
        header_fill = PatternFill(start_color='e8e8e8', end_color='e8e8e8', fill_type='solid')
        total_fill = PatternFill(start_color='e8e8e8', end_color='e8e8e8', fill_type='solid')
        
        alignment_center = Alignment(horizontal='center', vertical='center', wrap_text=True)
        alignment_left = Alignment(horizontal='left', vertical='center', wrap_text=True)
        alignment_right = Alignment(horizontal='right', vertical='center')
        
        thin_border = Border(
            left=Side(style='thin', color='cccccc'),
            right=Side(style='thin', color='cccccc'),
            top=Side(style='thin', color='cccccc'),
            bottom=Side(style='thin', color='cccccc')
        )
        
        # Fecha formateada
        hoy = datetime.now()
        meses_es = {'01': 'enero', '02': 'febrero', '03': 'marzo', '04': 'abril', '05': 'mayo', '06': 'junio', '07': 'julio', '08': 'agosto', '09': 'septiembre', '10': 'octubre', '11': 'noviembre', '12': 'diciembre'}
        mes_es = meses_es[hoy.strftime('%m')]
        fecha_str = f"{hoy.strftime('%d')} de {mes_es} de {hoy.strftime('%Y')}"
        
        # Agregar títulos
        row = 1
        ws[f'A{row}'] = 'Reporte financiero'
        ws[f'A{row}'].font = title_font
        ws.merge_cells(f'A{row}:C{row}')
        ws[f'A{row}'].alignment = alignment_center
        ws.row_dimensions[row].height = 35
        
        row += 2
        ws[f'A{row}'] = f'Fecha: {fecha_str}'
        ws[f'A{row}'].font = subtitle_font
        
        row += 1
        ws[f'A{row}'] = f'Usuario: {usuario["nombre_usuario"]}'
        ws[f'A{row}'].font = subtitle_font
        
        row += 2
        
        # Función para agregar tabla
        def agregar_tabla(registros, titulo, inicio_row):
            nonlocal row
            row = inicio_row
            
            ws[f'A{row}'] = titulo
            ws[f'A{row}'].font = header_font
            row += 1
            
            if not registros:
                ws[f'A{row}'] = 'No hay registros'
                row += 1
                return row
            
            # Encabezados
            ws[f'A{row}'] = 'Fecha'
            ws[f'B{row}'] = 'Descripción'
            ws[f'C{row}'] = 'Monto'
            
            for col in ['A', 'B', 'C']:
                cell = ws[f'{col}{row}']
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = alignment_center
                cell.border = thin_border
            
            row += 1
            
            # Datos
            total = 0
            for reg in registros:
                fecha = reg['fecha']
                if isinstance(fecha, datetime):
                    fecha = fecha.strftime('%Y-%m-%d')
                
                ws[f'A{row}'] = fecha
                ws[f'B{row}'] = reg['descripcion']
                ws[f'C{row}'] = reg['monto']
                
                ws[f'A{row}'].font = data_font
                ws[f'B{row}'].font = data_font
                ws[f'C{row}'].font = data_font
                
                ws[f'A{row}'].alignment = alignment_center
                ws[f'B{row}'].alignment = alignment_left
                ws[f'C{row}'].alignment = alignment_right
                
                ws[f'C{row}'].number_format = '$ #,##0.00'
                
                for col in ['A', 'B', 'C']:
                    ws[f'{col}{row}'].border = thin_border
                
                total += reg['monto']
                row += 1
            
            # Fila de total
            ws[f'B{row}'] = 'Total'
            ws[f'C{row}'] = total
            
            ws[f'B{row}'].font = total_font
            ws[f'C{row}'].font = total_font
            
            ws[f'B{row}'].alignment = alignment_right
            ws[f'C{row}'].alignment = alignment_right
            
            ws[f'C{row}'].number_format = '$ #,##0.00'
            
            ws[f'B{row}'].fill = total_fill
            ws[f'C{row}'].fill = total_fill
            
            for col in ['A', 'B', 'C']:
                ws[f'{col}{row}'].border = thin_border
            
            row += 2
            return row
        
        # Agregar tablas
        row = agregar_tabla(ingresos, 'Ingresos', row)
        row = agregar_tabla(gastos, 'Gastos', row)
        row = agregar_tabla(inversiones, 'Inversiones', row)
        
        # Ajustar ancho de columnas
        ws.column_dimensions['A'].width = 15
        ws.column_dimensions['B'].width = 35
        ws.column_dimensions['C'].width = 18
        
        # Guardar en buffer
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
                         as_attachment=True, download_name=f"Reporte_{mes}.xlsx")


    @bp.route('/metas', methods=['GET', 'POST'])
    @login_required_custom
    def metas():
        usuario_id = session['usuario_id']
        if request.method == 'POST':
            nombre = request.form.get('nombre')
            monto_objetivo = request.form.get('monto_objetivo')
            if agregar_meta(usuario_id, nombre, monto_objetivo):
                flash('Meta creada', 'success')
            else:
                flash('Error al crear meta', 'error')
            return redirect(url_for('main.metas'))
            
        mis_metas = obtener_metas(usuario_id)
        for m in mis_metas:
            # Convertir ambos a float para evitar errores de tipos
            m['monto_actual'] = float(m.get('monto_actual') or 0)
            m['monto_objetivo'] = float(m.get('monto_objetivo') or 0)
            m['porcentaje'] = round((m['monto_actual'] / m['monto_objetivo'] * 100), 1) if m['monto_objetivo'] > 0 else 0
            
        return render_template('config/metas.html', metas=mis_metas)

    @bp.route('/eliminar_meta/<int:id>')
    @login_required_custom
    def eliminar_meta(id):
        if eliminar_meta_db(id, session['usuario_id']):
            flash('Meta eliminada', 'success')
        return redirect(url_for('main.metas'))

    @bp.route('/aporte_meta/<int:id>', methods=['POST'])
    @login_required_custom
    def aporte_meta(id):
        import json
        data = json.loads(request.data)
        monto = float(data.get('monto', 0))
        
        if monto <= 0:
            return jsonify({'success': False, 'message': 'Monto inválido'})
        
        if actualizar_aporte_meta(id, session['usuario_id'], monto):
            return jsonify({'success': True, 'message': 'Aporte registrado'})
        else:
            return jsonify({'success': False, 'message': 'Error al registrar aporte'})


    @bp.route('/recurrentes', methods=['GET', 'POST'])
    @login_required_custom
    def recurrentes():
        usuario_id = session['usuario_id']
        if request.method == 'POST':
            tipo = request.form.get('tipo')
            monto = request.form.get('monto')
            descripcion = request.form.get('descripcion')
            frecuencia = request.form.get('frecuencia')
            proxima_fecha = request.form.get('proxima_fecha')
            if agregar_recurrente(usuario_id, tipo, monto, descripcion, frecuencia, proxima_fecha):
                flash('Transacción recurrente programada', 'success')
            else:
                flash('Error al programar transacción', 'error')
            return redirect(url_for('main.recurrentes'))
            
        mis_recurrentes = obtener_recurrentes(usuario_id)
        return render_template('config/recurrentes.html', recurrentes=mis_recurrentes)

    @bp.route('/eliminar_recurrente/<int:id>')
    @login_required_custom
    def eliminar_recurrente(id):
        if eliminar_recurrente_db(id, session['usuario_id']):
            flash('Programación eliminada', 'success')
        return redirect(url_for('main.recurrentes'))

    @bp.route('/seguridad', methods=['GET', 'POST'])
    @login_required_custom
    def seguridad():
        try:
            usuario_id = session['usuario_id']
            usuario = obtener_usuario_por_id(usuario_id)
            
            if request.method == 'POST':
                # Checkbox state
                MFA = request.form.get('MFA') is not None
                
                # Si se está activando (y no estaba activo)
                if MFA and not usuario.get('MFA'):
                    try:
                        import pyotp
                        import qrcode
                        import io
                        import base64
                    except ImportError as e:
                        flash("Error: Faltan librerías de seguridad (pyotp/qrcode)", "error")
                        return redirect(url_for('main.seguridad'))

                    # Generar nuevo secreto
                    secret = pyotp.random_base32()
                    if not actualizar_totp_secret_db(usuario_id, secret):
                        flash("Error al guardar secreto de seguridad en base de datos", "error")
                        return redirect(url_for('main.seguridad'))
                    
                    # Generar QR
                    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=usuario['nombre_usuario'], issuer_name="App Money")
                    img = qrcode.make(uri)
                    buffered = io.BytesIO()
                    img.save(buffered, format="PNG")
                    qr_b64 = base64.b64encode(buffered.getvalue()).decode()
                    
                    # Activar en BD
                    actualizar_seguridad_usuario(usuario_id, True)
                    
                    # Recargar usuario para verificar
                    usuario_actualizado = obtener_usuario_por_id(usuario_id)
                    
                    flash('2FA Activado. Escanea el código QR para configurar tu aplicación.', 'success')
                    # Renderizar con el código QR
                    return render_template('auth/seguridad.html', usuario=usuario_actualizado, qr_code=qr_b64, secret=secret)
                
                elif not MFA and usuario.get('MFA'):
                    # Desactivar
                    actualizar_seguridad_usuario(usuario_id, False)
                    flash('2FA Desactivado', 'success')
                    return redirect(url_for('main.seguridad'))
                
                # Si no hubo cambio de estado pero se hizo post
                return redirect(url_for('main.seguridad'))
                
            return render_template('auth/seguridad.html', usuario=usuario)
        except Exception as e:
            import traceback
            traceback.print_exc()
            flash(f"Error interno: {str(e)}", "error")
            return redirect(url_for('main.dashboard')) # Fallback seguro

    @bp.route('/buscar')
    @login_required_custom
    def buscar():
        usuario_id = session['usuario_id']
        q = request.args.get('q', '')
        desde = request.args.get('desde')
        hasta = request.args.get('hasta')
        
        resultados = obtener_transacciones_filtradas(usuario_id, q, desde, hasta)
        return render_template('dashboard/buscar.html', resultados=resultados)


    @bp.route('/categorias', methods=['GET', 'POST'])
    @login_required_custom
    def categorias_route():
        usuario_id = session['usuario_id']
        if request.method == 'POST':
            nombre = request.form.get('nombre')
            tipo = request.form.get('tipo')
            color = request.form.get('color')
            if agregar_categoria(usuario_id, nombre, tipo, color):
                flash('Categoría agregada', 'success')
            else:
                flash('Error al agregar categoría', 'error')
            return redirect(url_for('main.categorias_route'))
        
        categorias_list = obtener_categorias(usuario_id)
        return render_template('config/categorias.html', categorias=categorias_list)

    @bp.route('/eliminar_categoria/<int:id>')
    @login_required_custom
    def eliminar_categoria_route(id):
        if eliminar_categoria_db(id, session['usuario_id']):
            flash('Categoría eliminada', 'success')
        return redirect(url_for('main.categorias_route'))

    @bp.route('/presupuestos', methods=['GET', 'POST'])
    @login_required_custom
    def presupuestos():
        usuario_id = session['usuario_id']
        if request.method == 'POST':
            categoria_id = request.form.get('categoria_id')
            try:
                monto = float(request.form.get('monto', 0))
            except (ValueError, TypeError):
                monto = 0
            if agregar_o_actualizar_presupuesto(usuario_id, categoria_id, monto):
                flash('Presupuesto actualizado', 'success')
            else:
                flash('Error al actualizar presupuesto', 'error')
            return redirect(url_for('main.presupuestos'))
            
        mis_presupuestos = obtener_presupuestos_simples(usuario_id)
        return render_template('config/presupuestos.html', presupuestos=mis_presupuestos)

    @bp.route('/editar_presupuesto/<int:id>', methods=['POST'])
    @login_required_custom
    def editar_presupuesto(id):
        usuario_id = session['usuario_id']
        try:
            gastado = float(request.form.get('gastado', 0))
        except (ValueError, TypeError):
            gastado = 0
        
        if actualizar_presupuesto_gastado(usuario_id, id, gastado):
            # Si es una petición AJAX, devolver JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'gastado': gastado})
            flash('Presupuesto actualizado', 'success')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'Error al actualizar presupuesto'})
            flash('Error al actualizar presupuesto', 'error')
        
        return redirect(url_for('main.presupuestos'))

    @bp.route('/eliminar_presupuesto/<int:id>', methods=['GET'])
    @login_required_custom
    def eliminar_presupuesto(id):
        usuario_id = session['usuario_id']
        
        if eliminar_presupuesto_db(usuario_id, id):
            flash('Presupuesto eliminado', 'success')
        else:
            flash('Error al eliminar presupuesto', 'error')
        
        return redirect(url_for('main.presupuestos'))

    app.register_blueprint(bp)

# --- Funciones auxiliares para la lógica de base de datos ---
def obtener_usuario_por_id(usuario_id):
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM usuarios WHERE id = %s', (usuario_id,))
        usuario = cursor.fetchone()
        cursor.close()
        return usuario
    finally:
        conn.close()

def obtener_usuario_por_nombre(nombre_usuario):
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM usuarios WHERE nombre_usuario = %s', (nombre_usuario,))
        usuario = cursor.fetchone()
        cursor.close()
        return usuario
    finally:
        conn.close()

def crear_usuario(nombre_usuario, password_hash):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO usuarios (nombre_usuario, password_hash) VALUES (%s, %s)', (nombre_usuario, password_hash))
        usuario_id = cursor.lastrowid
        
        # Crear categorías por defecto
        categorias_defecto = [
            ('Gastos Generales', 'gasto', '#dc2626'),
            ('Ingresos Generales', 'ingreso', '#16a34a'),
            ('Inversiones Generales', 'inversion', '#2563eb')
        ]
        
        for nombre, tipo, color in categorias_defecto:
            cursor.execute('INSERT INTO categorias (usuario_id, nombre, tipo, color) VALUES (%s, %s, %s, %s)',
                          (usuario_id, nombre, tipo, color))
        
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def obtener_ingresos(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM ingresos WHERE usuario_id = %s ORDER BY fecha DESC', (usuario_id,))
        ingresos = cursor.fetchall()
        cursor.close()
        return ingresos
    finally:
        conn.close()

def obtener_gastos(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM gastos WHERE usuario_id = %s ORDER BY fecha DESC', (usuario_id,))
        gastos = cursor.fetchall()
        cursor.close()
        return gastos
    finally:
        conn.close()

def obtener_categoria_defecto(usuario_id, tipo):
    """Obtiene la categoría por defecto para un tipo de transacción"""
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id FROM categorias WHERE usuario_id = %s AND tipo = %s LIMIT 1', (usuario_id, tipo))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado['id'] if resultado else None
    finally:
        conn.close()

def agregar_ingreso(usuario_id, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        categoria_id = obtener_categoria_defecto(usuario_id, 'ingreso')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO ingresos (usuario_id, monto, descripcion, fecha, categoria_id) VALUES (%s, %s, %s, %s, %s)', (usuario_id, monto, descripcion, fecha, categoria_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()
def agregar_inversion(usuario_id, tipo, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        categoria_id = obtener_categoria_defecto(usuario_id, 'inversion')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO inversiones (usuario_id, monto, descripcion, fecha, categoria_id) VALUES (%s, %s, %s, %s, %s)', (usuario_id, monto, descripcion, fecha, categoria_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def obtener_inversiones(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM inversiones WHERE usuario_id = %s ORDER BY fecha DESC', (usuario_id,))
        inversiones = cursor.fetchall()
        cursor.close()
        return inversiones
    finally:
        conn.close()

def obtener_inversiones_por_mes(usuario_id, anio, mes):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM inversiones WHERE usuario_id = %s AND YEAR(fecha) = %s AND MONTH(fecha) = %s ORDER BY fecha DESC', (usuario_id, anio, mes))
        inversiones = cursor.fetchall()
        cursor.close()
        return inversiones
    finally:
        conn.close()
def agregar_gasto(usuario_id, monto, descripcion, fecha, categoria_id=None):
    """Agrega un gasto - categoria_id es opcional"""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO gastos (usuario_id, monto, descripcion, fecha, categoria_id) VALUES (%s, %s, %s, %s, %s)', 
                      (usuario_id, monto, descripcion, fecha, categoria_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def obtener_ingresos_por_mes(usuario_id, anio, mes):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM ingresos WHERE usuario_id = %s AND YEAR(fecha) = %s AND MONTH(fecha) = %s ORDER BY fecha DESC', (usuario_id, anio, mes))
        ingresos = cursor.fetchall()
        cursor.close()
        return ingresos
    finally:
        conn.close()

def obtener_gastos_por_mes(usuario_id, anio, mes):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM gastos WHERE usuario_id = %s AND YEAR(fecha) = %s AND MONTH(fecha) = %s ORDER BY fecha DESC', (usuario_id, anio, mes))
        gastos = cursor.fetchall()
        cursor.close()
        return gastos
    finally:
        conn.close()
def actualizar_password_usuario(usuario_id, nueva_password_hash):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET password_hash = %s WHERE id = %s', (nueva_password_hash, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def eliminar_ingreso(ingreso_id, usuario_id):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ingresos WHERE id = %s AND usuario_id = %s', (ingreso_id, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def eliminar_gasto(gasto_id, usuario_id):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM gastos WHERE id = %s AND usuario_id = %s', (gasto_id, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def eliminar_inversion(inversion_id, usuario_id):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM inversiones WHERE id = %s AND usuario_id = %s', (inversion_id, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def obtener_ingreso_por_id(ingreso_id, usuario_id):
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM ingresos WHERE id = %s AND usuario_id = %s', (ingreso_id, usuario_id))
        ingreso = cursor.fetchone()
        cursor.close()
        return ingreso
    finally:
        conn.close()

def obtener_gasto_por_id(gasto_id, usuario_id):
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM gastos WHERE id = %s AND usuario_id = %s', (gasto_id, usuario_id))
        gasto = cursor.fetchone()
        cursor.close()
        return gasto
    finally:
        conn.close()

def obtener_inversion_por_id(inversion_id, usuario_id):
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM inversiones WHERE id = %s AND usuario_id = %s', (inversion_id, usuario_id))
        inversion = cursor.fetchone()
        cursor.close()
        return inversion
    finally:
        conn.close()

def actualizar_ingreso(ingreso_id, usuario_id, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE ingresos SET monto = %s, descripcion = %s, fecha = %s WHERE id = %s AND usuario_id = %s', 
                      (monto, descripcion, fecha, ingreso_id, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def actualizar_gasto(gasto_id, usuario_id, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE gastos SET monto = %s, descripcion = %s, fecha = %s WHERE id = %s AND usuario_id = %s', 
                      (monto, descripcion, fecha, gasto_id, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def actualizar_inversion(inversion_id, usuario_id, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE inversiones SET monto = %s, descripcion = %s, fecha = %s WHERE id = %s AND usuario_id = %s', 
                      (monto, descripcion, fecha, inversion_id, usuario_id))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def crear_token_recuperacion(usuario_id, token, expires_at):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO password_reset_tokens (usuario_id, token, expires_at) VALUES (%s, %s, %s)', 
                      (usuario_id, token, expires_at))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def obtener_token_recuperacion(token):
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM password_reset_tokens WHERE token = %s', (token,))
        token_data = cursor.fetchone()
        cursor.close()
        return token_data
    finally:
        conn.close()

def eliminar_token_recuperacion(token):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM password_reset_tokens WHERE token = %s', (token,))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def actualizar_token_verificado(token):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE password_reset_tokens SET verified = TRUE WHERE token = %s', (token,))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def incrementar_intentos_captcha(token, intentos):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE password_reset_tokens SET captcha_attempt = %s WHERE token = %s', (intentos, token))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()



def obtener_metas(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM metas WHERE usuario_id = %s', (usuario_id,))
        return cursor.fetchall()
    finally:
        conn.close()

def agregar_meta(usuario_id, nombre, monto_objetivo):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO metas (usuario_id, nombre, monto_objetivo) VALUES (%s, %s, %s)', (usuario_id, nombre, monto_objetivo))
        conn.commit()
        return True
    finally:
        conn.close()

def eliminar_meta_db(id, usuario_id):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM metas WHERE id = %s AND usuario_id = %s', (id, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()

def actualizar_aporte_meta(meta_id, usuario_id, monto):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE metas SET monto_actual = monto_actual + %s WHERE id = %s AND usuario_id = %s', (monto, meta_id, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()

def obtener_recurrentes(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM transacciones_recurrentes WHERE usuario_id = %s AND activo = TRUE', (usuario_id,))
        return cursor.fetchall()
    finally:
        conn.close()

def agregar_recurrente(usuario_id, tipo, monto, descripcion, frecuencia, proxima_fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO transacciones_recurrentes (usuario_id, tipo, monto, descripcion, frecuencia, proxima_fecha) 
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (usuario_id, tipo, monto, descripcion, frecuencia, proxima_fecha))
        conn.commit()
        return True
    finally:
        conn.close()

def eliminar_recurrente_db(id, usuario_id):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM transacciones_recurrentes WHERE id = %s AND usuario_id = %s', (id, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()

def actualizar_seguridad_usuario(usuario_id, MFA):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET MFA = %s WHERE id = %s', (MFA, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()

def procesar_recurrentes_usuario(usuario_id):
    """Verifica si hay transacciones recurrentes que deben ejecutarse hoy o en el pasado."""
    conn = get_connection()
    if conn is None:
        return
    try:
        cursor = conn.cursor(dictionary=True)
        hoy = datetime.now().date()
        cursor.execute('SELECT * FROM transacciones_recurrentes WHERE usuario_id = %s AND proxima_fecha <= %s AND activo = TRUE', (usuario_id, hoy))
        pendientes = cursor.fetchall()
        
        for p in pendientes:
            # Insertar en la tabla correspondiente
            if p['tipo'] == 'ingreso':
                cursor.execute('INSERT INTO ingresos (usuario_id, monto, descripcion, fecha) VALUES (%s, %s, %s, %s)', 
                             (usuario_id, p['monto'], f"[Recurrente] {p['descripcion']}", p['proxima_fecha']))
            elif p['tipo'] == 'gasto':
                cursor.execute('INSERT INTO gastos (usuario_id, monto, descripcion, fecha) VALUES (%s, %s, %s, %s)', 
                             (usuario_id, p['monto'], f"[Recurrente] {p['descripcion']}", p['proxima_fecha']))
            
            # Calcular proxima fecha
            prox = p['proxima_fecha']
            if p['frecuencia'] == 'mensual':
                # Sumar un mes (aproximado)
                import calendar
                mo = prox.month + 1
                yr = prox.year
                if mo > 12:
                    mo = 1
                    yr += 1
                last_day = calendar.monthrange(yr, mo)[1]
                prox = prox.replace(year=yr, month=mo, day=min(prox.day, last_day))
            elif p['frecuencia'] == 'semanal':
                prox = prox + timedelta(days=7)
            elif p['frecuencia'] == 'diario':
                prox = prox + timedelta(days=1)
            elif p['frecuencia'] == 'anual':
                prox = prox.replace(year=prox.year + 1)
            
            cursor.execute('UPDATE transacciones_recurrentes SET proxima_fecha = %s WHERE id = %s', (prox, p['id']))
            
        conn.commit()
    except Exception as e:
        pass
    finally:
        conn.close()

def actualizar_perfil_usuario_db(usuario_id, nombre_completo='', email='', telefono='', pais='', ciudad='', moneda='USD'):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET nombre_completo = %s, email = %s, telefono = %s, pais = %s, ciudad = %s, moneda = %s WHERE id = %s', 
                       (nombre_completo, email, telefono, pais, ciudad, moneda, usuario_id))
        conn.commit()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def actualizar_foto_perfil_db(usuario_id, foto_path):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET foto_perfil = %s WHERE id = %s', (foto_path, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()

def actualizar_nombre_usuario_db(usuario_id, nuevo_nombre):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        # Verificar si ya existe (excluyendo el usuario actual)
        cursor.execute('SELECT id FROM usuarios WHERE nombre_usuario = %s AND id != %s', (nuevo_nombre, usuario_id))
        if cursor.fetchone():
            return False
            
        cursor.execute('UPDATE usuarios SET nombre_usuario = %s WHERE id = %s', (nuevo_nombre, usuario_id))
        conn.commit()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def obtener_transacciones_filtradas(usuario_id, q, desde, hasta):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """
            SELECT tipo, monto, descripcion, fecha FROM (
                SELECT 'ingreso' as tipo, monto, descripcion, fecha FROM ingresos WHERE usuario_id = %s
                UNION ALL
                SELECT 'gasto' as tipo, monto, descripcion, fecha FROM gastos WHERE usuario_id = %s
                UNION ALL
                SELECT 'inversion' as tipo, monto, descripcion, fecha FROM inversiones WHERE usuario_id = %s
            ) as t WHERE 1=1
        """
        params = [usuario_id, usuario_id, usuario_id]
        
        if q:
            sql += " AND descripcion LIKE %s"
            params.append(f"%{q}%")
        if desde:
            sql += " AND fecha >= %s"
            params.append(desde)
        if hasta:
            sql += " AND fecha <= %s"
            params.append(hasta)
            
        sql += " ORDER BY fecha DESC"
        cursor.execute(sql, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()

def obtener_categorias(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM categorias WHERE usuario_id = %s', (usuario_id,))
        return cursor.fetchall()
    finally:
        conn.close()

def agregar_categoria(usuario_id, nombre, tipo, color):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO categorias (usuario_id, nombre, tipo, color) VALUES (%s, %s, %s, %s)', 
                      (usuario_id, nombre, tipo, color))
        conn.commit()
        return True
    finally:
        conn.close()

def eliminar_categoria_db(id, usuario_id):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM categorias WHERE id = %s AND usuario_id = %s', (id, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()

def obtener_presupuestos_detallados(usuario_id):
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        # Obtener presupuestos con el nombre de la categoría y el gasto actual del mes
        hoy = datetime.now()
        mes = hoy.month
        anio = hoy.year
        
        cursor.execute('''
            SELECT p.*, c.nombre as categoria_nombre, 
            (SELECT COALESCE(SUM(monto), 0) FROM gastos 
             WHERE usuario_id = %s AND categoria_id = p.categoria_id 
             AND MONTH(fecha) = %s AND YEAR(fecha) = %s) as gasto_actual
            FROM presupuestos p
            JOIN categorias c ON p.categoria_id = c.id
            WHERE p.usuario_id = %s
        ''', (usuario_id, mes, anio, usuario_id))
        
        presupuestos = cursor.fetchall()
        for p in presupuestos:
            p['porcentaje'] = round((float(p['gasto_actual']) / float(p['monto']) * 100), 1) if p['monto'] > 0 else 0
        return presupuestos
    finally:
        conn.close()

def obtener_presupuestos_simples(usuario_id):
    """Obtiene presupuestos con gastos reales del mes actual"""
    conn = get_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, usuario_id, categoria_id, monto, gastado FROM presupuestos WHERE usuario_id = %s', (usuario_id,))
        presupuestos = cursor.fetchall()
        
        # Obtener gastos totales del mes actual
        cursor.execute(
            '''SELECT SUM(monto) as total_gastos 
               FROM gastos 
               WHERE usuario_id = %s 
               AND MONTH(fecha) = MONTH(NOW()) 
               AND YEAR(fecha) = YEAR(NOW())''',
            (usuario_id,)
        )
        gasto_total_result = cursor.fetchone()
        gasto_total = float(gasto_total_result['total_gastos'] or 0) if gasto_total_result else 0
        
        for p in presupuestos:
            p['categoria_nombre'] = p.get('categoria_id', 'Sin categoría')
            p['monto'] = float(p.get('monto') or 0)
            p['gastado'] = float(p.get('gastado') or 0)
            
            # Por simplicidad, distribuir los gastos totales entre los presupuestos
            # En un futuro, esto debería conectarse con categorías reales
            if len(presupuestos) > 0:
                p['gasto_actual'] = gasto_total / len(presupuestos)
            else:
                p['gasto_actual'] = 0
            
            # Calcular porcentaje usando gastado si está disponible, sino usar gasto_actual
            gasto_para_calculo = p['gastado'] if p['gastado'] > 0 else p['gasto_actual']
            p['porcentaje'] = round((gasto_para_calculo / p['monto'] * 100), 1) if p['monto'] > 0 else 0
            # Para la progress bar, limitar a 100 visualmente pero guardar el valor real
            p['porcentaje_visual'] = min(p['porcentaje'], 100)
        
        return presupuestos
    finally:
        conn.close()

def agregar_o_actualizar_presupuesto(usuario_id, categoria_id, monto):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id FROM presupuestos WHERE usuario_id = %s AND categoria_id = %s', (usuario_id, categoria_id))
        existente = cursor.fetchone()
        
        if existente:
            cursor.execute('UPDATE presupuestos SET monto = %s WHERE id = %s', (monto, existente['id']))
        else:
            cursor.execute('INSERT INTO presupuestos (usuario_id, categoria_id, monto) VALUES (%s, %s, %s)', 
                          (usuario_id, categoria_id, monto))
        conn.commit()
        return True
    finally:
        conn.close()

def actualizar_totp_secret_db(usuario_id, secret):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET totp_secret = %s WHERE id = %s', (secret, usuario_id))
        conn.commit()
        return True
    finally:
        conn.close()
def actualizar_ultimo_login(usuario_id):
    """Actualiza la fecha y hora del último login del usuario"""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET ultimo_login = NOW() WHERE id = %s', (usuario_id,))
        conn.commit()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def actualizar_presupuesto(usuario_id, presupuesto_id, monto):
    """Actualiza el monto de un presupuesto"""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE presupuestos SET monto = %s WHERE id = %s AND usuario_id = %s', 
                      (monto, presupuesto_id, usuario_id))
        conn.commit()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def actualizar_presupuesto_gastado(usuario_id, presupuesto_id, gastado):
    """Actualiza el gastado de un presupuesto"""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE presupuestos SET gastado = %s WHERE id = %s AND usuario_id = %s', 
                      (gastado, presupuesto_id, usuario_id))
        conn.commit()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def eliminar_presupuesto_db(usuario_id, presupuesto_id):
    """Elimina un presupuesto"""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM presupuestos WHERE id = %s AND usuario_id = %s', 
                      (presupuesto_id, usuario_id))
        conn.commit()
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

# --- Funciones auxiliares para MFA/TOTP ---
def validar_totp(totp_secret, codigo):
    """Valida un código TOTP contra el secreto del usuario"""
    try:
        totp = pyotp.TOTP(totp_secret)
        # Permitir ventana de ±30 segundos (1 ventana antes y después)
        return totp.verify(codigo, valid_window=1)
    except Exception as e:
        return False

def obtener_totp_secret_usuario(usuario_id):
    """Obtiene el secreto TOTP de un usuario"""
    conn = get_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT totp_secret FROM usuarios WHERE id = %s', (usuario_id,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado['totp_secret'] if resultado else None
    except Exception as e:
        return None
    finally:
        conn.close()

def usuario_tiene_mfa_activado(usuario_id):
    """Verifica si un usuario tiene MFA activado"""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT MFA FROM usuarios WHERE id = %s', (usuario_id,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado['MFA'] if resultado else False
    except Exception as e:
        return False
    finally:
        conn.close()