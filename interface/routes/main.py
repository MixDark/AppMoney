from flask import render_template, request, redirect, url_for, session, flash
from flask import Blueprint
from functools import wraps
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from infrastructure.db import get_connection
from infrastructure.validators import *
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

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
        ingresos = obtener_ingresos(usuario['id'])
        gastos = obtener_gastos(usuario['id'])
        inversiones = obtener_inversiones(usuario['id'])
        total_ingresos = sum(i['monto'] for i in ingresos)
        total_gastos = sum(g['monto'] for g in gastos)
        total_inversiones = sum(inv['monto'] for inv in inversiones)
        saldo = total_ingresos - total_gastos
        return render_template('dashboard/consolidado.html', usuario=usuario, ingresos=ingresos, gastos=gastos, inversiones=inversiones, total_ingresos=total_ingresos, total_gastos=total_gastos, total_inversiones=total_inversiones, saldo=saldo)

    @bp.route('/login', methods=['GET', 'POST'])
    def login():
        mensaje = None
        if request.method == 'POST':
            nombre_usuario = request.form.get('nombre_usuario', '').strip()
            password = request.form.get('password', '')
            
            valid, msg = validate_username(nombre_usuario)
            if not valid:
                mensaje = msg
                return render_template('auth/login.html', mensaje=mensaje)
            
            usuario = obtener_usuario_por_nombre(nombre_usuario)
            
            if not usuario:
                mensaje = 'Usuario no encontrado'
            elif not check_password_hash(usuario['password_hash'], password):
                mensaje = 'Contraseña incorrecta'
            else:
                session.permanent = True
                session['usuario_id'] = usuario['id']
                return redirect(url_for('main.consolidado'))
        
        return render_template('auth/login.html', mensaje=mensaje)

    @bp.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('main.login'))

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
            
            return redirect(url_for('main.registrar'))
        
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
        total_ingresos = sum(i['monto'] for i in ingresos)
        total_gastos = sum(g['monto'] for g in gastos)
        total_inversiones = sum(inv['monto'] for inv in inversiones)
        saldo = total_ingresos - total_gastos
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
        total_inversiones = sum(i['monto'] for i in inversiones_list)
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

    @bp.route('/editar_perfil', methods=['GET', 'POST'])
    def editar_perfil():
        if 'usuario_id' not in session:
            return redirect(url_for('main.login'))
        
        usuario = obtener_usuario_por_id(session['usuario_id'])
        mensaje = None
        
        if request.method == 'POST':
            password_actual = request.form.get('password_actual', '')
            password_nueva = request.form.get('password_nueva', '')
            password_confirmar = request.form.get('password_confirmar', '')
            
            if not check_password_hash(usuario['password_hash'], password_actual):
                mensaje = 'La contraseña actual es incorrecta'
            elif password_nueva:
                valid, msg = validate_password(password_nueva)
                if not valid:
                    mensaje = msg
                elif password_nueva != password_confirmar:
                    mensaje = 'Las nuevas contraseñas no coinciden'
                else:
                    nueva_password_hash = generate_password_hash(password_nueva)
                    actualizar_password_usuario(usuario['id'], nueva_password_hash)
                    mensaje = 'Contraseña actualizada exitosamente'
                    usuario = obtener_usuario_por_id(session['usuario_id'])
            else:
                mensaje = 'No hubo cambios para guardar'
        
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
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        print(f"Error al crear usuario: {e}")
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

def agregar_ingreso(usuario_id, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO ingresos (usuario_id, monto, descripcion, fecha) VALUES (%s, %s, %s, %s)', (usuario_id, monto, descripcion, fecha))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        print(f"Error al agregar ingreso: {e}")
        return False
    finally:
        conn.close()
def agregar_inversion(usuario_id, tipo, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO inversiones (usuario_id, monto, descripcion, fecha) VALUES (%s, %s, %s, %s)', (usuario_id, monto, descripcion, fecha))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        print(f"Error al agregar inversión: {e}")
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
def agregar_gasto(usuario_id, monto, descripcion, fecha):
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO gastos (usuario_id, monto, descripcion, fecha) VALUES (%s, %s, %s, %s)', (usuario_id, monto, descripcion, fecha))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        print(f"Error al agregar gasto: {e}")
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
        print(f"Error al actualizar contraseña: {e}")
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
        print(f"Error al eliminar ingreso: {e}")
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
        print(f"Error al eliminar gasto: {e}")
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
        print(f"Error al eliminar inversión: {e}")
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
        print(f"Error al actualizar ingreso: {e}")
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
        print(f"Error al actualizar gasto: {e}")
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
        print(f"Error al actualizar inversión: {e}")
        return False
    finally:
        conn.close()