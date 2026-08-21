from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura'

# Inicialización de la Base de Datos SQL
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            rol TEXT NOT NULL DEFAULT 'cliente'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Decorador para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor inicia sesión primero.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Ruta: Registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        rol = request.form.get('rol', 'cliente')

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)',
                           (nombre, email, password, rol))
            conn.commit()
            conn.close()
            flash('¡Registro exitoso! Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El correo ya está registrado.', 'danger')

    return render_template('registro.html')

# Ruta: Login
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['usuario_id'] = user[0]
            session['nombre'] = user[1]
            session['email'] = user[2]
            session['rol'] = user[4]
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas.', 'danger')

    return render_template('login.html')

# Ruta: Panel Principal (Dashboard según Rol)
@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Si es Admin, trae a todos los usuarios registrados
    todos_los_usuarios = []
    if session['rol'] == 'admin':
        cursor.execute('SELECT id, nombre, email, rol FROM usuarios')
        todos_los_usuarios = cursor.fetchall()
    
    conn.close()
    return render_template('dashboard.html', usuarios=todos_los_usuarios)

# Ruta: Cerrar Sesión
@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)