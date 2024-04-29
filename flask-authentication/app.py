from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Generate RSA key pair
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

private_key, public_key = generate_key_pair()

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    print("Opened database successfully")
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)')
    print("Table created successfully")
    conn.close()

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Encrypt the password using RSA public key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_password = base64.b64encode(cipher_rsa.encrypt(password.encode()))

        # Insert user into database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted_password))
        conn.commit()
        conn.close()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve encrypted password from the database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        encrypted_password = cursor.fetchone()
        conn.close()

        if encrypted_password:
            # Decrypt the stored password using RSA private key
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
            decrypted_password = cipher_rsa.decrypt(base64.b64decode(encrypted_password[0])).decode()

            # Check if the decrypted password matches the input password
            if decrypted_password == password:
                session['logged_in'] = True
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('home'))

        flash('Invalid username or password. Please try again.', 'error')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Home route (requires authentication)
@app.route('/')
def home():
    if 'logged_in' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
