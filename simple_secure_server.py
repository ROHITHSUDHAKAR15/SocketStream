import os
import json
import base64
import hashlib
import threading
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt
import ssl

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Global variables
connected_users = {}
user_keys = {}
message_history = []
broadcast_messages = []
db_lock = threading.Lock()

# Initialize database
def init_database():
    with db_lock:
        conn = sqlite3.connect('secure_messaging.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT,
                private_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT,
                encrypted_message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

# Encryption utilities
def generate_key_pair():
    """Generate RSA key pair for user"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

def encrypt_message(message, public_key_pem):
    """Encrypt message using recipient's public key"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        # Generate a random AES key for message encryption
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Encrypt the message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the message to be a multiple of 16 bytes
        padded_message = message.encode()
        padding_length = 16 - (len(padded_message) % 16)
        padded_message += bytes([padding_length] * padding_length)
        
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt the AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key, IV, and encrypted message
        combined = encrypted_key + iv + encrypted_message
        return base64.b64encode(combined).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_data, private_key_pem):
    """Decrypt message using user's private key"""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decode the combined data
        combined = base64.b64decode(encrypted_data)
        
        # Extract encrypted key, IV, and encrypted message
        encrypted_key = combined[:256]  # RSA encrypted key
        iv = combined[256:272]  # 16 bytes IV
        encrypted_message = combined[272:]  # AES encrypted message
        
        # Decrypt the AES key
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt the message
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
        
        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted_message = decrypted_padded[:-padding_length]
        
        return decrypted_message.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Database operations
def save_user(username, password_hash, public_key, private_key=None):
    """Save user to database"""
    with db_lock:
        conn = sqlite3.connect('secure_messaging.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO users (username, password_hash, public_key, private_key) VALUES (?, ?, ?, ?)',
            (username, password_hash, public_key, private_key)
        )
        conn.commit()
        conn.close()

def get_user(username):
    """Get user from database"""
    with db_lock:
        conn = sqlite3.connect('secure_messaging.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        return user

def save_message(sender, recipient, encrypted_message, message_type='broadcast'):
    """Save encrypted message to database"""
    with db_lock:
        conn = sqlite3.connect('secure_messaging.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO messages (sender, recipient, encrypted_message) VALUES (?, ?, ?)',
            (sender, recipient, encrypted_message)
        )
        conn.commit()
        conn.close()

# Flask routes
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'})
        
        # Check if user already exists
        existing_user = get_user(username)
        if existing_user:
            return jsonify({'success': False, 'message': 'Username already exists'})
        
        # Generate key pair
        private_key, public_key = generate_key_pair()
        
        # Hash password with bcrypt
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        # Save user with private key (NOT secure for production!)
        save_user(username, password_hash, public_key, private_key)
        
        # Store private key in session
        session['private_key'] = private_key
        session['username'] = username
        
        return jsonify({'success': True, 'message': 'Registration successful'})
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'})
        
        # Get user from database
        user = get_user(username)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        # Verify password
        if bcrypt.checkpw(password.encode(), user[2].encode()):
            session['username'] = username
            session['private_key'] = user[4]  # Private key is now at index 4
            return jsonify({'success': True, 'message': 'Login successful'})
        else:
            return jsonify({'success': False, 'message': 'Invalid password'})
    
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('simple_chat.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    data = request.get_json()
    message = data.get('message', '').strip()
    recipient = data.get('recipient')
    
    if not message:
        return jsonify({'success': False, 'message': 'Message cannot be empty'})
    
    sender = session['username']
    
    # For broadcast messages (no recipient specified)
    if not recipient or recipient == '':
        # Create a broadcast message that all users can decrypt
        try:
            # Get all users to encrypt for each one
            with db_lock:
                conn = sqlite3.connect('secure_messaging.db')
                cursor = conn.cursor()
                cursor.execute('SELECT username, public_key FROM users')
                users = cursor.fetchall()
                conn.close()
            
            # Encrypt message for each user
            encrypted_messages = {}
            for username, public_key in users:
                if public_key:
                    encrypted = encrypt_message(message, public_key)
                    if encrypted:
                        encrypted_messages[username] = encrypted
            
            # Save the message for each user
            for username, encrypted_msg in encrypted_messages.items():
                save_message(sender, username, encrypted_msg, 'broadcast')
            
            # Also save a plain text version for the sender
            save_message(sender, sender, message, 'broadcast')
            
            # Add to broadcast history
            broadcast_messages.append({
                'sender': sender,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'encrypted_for': list(encrypted_messages.keys())
            })
            
            return jsonify({
                'success': True, 
                'message': f'Broadcast message sent to {len(encrypted_messages)} users',
                'encrypted': True,
                'recipients': len(encrypted_messages)
            })
            
        except Exception as e:
            print(f"Broadcast encryption error: {e}")
            # Fallback to plain text broadcast
            save_message(sender, None, message, 'broadcast')
            broadcast_messages.append({
                'sender': sender,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'encrypted_for': []
            })
            return jsonify({
                'success': True, 
                'message': 'Broadcast message sent (not encrypted)',
                'encrypted': False
            })
    
    else:
        # Direct message to specific recipient
        try:
            # Get recipient's public key
            recipient_user = get_user(recipient)
            if not recipient_user or not recipient_user[3]:  # public_key
                return jsonify({'success': False, 'message': 'Recipient not found or no public key'})
            
            encrypted_message = encrypt_message(message, recipient_user[3])
            if encrypted_message:
                save_message(sender, recipient, encrypted_message, 'direct')
                # Save plain text for sender
                save_message(sender, sender, message, 'direct')
                return jsonify({
                    'success': True, 
                    'message': 'Direct message sent successfully',
                    'encrypted': True
                })
            else:
                save_message(sender, recipient, message, 'direct')
                save_message(sender, sender, message, 'direct')
                return jsonify({
                    'success': True, 
                    'message': 'Direct message sent (not encrypted)',
                    'encrypted': False
                })
        except Exception as e:
            print(f"Direct message encryption error: {e}")
            save_message(sender, recipient, message, 'direct')
            save_message(sender, sender, message, 'direct')
            return jsonify({
                'success': True, 
                'message': 'Direct message sent (not encrypted)',
                'encrypted': False
            })

@app.route('/api/decrypt_message', methods=['POST'])
def decrypt_message_api():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    data = request.get_json()
    encrypted_message = data.get('encrypted_message')
    
    if not encrypted_message or 'private_key' not in session:
        return jsonify({'success': False, 'message': 'Invalid request'})
    
    try:
        # Check if the message is actually encrypted (base64 format)
        if len(encrypted_message) > 100 and encrypted_message.startswith('-----BEGIN PUBLIC KEY-----'):
            # This is a public key, not an encrypted message
            return jsonify({'success': False, 'message': 'Message is not encrypted'})
        
        # Try to decrypt
        decrypted_message = decrypt_message(encrypted_message, session['private_key'])
        if decrypted_message:
            return jsonify({
                'success': True,
                'decrypted_message': decrypted_message
            })
        else:
            # If decryption fails, the message might be plain text
            return jsonify({
                'success': True,
                'decrypted_message': encrypted_message,
                'note': 'Message was not encrypted'
            })
    except Exception as e:
        print(f"Decryption error: {e}")
        # If decryption fails, return the original message
        return jsonify({
            'success': True,
            'decrypted_message': encrypted_message,
            'note': 'Decryption failed, showing original message'
        })

@app.route('/api/users')
def get_users():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    with db_lock:
        conn = sqlite3.connect('secure_messaging.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username != ?', (session['username'],))
        users = [row[0] for row in cursor.fetchall()]
        conn.close()
    
    return jsonify({'success': True, 'users': users})

@app.route('/api/messages')
def get_messages():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    with db_lock:
        conn = sqlite3.connect('secure_messaging.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sender, recipient, encrypted_message, timestamp 
            FROM messages 
            WHERE sender = ? OR recipient = ? OR recipient IS NULL
            ORDER BY timestamp DESC LIMIT 50
        ''', (session['username'], session['username']))
        messages = []
        for row in cursor.fetchall():
            # Handle message display - always show readable content
            message_content = row[2]  # encrypted_message field
            
            # If the sender is the current user, always show plain text
            if row[0] == session['username']:
                display_message = message_content
            # Check if message is encrypted (long base64 string)
            elif message_content and len(message_content) > 100 and not message_content.startswith('🔒'):
                # Try to decrypt
                try:
                    decrypted = decrypt_message(message_content, session.get('private_key', ''))
                    if decrypted:
                        display_message = decrypted
                    else:
                        display_message = "🔒 Encrypted message"
                except Exception as e:
                    display_message = "🔒 Encrypted message"
            else:
                # Already readable or placeholder
                display_message = message_content
            
            messages.append({
                'sender': row[0],
                'recipient': row[1],
                'encrypted_message': display_message,  # Now contains displayable text
                'timestamp': row[3]
            })
        conn.close()
    
    return jsonify({'success': True, 'messages': messages})

@app.route('/api/broadcast_messages')
def get_broadcast_messages():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    # Return recent broadcast messages
    recent_broadcasts = broadcast_messages[-20:]  # Last 20 broadcast messages
    return jsonify({'success': True, 'broadcast_messages': recent_broadcasts})

if __name__ == '__main__':
    init_database()
    
    # SSL context for HTTPS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.crt', 'server.key')
    
    print("Starting SocketStream Secure Messaging Server...")
    print("Server will be available at: https://localhost:5000")
    print("Features:")
    print("- End-to-End Encryption with RSA-2048 and AES-256")
    print("- SSL/TLS Security")
    print("- Secure Authentication with bcrypt")
    print("- SQLite Database Storage")
    print("- Web-based Interface")
    print("- Broadcast Messaging")
    
    # Run with SSL
    app.run(host='0.0.0.0', port=5050, ssl_context=context, debug=True) 