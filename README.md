# Secure Chat Application

A simple, secure web-based chat application built with Flask, SQLite, and end-to-end encryption (RSA-2048 & AES-256).
<img width="1440" height="900" alt="Screenshot 2025-07-19 at 12 09 15" src="https://github.com/user-attachments/assets/b02df83f-ef9c-484b-b947-0bf99fa016f6" />
![WhatsApp Image 2025-07-19 at 12 20 39](https://github.com/user-attachments/assets/945bcbdc-af97-46be-a02f-de6387d2d651)


## Quick Start: Run Locally

1. **Clone this repository**
   ```bash
   git clone <your-repo-url>
   cd <project-directory>
   ```
2. **(Recommended) Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies**
   ```bash
   pip install flask flask-bcrypt cryptography
   ```
4. **Run the server**
   ```bash
   python simple_secure_server.py
   ```
5. **Open your browser** and go to [https://localhost:5000](https://localhost:5000) (or the port shown in the terminal)

> **Note:**
> - Python 3.8+ is recommended.
> - The server uses a self-signed SSL certificate for HTTPS. Your browser may warn you; you can safely proceed for local testing.

---

## Features
- **Direct & Broadcast Messaging**: Private and public channels
- **End-to-End Encryption**: RSA-2048 for key exchange, AES-256 for message content
- **User Authentication**: Passwords hashed with bcrypt
- **Web UI**: Modern Bootstrap 5 interface
- **SSL/TLS**: HTTPS support for secure transport
- **SQLite Database**: Lightweight, file-based storage

## Setup
1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd <project-directory>
   ```
2. **Install dependencies**
   ```bash
   pip install flask flask-bcrypt cryptography
   ```
   (You may also need: `pip install pyopenssl` for SSL support)
3. **Run the server**
   ```bash
   python simple_secure_server.py
   ```
4. **Access the app**
   Open your browser to [https://localhost:5000](https://localhost:5000)

## Security Notes
- All messages are end-to-end encrypted. Only the intended recipient can decrypt direct messages.
- Passwords are never stored in plain text; bcrypt is used for secure hashing.
- SSL/TLS is enabled by default for secure transport.

## Project Structure
- `simple_secure_server.py` — Main Flask server
- `templates/` — HTML templates
- `static/` — CSS and JS files
- `secure_messaging.db` — SQLite database (auto-created)

---

## High-Level Design (HLD)

### Architecture Overview
- **Client-Server Model:**
  - Web browser (client) communicates with Flask server (backend) over HTTPS.
  - All data is stored in a local SQLite database.
- **Main Components:**
  - **Frontend:** HTML (Bootstrap 5), JavaScript for UI and API calls.
  - **Backend:** Flask app with RESTful APIs for authentication, messaging, and user management.
  - **Database:** SQLite for persistent storage of users and messages.
  - **Security:** End-to-end encryption (RSA/AES), bcrypt password hashing, SSL/TLS for transport.

### Data Flow
1. **User Registration/Login:**
   - User submits credentials via web form.
   - Backend hashes password, generates RSA key pair, stores user in DB.
2. **Sending a Message:**
   - User enters message in UI.
   - Message is encrypted (AES, RSA) and sent to backend via API.
   - Backend stores encrypted message in DB.
3. **Receiving a Message:**
   - Client polls API for new messages.
   - Backend returns encrypted messages.
   - Client decrypts (if possible) and displays plain text.

---

## Low-Level Design (LLD)

### Backend Modules
- **simple_secure_server.py**
  - `init_database()`: Initializes SQLite tables for users and messages.
  - `register()`: Handles user registration, password hashing, key generation.
  - `login()`: Authenticates users, manages sessions.
  - `send_message()`: Encrypts and stores messages (direct/broadcast).
  - `get_messages()`: Retrieves and decrypts messages for the user.
  - `encrypt_message() / decrypt_message()`: Handles RSA/AES encryption logic.
  - `save_user()`, `save_message()`: DB helper functions.

### Frontend Modules
- **templates/simple_chat.html**
  - Bootstrap-based layout with panels for users, direct messages, and broadcast channel.
  - JavaScript functions for sending/receiving messages, updating UI.
  - Message display logic to show plain text to sender, encrypted blob to recipient if not decrypted.

### Database Tables
- **users**: id, username, password_hash, public_key, private_key, created_at
- **messages**: id, sender, recipient, encrypted_message, timestamp

### Security Details
- **Password Hashing:** bcrypt
- **Encryption:** RSA-2048 for key exchange, AES-256 for message content
- **Transport:** HTTPS (self-signed cert for local dev)

---

For any issues or questions, please open an issue or contact the maintainer. 
