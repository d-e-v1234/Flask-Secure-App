# Flask-Secure-App
This includes a simple Flask App with additional security features embedded. 
# Secure Flask Web Application

A simple Flask web application designed with a focus on core **web security best practices**.  
This project demonstrates secure handling of user input, authentication, and error responses using built-in Flask features and recommended libraries.

---

## 🔒 Implemented Security Features

### 1. Input Validation and XSS Protection
**What I did:**  
Used **Flask-WTF** forms with validators such as:
- `DataRequired()`
- `Length()`
- `Email()`

**Why it’s safer:**  
- Prevents invalid or malicious data (e.g., excessively long usernames).  
- Automatically escapes HTML input, blocking XSS attacks (like `<script>` injections).

---

### 2. Preventing SQL Injection (SQLi)
**What I did:**  
Used **Flask-SQLAlchemy (ORM)** for all database interactions instead of raw SQL queries.

**Why it’s safer:**  
- The ORM separates SQL commands from user-provided data.  
- Any injected SQL like `' OR 1=1; --` is treated as a plain string, making the attack ineffective.

---

### 3. CSRF Protection and Secure Session Management
**What I did:**  
- Enabled `CSRFProtect(app)` in Flask.  
- Added `{{ form.hidden_tag() }}` to all forms.  
- Set `SESSION_COOKIE_HTTPONLY = True` in app configuration.

**Why it’s safer:**  
- **CSRF Protection:** Ensures every form includes a unique token, stopping attackers from submitting unauthorized requests from other sites.  
- **HTTPOnly Cookies:** Prevents JavaScript from accessing session cookies, mitigating the impact of XSS.

---

### 4. Secure Error Handling
**What I did:**  
- Implemented custom error handlers with `@app.errorhandler(404)` and `@app.errorhandler(500)`.  
- Disabled debug mode (`debug=False`) in production.

**Why it’s safer:**  
- Hides sensitive system details (like file paths and stack traces).  
- Prevents attackers from gaining insight into the app’s internal structure.

---

### 5. Secure Password Storage
**What I did:**  
Used **Flask-Bcrypt** to:
- Hash passwords with `generate_password_hash()` during signup.  
- Verify passwords with `check_password_hash()` during login.

**Why it’s safer:**  
- No plain-text passwords are ever stored.  
- Bcrypt hashing is slow and salted, making brute-force attacks computationally expensive.  
- Even if the database is compromised, real passwords remain secure.

---

## ⚙️ Example Configuration
```python
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
