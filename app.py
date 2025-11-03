import os
from flask import (
    Flask, render_template_string, request, redirect, url_for, flash, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, current_user, login_required
)
from flask_wtf.csrf import CSRFProtect

# --- Configuration ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_should_be_changed')
if SECRET_KEY == 'a_very_secret_key_that_should_be_changed':
    print("WARNING: Using default SECRET_KEY. Please set a secure environment variable.")

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    items = db.relationship('Item', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    message = db.Column(db.Text, nullable=False)

# --- Forms ---

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', 
                             validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ItemForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Save Item')

class ContactForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Your Email', validators=[DataRequired(), Email()])
    phone = StringField('Your Phone (optional)', validators=[Optional(), Length(max=20)])
    message = TextAreaField('Your Message', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Submit')

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Templates (as strings for a single-file app) ---

# **** MODIFICATION 1: BASE_TEMPLATE ****
# Removed {% block content %} and replaced with {{ content | safe }}
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - Secure App</title>
    <!-- Simple styling -->
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; background-color: #f4f7f6; margin: 0; padding: 0; }
        .container { max-width: 960px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        nav { background-color: #333; padding: 10px 20px; border-radius: 8px 8px 0 0; }
        nav a { color: white; text-decoration: none; padding: 10px 15px; display: inline-block; }
        nav a:hover { background-color: #555; border-radius: 4px; }
        nav .right { float: right; }
        h1, h2 { color: #333; }
        .flash { padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .flash.success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .flash.danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .flash.info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        form { display: grid; gap: 15px; }
        form label { font-weight: bold; }
        form input[type="text"], form input[type="password"], form textarea {
            width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;
        }
        form .error { color: #d9534f; font-size: 0.9em; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-secondary { background-color: #6c757d; color: white; }
        .btn-danger { background-color: #dc3545; color: white; }
        .item-list { list-style: none; padding: 0; }
        .item { background: #fdfdfd; border: 1px solid #eee; padding: 15px; margin-bottom: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .item p { margin: 0; }
        .item-actions a { margin-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="{{ url_for('index') }}">Home (Items)</a>
            <a href="{{ url_for('contact') }}">Contact</a>
            <div class="right">
                {% if current_user.is_authenticated %}
                    <a href="{{ url_for('logout') }}">Logout ({{ current_user.username }})</a>
                {% else %}
                    <a href="{{ url_for('login') }}">Login</a>
                    <a href="{{ url_for('register') }}">Register</a>
                {% endif %}
            </div>
        </nav>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <!-- MODIFICATION 1.1: This is where child content will be injected -->
        {{ content | safe }}
        
    </div>
</body>
</html>
"""

# **** MODIFICATION 2: All child templates ****
# Removed {% extends 'base.html' %}, {% block content %}, and {% endblock %}

INDEX_TEMPLATE = """
<h1>Your Items</h1>
<a href="{{ url_for('add_item') }}" class="btn btn-primary" style="margin-bottom: 20px;">Add New Item</a>
{% if items %}
    <ul class="item-list">
        {% for item in items %}
            <li class="item">
                <div>
                    <strong>{{ item.name }}</strong>
                    <p>{{ item.description or 'No description' }}</p>
                </div>
                <div class="item-actions">
                    <a href="{{ url_for('edit_item', item_id=item.id) }}" class="btn btn-secondary">Edit</a>
                    <a href="{{ url_for('delete_item', item_id=item.id) }}" class="btn btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
                </div>
            </li>
        {% endfor %}
    </ul>
{% else %}
    <p>You have no items yet. Add one!</p>
{% endif %}
"""

FORM_TEMPLATE = """
<h1>{{ title }}</h1>
<form method="POST" action="">
    <!-- Task 3: CSRF Protection - This hidden tag is crucial -->
    {{ form.hidden_tag() }}
    
    {% for field in form if field.widget.input_type != 'hidden' and field.widget.input_type != 'submit' %}
        <div>
            {{ field.label }}
            {{ field() }}
            {% if field.errors %}
                {% for error in field.errors %}
                    <span class="error">{{ error }}</span>
                {% endfor %}
            {% endif %}
        </div>
    {% endfor %}
    
    {{ form.submit(class='btn btn-primary') }}
</form>
"""

ERROR_404_TEMPLATE = """
<h1>404 - Page Not Found</h1>
<p>Sorry, the page you are looking for does not exist.</p>
<!-- Task 4: Note that no sensitive debug info is shown -->
<a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
"""

ERROR_500_TEMPLATE = """
<h1>500 - Internal Server Error</h1>
<p>Sorry, something went wrong on our end. We are looking into it.</p>
<!-- Task 4: No stack trace or database info is exposed -->
<a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
"""

# --- Routes (Views) ---

# **** MODIFICATION 3: All routes updated ****
# Now render content first, then render the base template with content injected.

@app.route('/')
@login_required
def index():
    items = Item.query.filter_by(user_id=current_user.id).all()
    page_title = 'Home'
    content = render_template_string(INDEX_TEMPLATE, title=page_title, items=items)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    page_title = 'Register'
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    
    content = render_template_string(FORM_TEMPLATE, title=page_title, form=form)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    page_title = 'Login'
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            
    content = render_template_string(FORM_TEMPLATE, title=page_title, form=form)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    page_title = 'Contact Us'
    if form.validate_on_submit():
        contact_entry = Contact(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            message=form.message.data
        )
        db.session.add(contact_entry)
        db.session.commit()
        flash('Thank you for your message. We will get back to you soon!', 'success')
        return redirect(url_for('contact'))
        
    content = render_template_string(FORM_TEMPLATE, title=page_title, form=form)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = ItemForm()
    page_title = 'Add New Item'
    if form.validate_on_submit():
        item = Item(name=form.name.data, description=form.description.data, author=current_user)
        db.session.add(item)
        db.session.commit()
        flash('Your item has been created!', 'success')
        return redirect(url_for('index'))
    
    content = render_template_string(FORM_TEMPLATE, title=page_title, form=form)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content)

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.author != current_user:
        flash('You do not have permission to edit this item.', 'danger')
        return redirect(url_for('index'))
    
    form = ItemForm()
    page_title = 'Edit Item'
    if form.validate_on_submit():
        item.name = form.name.data
        item.description = form.description.data
        db.session.commit()
        flash('Your item has been updated!', 'success')
        return redirect(url_for('index'))
    elif request.method == 'GET':
        form.name.data = item.name
        form.description.data = item.description
        
    content = render_template_string(FORM_TEMPLATE, title=page_title, form=form)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content)

@app.route('/delete_item/<int:item_id>', methods=['POST', 'GET'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.author != current_user:
        flash('You do not have permission to delete this item.', 'danger')
        return redirect(url_for('index'))
    
    db.session.delete(item)
    db.session.commit()
    flash('Your item has been deleted!', 'success')
    return redirect(url_for('index'))

# --- Error Handlers ---

# **** MODIFICATION 4: Error handlers updated ****
# This now prevents the "error inside an error" problem.

@app.errorhandler(404)
def not_found_error(error):
    page_title = 'Not Found'
    content = render_template_string(ERROR_404_TEMPLATE)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content), 404

@app.errorhandler(500)
def internal_error(error):
    print(f"500 Error: {error}") 
    db.session.rollback()
    page_title = 'Server Error'
    content = render_template_string(ERROR_500_TEMPLATE)
    return render_template_string(BASE_TEMPLATE, title=page_title, content=content), 500

# --- App Runner ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=False, port=5001)

