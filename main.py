from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from wtforms import StringField, SubmitField, URLField
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from werkzeug.security import generate_password_hash
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
login_manager = LoginManager()
login_manager.init_app(app)
# CREATE DATABASE


class Base(DeclarativeBase):
    pass

db_path = os.path.join('YOUR_FILE', 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
db = SQLAlchemy(model_class=Base)
db.init_app(app)
app.config['UPLOAD_FOLDER'] = 'YOUR_FILE'


# CREATE TABLE IN DB

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(1000), nullable=False)

    def is_active(self):
        return True
    
with app.app_context():
    db.create_all()
    
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password = generate_password_hash(request.form.get('password'),method='pbkdf2:sha256',salt_length=8)
        )
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        return render_template("secrets.html",name=request.form.get('name'))

    return render_template("register.html")


@app.route('/login',methods = ["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'),)
        else:
            flash('Invalid email or password', 'error')
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
@login_required
def logout():
    return render_template("login.html")


@app.route('/download/<path:name>')
def download(name):
    return send_from_directory(
    app.config['UPLOAD_FOLDER'], name , as_attachment=True
)

if __name__ == "__main__":
    app.run(debug=True)
