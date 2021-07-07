from flask import Flask, render_template, redirect, request, url_for
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

from config import PORT

app = Flask(__name__)

app.config.from_object("config")

Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(31), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(70), unique=True)
    description = db.Column(db.String(100))

    def __init__(self, name, description):
        self.name = name
        self.description = description


class Component(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(70), unique=True)
    description = db.Column(db.String(100))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    quantity = db.Column(db.Integer)

    def __init__(self, name, description, category_id, quantity):
        self.name = name
        self.description = description
        self.category_id = category_id
        self.quantity = quantity


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    component_id = db.Column(db.Integer, db.ForeignKey('component.id'))
    is_approved = db.Column(db.String(1))
    quantity = db.Column(db.Integer)
    operation = db.Column(db.String(1))

    def __init__(self, user_id, component_id, is_approved, quantity, operation):
        self.user_id = user_id
        self.component_id = component_id
        self.is_approved = is_approved
        self.quantity = quantity
        self.operation = operation


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[
        InputRequired(),
        Length(min=4, max=15)])
    password = PasswordField('Contraseña', validators=[
        InputRequired(),
        Length(min=8, max=80)])
    remember = BooleanField('Recuérdame')


class RegisterForm(FlaskForm):
    email = StringField('Correo electrónico', validators=[
        InputRequired(),
        Email(message='Correo inválido'),
        Length(max=50)])
    username = StringField('Nombre de usuario', validators=[
        InputRequired(),
        Length(min=4, max=15)])
    password = PasswordField('Contraseña', validators=[
        InputRequired(),
        Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return '<h1>Nombre de usuario o contraseña inválidos</h1>'
        # return'<h1>' + form.username.data + '' + form.password.data + '</h1>'
    return render_template('login.html', form=form)


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>Tu usuario se ha creado exitosamente!</h1>'
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    components = Component.query.all()
    return render_template('dashboard.html', name=current_user.username, components=components)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/components/add/')
def components_add():
    return render_template('components/add.html')


@app.route('/components/addcomponent', methods=['POST', 'GET'])
def components_add_form():
    if request.method == 'POST' and request.form['save']:
        name = request.form['name']
        description = request.form['description']
        category_id = 1
        quantity = int(request.form['quantity'])
        component_exists = Component.query.filter_by(name=name)
        if not component_exists:
            return redirect(url_for('dashboard')), 404
        new_component = Component(name, description, category_id, quantity)
        new_component
        db.session.add(new_component)
        db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/components/update/<int:id>')
def components_update(id: int):
    # data=db.read(id)
    # if len(data) == 0:
    #     return redirect(url_for('usuario_index'))

    # session['update'] = id
    return render_template('components/update.html')
    # return render_template('components/update.html',data=data)


@app.route('/components/delete/<int:id>')
def components_delete():
    return render_template('components/delete.html')


if __name__ == '__main__':
    app.run(debug=True, port=PORT, host="0.0.0.0")
