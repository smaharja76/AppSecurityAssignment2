from flask import Flask
from flask_wtf import FlaskForm
from flask import flash, url_for, redirect, render_template, request, escape
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

#csrf = CSRFProtect()
app = Flask(__name__)
#app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect()
csrf.init_app(app)

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appdb.db'
db = SQLAlchemy(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config['WTF_CSRF_CHECK_DEFAULT'] =False
#keep track of registered users

currentUser = ''

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False, nullable=False)
    phone = db.Column(db.String(10), nullable=True)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    words = db.Column(db.String(100), nullable=False)
    result = db.Column(db.String(200))

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    login = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    logout = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    
db.create_all()

class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=50, message=(u'username must be between 4 and 25 chars long')), validators.DataRequired()], id='uname')
    password = PasswordField('Password', [validators.Length(min=4, max=25), validators.DataRequired()], id='pword')
    twofactor = StringField('2-factor phone', [validators.Length(min=4,max=15), validators.DataRequired()], id='2fa')

class LoginForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=25, message=(u'username must be between 4 and 25 chars long')), validators.DataRequired()], id='uname')
    password = PasswordField('Password', [validators.Length(min=4, max=25), validators.DataRequired()], id='pword')
    twofactor = StringField('2-factor phone', [validators.Length(min=4,max=15), validators.DataRequired()], id='2fa')

class SpellCheckForm(FlaskForm):
    words = StringField('Enter words', [validators.Length(min=1), validators.DataRequired()], id='inputtext')

class UserQueryForm(FlaskForm):
    username = StringField('Enter username', [validators.Length(min=1), validators.DataRequired()], id='userquery')

class LoginHistoryForm(FlaskForm):
    username = StringField('Enter username', [validators.Length(min=1), validators.DataRequired()], id='userid')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        #if user in registered:
        if (db.session.query(User.id).filter_by(username=username).scalar() is not None):
            return render_template('register_fail.html')
        #registered[user] = {"password":escape(form.password.data), "phone":escape(form.twofactor.data)}
        user = User(username=username, password=generate_password_hash(form.password.data), phone=form.twofactor.data)
        db.session.add(user)
        db.session.commit()

        return render_template('register_success.html')
        #else:
         #   return "<html><h1 id='success'>Registration failure!</h1></html>"
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        username = escape(form.username.data)
        phone = escape(form.twofactor.data)
        user = db.session.query(User).filter_by(username=username, phone=phone).scalar()
        # print(user.username)
        #app.logger.info('%s user is:', user)
        if(user is not None):
            global currentUser
            currentUser = username
            if (check_password_hash(user.password, form.password.data)):
        # if (db.session.query(User.id).filter_by(username=username, password=generate_password_hash(form.password.data), phone=phone).scalar() is not None):
                record = LoginHistory(username=currentUser)
                db.session.add(record)
                db.session.commit()
                return render_template('login_success.html')
            else:
                return '<html><h1 id="result">Incorrect username or password!</h1> <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/></form></html>'
        else:
            return '<html><h1 id="result">user does not exist!</h1> <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/></form></html>'

    return render_template('login.html', form=form)


@app.route('/spell_check', methods=['GET','POST'])
def spell_check():
    global currentUser
    if(currentUser == ''):
        return '<html><h1>login first!</h1></html>'
    else:
        form = SpellCheckForm(request.form)
        if request.method == 'POST' and form.validate():
            record = History(username=currentUser, words=form.words.data, result='')
            db.session.add(record)
            db.session.commit()
            return render_template('spell_check_result.html')
        return render_template('spell_check.html', form=form)

@app.route('/history', methods=['GET','POST'])
def history():
    global currentUser
    #print("current user:" + currentUser)
    if currentUser == 'admin':
        form = UserQueryForm(request.form)
        if request.method == 'POST' and form.validate():
            history = History.query.filter_by(username=form.username.data).all()
            return render_template('history.html', len=len(history), history=history)
        return render_template('user_query.html', form=form)
    if(currentUser !='' and currentUser is not None):
        history = History.query.filter_by(username=currentUser).all()
        return render_template('history.html', len=len(history), history=history)
    else:
        return '<html><h1>Access denied</h1></html>'

@app.route('/history/query<id>', methods=['GET'])
def query_history(id):
    query = History.query.filter_by(id=id).scalar()
    #print(query)
    return render_template('query.html', query=query)

@app.route('/login_history', methods=['GET','POST'])
def login_history():
    global  currentUser
    if currentUser == 'admin':
        form = LoginHistoryForm(request.form)
        if request.method == 'POST' and form.validate():
            history = LoginHistory.query.filter_by(username=form.username.data).all()
            return render_template('login_history.html', len=len(history), history=history)
        return render_template('user_query.html', form=form)
    else:
        return '<html><h1>Access denied</h1></html>'

@app.route('/logout', methods=['GET','POST'])
def logout():
    global  currentUser
    currentUser = ''
    return '<html><h1>logged out</h1></html>'