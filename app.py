from flask import Flask, render_template, request, session, redirect, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Email, Length
import ctypes
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'

db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'fgfghjghghfgfggg'
app.secret_key = 'DSADSAFDET$%TE%dffgfdgfdg6767$@$$^%'
Bootstrap(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    twofa = db.Column(db.String(15))
    datecreated = db.Column(db.DateTime, default=datetime.now)

class LoginForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired('Incorrect'), Length(min=4, max=15)])
    pword = PasswordField('password', validators=[InputRequired('Incorrect'), Length(min=8, max=80)])
    twofa = StringField('twofa', validators=[InputRequired('Two-factor failure'), Length(min=10, max=15)], id='2fa')


#    remember = BooleanField('remember me')


def validate_uname(self, uname):
    user_object = session['user']
    if user_object:
        raise ValidationError("Username already exists. Select a different username")
#    if user_object == User.query.filter_by(username=username).first()
#        raise ValidationError("Username already exists. Select a different username")

class RegisterForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired(message='Username incorrect'), Length(min=4, max=15)])
    pword = PasswordField('password', validators=[InputRequired(message='Password incorrect'), Length(min=8, max=80)])
    twofa = StringField('twofa', validators=[InputRequired('Two-factor failure'), Length(min=10, max=15)], id='2fa')

class SpellCheckForm(FlaskForm):
    inputtext = StringField('SpellCheck', validators=[InputRequired(message='Check Spelling'), Length(min=4, max=15)])


@app.route('/', methods=['GET', 'POST'])
def index():

    return redirect(url_for('register'))

@app.route('/history', methods=['GET', 'POST'])
def history():
    if 'user' in session:
        queries = User.query.filter_by(username=request.form['uname']).all()

    return redirect(url_for('login'))



# User registration: /your/webroot/register
@app.route('/register', methods=['GET', 'POST'])
def register():
    request_form = RegisterForm()

    if request.method == 'POST' and request_form.validate():
        session['user'] = request.form['uname']
        session['password'] = request.form['pword']
        session['twofa'] = request.form['twofa']

        new_user = User(username=request.form['uname'], password=request.form['pword'], twofa=request.form['twofa'])
        db.session.add(new_user)
        db.session.commit()

        # form.validate_on_submit():
        success = "success"
        return '<div id="success">Success Proceed to Login page<a href="/login">Login</a></div>'

    # else:
    # return '<div id="success">Failure return to Registration page<a href="/register">Re-register</a></div>'
    success ="failure"
    return render_template('register.html', request_form=request_form)


# User login: /your/webroot/login
@app.route('/login', methods=['GET', 'POST'])
def login():

    login_form = LoginForm()

    # if form.validate_on_submit():
    if 'user' in session:
        if request.method == 'POST' and login_form.validate() and session['user'] == login_form.uname.data and session['password'] == login_form.pword.data and session['twofa'] == login_form.twofa.data:

            session['user'] = request.form['uname']
            result = "success"
            # return '<div id="request">success Proceed to Spell Check page<a href="/spell_check">Spell Check</a></div>'

            return redirect(url_for('spell_check'))
            # return '<h1>The username is {}. The password is {}. 2fa is {} {} {} {}'.format(login_form.uname.data,
            #                                                                                login_form.pword.data,
            #                                                                                login_form.twofa.data,
            #                                                                                session['user'],
            #                                                                                session['password'],
            #                                                                                session['twofa'])
            #                                                                                # request.request_form.uname.data,
            #                                                                                # pwtemp,
            #                                                                                # twofatemp)
        result = "failure"
    # return '<div id="result">failure</div>'
    return render_template('login.html', login_form=login_form)


@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']


@app.route('/getsession')
def getsession():
    if 'user' in session:
        return session['user']

    return 'Not logged in'


@app.route('/dropsession')
def dropsession():
    session.pop('user', None)
    return 'Dropped!'


# Result retrieval: /your/webroot/spell_check
@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if g.user:
        form = SpellCheckForm()

        if request.method == 'POST' and form.validate():
            return '<div id="success">success</div>'
            inputTextString = login_form.inputtext.data
            checkspell = ctypes.cdll('a.o')
            checkspell.argtypes(ctypes.c_char_p)
            misspelledString = checkspell.check_words(inputTextString)
            return '<h1 id="misspelled">Misspelled words are {}.'.format(misspelledString)

        return render_template('spell_check.html', form=form)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
