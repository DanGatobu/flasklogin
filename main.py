import psycopg2
from flask import Flask, redirect, render_template, url_for
from flask_bcrypt import Bcrypt #encrypt password
from flask_login import (UserMixin, current_user,
                         login_required, login_user, logout_user)

from flask_login.login_manager import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import INTEGER, Column, DateTime, String, create_engine
from sqlalchemy.orm import declarative_base,sessionmaker
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import ValidationError, input_required, length




app=Flask(__name__)




session=sessionmaker()

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

base=declarative_base()
app.config['SQLALCHEMY_DATABASE_URI']='postgresql+psycopg2://postgres:dannewton\
@localhost/login'
app.config['SECRET_KEY']="Dan"
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)

class User(db.Model,UserMixin):
    __tablename__='Userr'
    id=Column(INTEGER(),primary_key=True)
    username=Column(String(30),nullable=False,unique=True)
    password=Column(String(300),nullable=False,unique=True)
    
class Registerform(FlaskForm):
    username=StringField(validators=[input_required(),length(min=4,max=20)],render_kw={"placeholder":"username"})
    password=PasswordField(validators=[input_required(),length(min=4,max=20)],render_kw={"placeholder":"password"})
    submit=SubmitField("Register")
    
    
    def validate_username(self,username):
        existing_user_username=User.query.filter_by(username=username.data).first()
        
        if existing_user_username:
            raise ValidationError("That user name already exists")
        
class Loginform(FlaskForm):
    username=StringField(validators=[input_required(),length(min=4,max=20)],render_kw={"placeholder":"username"})
    password=PasswordField(validators=[input_required(),length(min=4,max=20)],render_kw={"placeholder":"username"})
    submit=SubmitField("Login")


@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/register',methods=['GET','POST'])
def register():
    form=Registerform()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user=User(username=form.username.data,password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html',form=form)


@app.route('/login',methods=['GET','POST'])
def login():
    form=Loginform()
    
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    
    return render_template('login.html',form=form)




@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__=='__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

