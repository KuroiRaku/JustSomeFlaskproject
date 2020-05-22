import os
from flask_bootstrap import Bootstrap
from flask import Blueprint, Flask, render_template, url_for, request, flash, current_app, redirect, session
from flask_wtf import FlaskForm
from wtforms import TextField, TextAreaField, SubmitField, SelectField, ValidationError, StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy # instantiate database object # import class

app = Flask(__name__)
bootstrap = Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:\\All of My folders\\Assignment\\Flask Project\\MusicDatabse.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SERVER_NAME']='localhost:5000'
app.config['SECRET_KEY']='123456789_ABC'
app.config['CSRF_ENABLED']= True

db = SQLAlchemy(app) # instantiate database object #interface with flask app itself







db.create_all()
