from flask import Flask, render_template, session, jsonify
from flask_nav import Nav, register_renderer
from flask_nav.elements import *

nav = Nav()

navitems = [
    View('Widgits, Inc.', 'index'),
    View('Our Mission', 'about'),
]

def with_user_session_action(items):
    return (
        items
        + [ View('Login', 'login') if not session.get('logged') else View('Logout', 'logout')]
    )

def register_element(nav, navitems):
    navitems = with_user_session_action(navitems)
    return nav.register_element('top',
        Navbar(*navitems)
    )

_render_template = render_template

def render_template(*args, **kwargs):
    register_element(nav, navitems)

    return _render_template(*args, nav=nav.elems, **kwargs)

def create_app(configfile=None):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hearingvoicesnooneelsecanhearisn\'tagoodsign,eveninthewizardingworld'
    nav.init_app(app)

    @app.route('/')
    def index():
        return render_template('login.html')

    @app.route('/about-us/')
    def about():
        return render_template('login.html')

    @app.route('/login/')
    def login():
        session['logged'] = True
        return render_template('login.html')

    @app.route('/logout/')
    def logout():
        session['logged'] = False
        return render_template('login.html')

    return app
