from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

login_manager = LoginManager(app)
db = SQLAlchemy(app)
login_manager.login_view = 'login'
#login_manager.login_message = 'You have to login first to access this page'

#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://iilzmvldnzopop:b4d99aa43574ba8a9200fd218d1a4410c62c2f6958e16b4949fd2f77b7886a2b@ec2-18-233-83-165.compute-1.amazonaws.com:5432/d6rbl82tpnc5h2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = os.urandom(24)
app.config['DEBUG'] = True
app.config['USE_SESSION_FOR_NEXT'] = True

class User(UserMixin, db.Model):
    __tablename__= 'userlogs'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'POST':
       existing_user = User.query.filter_by(username=request.form['username']).first()
       existing_email = User.query.filter_by(email=request.form['email']).first()

       if existing_user or existing_email:
          flash('User name or email exists', 'info')
          return redirect(url_for('register'))
       else:
          username = request.form['username']
          email = request.form['email']
          password = request.form['password']
          hashed_password = generate_password_hash(password, method='sha256')

          user = User(username=username, email=email, password=hashed_password) 
          db.session.add(user)  
          db.session.commit()  

          flash('Record was successfully added', 'success')
          return redirect(url_for('login'))
  
    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()   

        if user:

            if check_password_hash(user.password, password):
                login_user(user)
                flash('You have logged in successfully!', 'success')
                
                return redirect(url_for('content'))
            else:
                    flash('The password is incorrect.', 'danger')
                    return redirect(url_for('login'))

        else:
                flash('The user does not exist!', 'info')
                return redirect(url_for('login'))

        '''if 'next' in session:
            next = session['next']

            if next is not None:
               return redirect(next)''' 
    #session['next'] = request.args.get('next')
    return render_template('login.html')    

@app.route('/')
def index():
    return render_template('index.html')   

@app.route('/content')
@login_required
def content():
    users = User.query.all()

    return render_template('content.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are now logged out!', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    