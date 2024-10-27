from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'zxc123123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('restaurants', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    return render_template('index.html', login=True)

@app.route('/register', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully')
        return redirect(url_for('login'))
    return render_template('index.html', login=False)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form.get('name')
        location = request.form.get('location')

        if not name or not location:
            flash('Both fields are required!', 'danger')
        else:
            new_restaurant = Restaurant(name=name, location=location, user=current_user)
            db.session.add(new_restaurant)
            db.session.commit()
            flash('Restaurant added successfully!', 'success')

    user_restaurants = current_user.restaurants
    return render_template('profile.html', restaurants=user_restaurants)


@app.route('/delete_restaurant/<int:id>', methods=['POST'])
@login_required
def delete_restaurant(id):
    restaurant = Restaurant.query.get_or_404(id)
    if restaurant.user_id != current_user.id:
        flash('You do not have permission to delete this restaurant.')
        return redirect(url_for('profile'))

    db.session.delete(restaurant)
    db.session.commit()
    flash('Restaurant deleted successfully.')
    return redirect(url_for('profile'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! You are logged in.'

@app.route('/general')
@login_required
def general():
    return render_template('general.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


if __name__ == '__main__':
     # with app.app_context():
     #    db.create_all()
     app.run(debug=True)
