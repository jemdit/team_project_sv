from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'zxc123123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
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
    description = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('restaurants', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def general():
    return render_template('general.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('restaurants'))
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

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form.get('name')
        location = request.form.get('location')
        description = request.form.get('description')

        if name and location:
            new_restaurant = Restaurant(name=name, location=location, description=description, user=current_user)
            db.session.add(new_restaurant)
            db.session.commit()
            flash('Restaurant added successfully!', 'success')
        else:
            flash('Name and location are required!', 'danger')

    user_restaurants = Restaurant.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', restaurants=user_restaurants)


@app.route('/restaurants', methods=['GET'])
def restaurants():
    return render_template('restaurants.html')

@app.route('/add_restaurant', methods=['POST'])
@login_required
def add_restaurant():
    name = request.form.get('name')
    location = request.form.get('location')
    description = request.form.get('description')

    if not name or not location:
        flash('Both fields are required!', 'danger')
    else:
        new_restaurant = Restaurant(name=name, location=location, description=description, user=current_user)
        db.session.add(new_restaurant)
        db.session.commit()
        flash('Restaurant added successfully!', 'success')

    return redirect(url_for('home'))

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


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)