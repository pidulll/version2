import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here_change_this_in_production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///car_rental.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 megabytes
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(255), nullable=True)
    rentals = db.relationship('Booking', backref='renter', lazy=True)
    messages = db.relationship('ContactMessage', backref='sender', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Car(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    price_per_day = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=True)
    active = db.Column(db.Boolean, default=True)
    bookings = db.relationship('Booking', backref='car', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    car_id = db.Column(db.Integer, db.ForeignKey('car.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Confirmed')  # Confirmed, Cancelled, Completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_admin():
    return current_user.is_authenticated and current_user.is_admin

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not is_admin():
            abort(403)
        return func(*args, **kwargs)
    return decorated_view

def create_tables_and_admin():
    with app.app_context():
        db.create_all()
        # Create default admin if none exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', is_admin=True)
            admin.set_password('adminpass')
            db.session.add(admin)
            db.session.commit()

# Authentication Routes

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method=='POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not username or not email or not password or not confirm_password:
            flash('Please fill all fields.', 'danger')
            return render_template('register.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. You can log in now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method=='POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method=='POST':
        email = request.form.get('email').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            # For demo, no real email sending
            flash('Password reset instructions sent to your email (demo).', 'info')
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

# User-Side Pages

@app.route('/')
def home():
    cars = Car.query.filter_by(active=True).all()
    return render_template('home.html', cars=cars)

@app.route('/car/<int:car_id>')
def car_details(car_id):
    car = Car.query.get_or_404(car_id)
    if not car.active and not is_admin():
        abort(404)
    return render_template('car_details.html', car=car)

@app.route('/booking/<int:car_id>', methods=['GET','POST'])
@login_required
def booking(car_id):
    car = Car.query.get_or_404(car_id)
    if not car.active:
        flash('Car not available for booking.', 'warning')
        return redirect(url_for('home'))
    if request.method == 'POST':
        try:
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            if start_date < date.today():
                flash('Start date cannot be in the past.', 'danger')
                return render_template('booking.html', car=car)
            if end_date < start_date:
                flash('End date cannot be before start date.', 'danger')
                return render_template('booking.html', car=car)
        except Exception:
            flash('Invalid date format.', 'danger')
            return render_template('booking.html', car=car)
        # Check overlapping bookings
        overlapping = Booking.query.filter(
            Booking.car_id == car.id,
            Booking.status == 'Confirmed',
            Booking.end_date >= start_date,
            Booking.start_date <= end_date
        ).first()
        if overlapping:
            flash('Car is already booked for selected dates.', 'danger')
            return render_template('booking.html', car=car)
        days = (end_date - start_date).days + 1
        total_price = days * car.price_per_day
        booking = Booking(
            user_id = current_user.id,
            car_id = car.id,
            start_date = start_date,
            end_date = end_date,
            total_price = total_price,
            status = 'Confirmed'
        )
        db.session.add(booking)
        db.session.commit()
        flash(f'Booking confirmed! Total price: ₱{total_price:.2f}', 'success')
        return redirect(url_for('my_rentals'))
    return render_template('booking.html', car=car)

@app.route('/myrentals')
@login_required
def my_rentals():
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.created_at.desc()).all()
    return render_template('my_rentals.html', bookings=bookings)

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        current_pw = request.form.get('current_password')
        new_pw = request.form.get('new_password')
        confirm_pw = request.form.get('confirm_password')
        # Validate uniqueness
        if username != current_user.username:
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'danger')
                return render_template('profile.html')
        if email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'danger')
                return render_template('profile.html')
        current_user.username = username
        current_user.email = email
        if current_pw or new_pw or confirm_pw:
            if not current_pw or not new_pw or not confirm_pw:
                flash('To change password, fill all password fields.', 'danger')
                return render_template('profile.html')
            if not current_user.check_password(current_pw):
                flash('Current password is incorrect.', 'danger')
                return render_template('profile.html')
            if new_pw != confirm_pw:
                flash('New passwords do not match.', 'danger')
                return render_template('profile.html')
            current_user.set_password(new_pw)

        # Handle profile image upload
        file = request.files.get('profile_image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            current_user.profile_image = f"uploads/{filename}"

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        message_text = request.form.get('message').strip()
        if not name or not email or not message_text:
            flash('Please fill all fields.', 'danger')
            return render_template('contact.html')
        user_id = current_user.id if current_user.is_authenticated else None
        msg = ContactMessage(user_id=user_id, name=name, email=email, message=message_text)
        db.session.add(msg)
        db.session.commit()
        flash('Message sent successfully. We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

# Admin Pages

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_cars = Car.query.count()
    total_bookings = Booking.query.count()
    total_revenue = db.session.query(db.func.sum(Booking.total_price)).filter(Booking.status=='Confirmed').scalar() or 0
    recent_bookings = Booking.query.order_by(Booking.created_at.desc()).limit(5).all()
    return render_template('admin_dashboard.html',
                           total_users=total_users,
                           total_cars=total_cars,
                           total_bookings=total_bookings,
                           total_revenue=total_revenue,
                           recent_bookings=recent_bookings)

@app.route('/admin/cars', methods=['GET','POST'])
@login_required
@admin_required
def admin_cars():
    if request.method == 'POST':
        make = request.form.get('make').strip()
        model = request.form.get('model').strip()
        year = request.form.get('year')
        price_per_day = request.form.get('price_per_day')
        description = request.form.get('description').strip()
        # Handle uploaded file
        file = request.files.get('image_file')
        image_url = None
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = f"uploads/{filename}"
        else:
            image_url = request.form.get('image_url', '').strip()
        # Validation
        if not make or not model or not year or not price_per_day:
            flash('Please fill in all required fields.', 'danger')
            cars = Car.query.all()
            return render_template('admin_cars.html', cars=cars)
        try:
            year = int(year)
            price_per_day = float(price_per_day)
        except ValueError:
            flash('Year must be a number and price must be numeric.', 'danger')
            cars = Car.query.all()
            return render_template('admin_cars.html', cars=cars)
        car = Car(make=make, model=model, year=year, price_per_day=price_per_day,
                  description=description, image_url=image_url, active=True)
        db.session.add(car)
        db.session.commit()
        flash('Car added successfully.', 'success')
        return redirect(url_for('admin_cars'))
    cars = Car.query.all()
    return render_template('admin_cars.html', cars=cars)

@app.route('/admin/cars/edit/<int:car_id>', methods=['GET','POST'])
@login_required
@admin_required
def admin_cars_edit(car_id):
    car = Car.query.get_or_404(car_id)
    if request.method == 'POST':
        car.make = request.form.get('make').strip()
        car.model = request.form.get('model').strip()
        try:
            car.year = int(request.form.get('year'))
        except ValueError:
            flash('Year must be an integer.', 'danger')
            return render_template('admin_car_edit.html', car=car)
        try:
            car.price_per_day = float(request.form.get('price_per_day'))
        except ValueError:
            flash('Price must be a number.', 'danger')
            return render_template('admin_car_edit.html', car=car)
        car.description = request.form.get('description').strip()
        # Handle uploaded image file
        file = request.files.get('image_file')
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            car.image_url = f"uploads/{filename}"
        else:
            # If no new file uploaded, optionally update via image_url input
            image_url = request.form.get('image_url', '').strip()
            if image_url:
                car.image_url = image_url
        car.active = bool(request.form.get('active'))
        db.session.commit()
        flash('Car updated successfully.', 'success')
        return redirect(url_for('admin_cars'))
    return render_template('admin_car_edit.html', car=car)

@app.route('/admin/cars/delete/<int:car_id>', methods=['POST'])
@login_required
@admin_required
def admin_cars_delete(car_id):
    car = Car.query.get_or_404(car_id)
    db.session.delete(car)
    db.session.commit()
    flash('Car deleted successfully.', 'success')
    return redirect(url_for('admin_cars'))

@app.route('/admin/bookings')
@login_required
@admin_required
def admin_bookings():
    bookings = Booking.query.order_by(Booking.created_at.desc()).all()
    return render_template('admin_bookings.html', bookings=bookings)

@app.route('/admin/bookings/edit/<int:booking_id>', methods=['GET','POST'])
@login_required
@admin_required
def admin_bookings_edit(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if request.method == 'POST':
        status = request.form.get('status')
        if status not in ['Confirmed', 'Cancelled', 'Completed']:
            flash('Invalid status.', 'danger')
            return render_template('admin_booking_edit.html', booking=booking)
        booking.status = status
        db.session.commit()
        flash('Booking updated successfully.', 'success')
        return redirect(url_for('admin_bookings'))
    return render_template('admin_booking_edit.html', booking=booking)

@app.route('/admin/bookings/delete/<int:booking_id>', methods=['POST'])
@login_required
@admin_required
def admin_bookings_delete(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    flash('Booking deleted successfully.', 'success')
    return redirect(url_for('admin_bookings'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET','POST'])
@login_required
@admin_required
def admin_users_edit(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        is_admin_val = request.form.get('is_admin') == 'on'
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('admin_user_edit.html', user=user)
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('admin_user_edit.html', user=user)
        user.username = username
        user.email = email
        user.is_admin = is_admin_val
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('admin_user_edit.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_users_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    bookings = Booking.query.order_by(Booking.created_at.desc()).all()
    csv_content = "Booking ID,User,Car,Start Date,End Date,Total Price,Status,Created At\n"
    for b in bookings:
        csv_content += f"{b.id},{b.renter.username},{b.car.make} {b.car.model},{b.start_date},{b.end_date},{b.total_price},{b.status},{b.created_at}\n"
    return send_file(BytesIO(csv_content.encode()), mimetype='text/csv', as_attachment=True, download_name='bookings_report.csv')


@app.route('/admin/settings', methods=['GET','POST'])
@login_required
@admin_required
def admin_settings():
    if request.method == 'POST':
        rental_rate_key = 'default_rental_rate'
        rental_rate_value = request.form.get('default_rental_rate').strip()
        setting = Setting.query.filter_by(key=rental_rate_key).first()
        if not setting:
            setting = Setting(key=rental_rate_key, value=rental_rate_value)
            db.session.add(setting)
        else:
            setting.value = rental_rate_value
        db.session.commit()
        flash('Settings saved successfully.', 'success')
        return redirect(url_for('admin_settings'))
    rental_rate_value = Setting.query.filter_by(key='default_rental_rate').first()
    rental_rate_value = rental_rate_value.value if rental_rate_value else ''
    return render_template('admin_settings.html', default_rental_rate=rental_rate_value)

# Error handlers

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    if not os.path.exists('car_rental.db'):
        create_tables_and_admin()
    app.run(debug=True)

