import os
import zipfile
import tempfile
import threading
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from sqlalchemy import text
import fal_client
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key_here')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
jwt = JWTManager(app)

fal_client.api_key = os.environ.get('FAL_KEY')

UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'lora_trainer_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Set up logging
if not app.debug:
    file_handler = logging.FileHandler('app.log')
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    jobs = db.relationship('Job', backref='user', lazy=True)

class Job(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    status = db.Column(db.String(20), nullable=False, default='running')
    model_url = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fal_job_id = db.Column(db.String(36))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def check_fal_job_status(job_id):
    try:
        handler = fal_client.get_handler(job_id)
        status = handler.status()
        return status
    except Exception as e:
        app.logger.error(f"Error checking FAL job status: {str(e)}")
        return None

def update_job_status(job_id):
    job = Job.query.get(job_id)
    if job and job.status != 'completed':
        fal_status = check_fal_job_status(job.fal_job_id)
        if fal_status == 'completed':
            result = fal_client.get_handler(job.fal_job_id).result()
            job.status = 'completed'
            job.model_url = result['diffusers_lora_file']['url']
            db.session.commit()
            app.logger.info(f"Job {job_id} completed and updated in database")
        elif fal_status == 'failed':
            job.status = 'failed'
            db.session.commit()
            app.logger.info(f"Job {job_id} failed and updated in database")

def run_training_job(job_id, images_url, user_id):
    try:
        app.logger.info(f"Starting training job {job_id} for user {user_id}")
        app.logger.info(f"Images URL: {images_url}")
        
        handler = fal_client.submit(
            "fal-ai/flux-lora-general-training",
            arguments={
                "images_data_url": images_url
            },
        )
        app.logger.info(f"Job submitted to FAL. Handler: {handler}")
        
        # Store the FAL job ID in our database
        job = Job.query.get(job_id)
        job.fal_job_id = handler.job_id
        db.session.commit()
        
        app.logger.info(f"Job {job_id} started on FAL platform")
    except Exception as e:
        app.logger.error(f"Error in training job {job_id}: {str(e)}", exc_info=True)
        job = Job.query.get(job_id)
        job.status = 'failed'
        db.session.commit()
        app.logger.info(f"Job {job_id} marked as failed in database")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered.')
            return redirect(url_for('register'))
        new_user = User(email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    jobs = Job.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', jobs=jobs)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.id}_{filename}")
        
        # Check if file already exists
        if os.path.exists(file_path):
            return jsonify({'message': 'File already uploaded', 'filename': filename})
        
        file.save(file_path)
        app.logger.info(f"File uploaded: {file_path}")
        return jsonify({'message': 'File uploaded successfully', 'filename': filename})

@app.route('/list_files', methods=['GET'])
@login_required
def list_files():
    user_files = [f.split('_', 1)[1] for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.startswith(f"{current_user.id}_")]
    return jsonify({'files': user_files})

@app.route('/train', methods=['POST'])
@login_required
def train():
    try:
        user_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.startswith(f"{current_user.id}_")]
        if not user_files:
            app.logger.warning(f"No files uploaded for training for user {current_user.id}")
            return jsonify({'error': 'No files uploaded'}), 400

        app.logger.info(f"Files for training: {user_files}")

        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{current_user.id}_images.zip')
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            for file in user_files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file)
                zip_file.write(file_path, file.split('_', 1)[1])
        
        app.logger.info(f"Created zip file at {zip_path}")

        with open(zip_path, 'rb') as f:
            url = fal_client.upload(f, "application/zip")
        
        app.logger.info(f"Uploaded zip file to FAL. URL: {url}")

        job_id = str(uuid.uuid4())
        new_job = Job(id=job_id, user_id=current_user.id)
        db.session.add(new_job)
        db.session.commit()
        app.logger.info(f"Created new job with ID {job_id} for user {current_user.id}")
        
        thread = threading.Thread(target=run_training_job, args=(job_id, url, current_user.id))
        thread.start()
        app.logger.info(f"Started training thread for job {job_id}")

        for file in user_files:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file))
        os.remove(zip_path)
        app.logger.info("Removed temporary files")

        return jsonify({'job_id': job_id, 'status': 'training_started', 'file_count': len(user_files)})
    except Exception as e:
        app.logger.error(f"Error in train route: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/job_status/<job_id>', methods=['GET'])
@login_required
def job_status(job_id):
    job = Job.query.get(job_id)
    if job and job.user_id == current_user.id:
        update_job_status(job_id)
        return jsonify({'status': job.status, 'model_url': job.model_url})
    return jsonify({'status': 'not_found'}), 404

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Here you would typically send an email with reset instructions
            # For now, we'll just flash a message
            flash('Password reset instructions sent to your email.')
            return redirect(url_for('login'))
        else:
            flash('Email not found.')
    return render_template('reset_password.html')

@app.route('/run_migrations')
def run_migrations():
    try:
        with app.app_context():
            # Check if the 'fal_job_id' column exists
            result = db.engine.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='job' AND column_name='fal_job_id'"))
            if result.fetchone() is None:
                # If the column doesn't exist, add it
                db.engine.execute(text("ALTER TABLE job ADD COLUMN fal_job_id VARCHAR(36)"))
                return "Migration successful: Added fal_job_id column to job table"
            else:
                return "Migration not needed: fal_job_id column already exists"
    except Exception as e:
        return f"Error running migration: {str(e)}"

@app.route('/admin/update_job/<job_id>', methods=['POST'])
@login_required
def admin_update_job(job_id):
    if current_user.email != 'your_admin_email@example.com':  # Replace with your admin email
        return jsonify({'error': 'Unauthorized'}), 403
    update_job_status(job_id)
    return jsonify({'message': 'Job status updated'})

# API Routes
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user:
        return jsonify({"message": "User already exists"}), 400
    new_user = User(email=data['email'], password=generate_password_hash(data['password']))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/start_training', methods=['POST'])
@jwt_required()
def api_start_training():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_paid:
        return jsonify({"message": "Payment required"}), 403
    # Your training logic here
    return jsonify({"message": "Training started"}), 200

def init_db():
    with app.app_context():
        db.create_all()
        app.logger.info("Database tables created.")

# Initialize the database
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))