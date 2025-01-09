from flask import (
    Flask,
    render_template,
    session,
    redirect,
    request,
    url_for,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    UserMixin,
    current_user,
)
from flask_session import Session
from pymongo import MongoClient
import os
import re
from datetime import datetime,timedelta
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from openai import OpenAI
import random
from bson.objectid import ObjectId
load_dotenv()
app = Flask(__name__, static_url_path="/static", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

app.config["MONGO_URI"] = os.getenv("MONGODB_URI")
client = MongoClient(app.config["MONGO_URI"])
db = client.get_database('quantum')
# MongoDB collections
users_collection = db.users
doctors_collection = db.doctors
messages_collection = db.messages
reviews_collection = db.reviews
appointments_collection = db.appointments
favorites_collection = db.favorites
replies_collection = db.replies
user_activity_collection = db.user_activity
# Define the collection
conversations_collection = db.conversations
vitals_collection = db.vitals
# Define a path to save uploaded files
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

api_key = os.getenv("OPENAI_API_KEY")
socketio = SocketIO(app, cors_allowed_origins="*")
openai_client = OpenAI(api_key=api_key)


mail = Mail(app)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'myapp:'

Session(app)
# Allowed file extensions
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ALLOWED_DOCUMENT_EXTENSIONS = {'pdf'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_phone(phone):
    return re.match(r"^[0-9]{10,15}$", phone)
# Secret key for generating reset tokens
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
# Example user data



class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.first_name = user_data.get('first_name')
        self.last_name = user_data.get('last_name')
        self.email = user_data.get('email')
        self.password = user_data.get('password')
        self.avatar = self._strip_static_prefix(user_data.get('avatar', ''))
        self.contact = user_data.get('contact', '')
        self.role = user_data.get('role')
        self.conversation_history = user_data.get('conversation_history', [])
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': f"{self.first_name} {self.last_name}",
            'email': self.email,
            'contact': self.contact,
            'avatar': self.avatar,
        }

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id
    
    def _strip_static_prefix(self, avatar_path):
        if avatar_path.startswith('static/'):
            return avatar_path[len('static/'):]
        return avatar_path
class Doctor:
    def __init__(self, doctor_data):
        self.id = str(doctor_data['_id'])
        self.first_name = doctor_data.get('first_name', '')
        self.last_name = doctor_data.get('last_name', '')
        self.email = doctor_data.get('email', '')
        self.specialization = doctor_data.get('specialization', '')
        self.location = doctor_data.get('location', '')
        self.about = doctor_data.get('about', '')
        self.experience = doctor_data.get('experience', '')
        self.contact = doctor_data.get('contact', '')
        self.avatar = self._strip_static_prefix(doctor_data.get('avatar', ''))
        self.online = doctor_data.get('online', False)
        self.rating = doctor_data.get('rating', 0)
        self.messages = doctor_data.get('messages', [])
        self.reviews = doctor_data.get('reviews', [])
        self.medical_license = doctor_data.get('medical_license', '')
        self.medical_school_certificate = doctor_data.get('medical_school_certificate', '')
        self.nysc_certificate = doctor_data.get('nysc_certificate', '')
        self.verified = doctor_data.get('verified', False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': f"{self.first_name} {self.last_name}",
            'email': self.email,
            'specialization': self.specialization,
            'location': self.location,
            'about': self.about,
            'experience': self.experience,
            'contact': self.contact,
            'avatar': self.avatar,
            'online': self.online,
            'rating': self.rating,
            'messages': self.messages,
            'reviews': self.reviews,
            'medical_license': self.medical_license,
            'medical_school_certificate': self.medical_school_certificate,
            'nysc_certificate': self.nysc_certificate,
            'verified': self.verified
        }

    def get_unread_messages(self):
        return [message for message in self.messages if not message['read']]

    def get_reviews(self):
        return self.reviews

    @property
    def is_active(self):
        return self.verified

    @property
    def is_authenticated(self):
        return self.verified

    @property
    def is_anonymous(self):
        return False

    def _strip_static_prefix(self, avatar_path):
        if avatar_path.startswith('static/'):
            return avatar_path[len('static/'):]
        return avatar_path

class Message:
    def __init__(self, message_data):
        self.id = str(message_data['_id'])
        self.sender_id = message_data.get('sender_id')
        self.receiver_id = message_data.get('receiver_id')
        self.content = message_data.get('content')
        self.timestamp = message_data.get('timestamp')

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'content': self.content,
            'timestamp': self.timestamp
        }

class Reply:
    def __init__(self, reply_data):
        self.id = str(reply_data['_id'])
        self.message_id = reply_data.get('message_id')
        self.doctor_id = reply_data.get('doctor_id')
        self.content = reply_data.get('content')
        self.timestamp = reply_data.get('timestamp', datetime.utcnow())
    
    def to_dict(self):
        return {
            'id': self.id,
            'message_id': self.message_id,
            'doctor_id': self.doctor_id,
            'content': self.content,
            'timestamp': self.timestamp
        }

class Review:
    def __init__(self, data):
        self.id = str(data["_id"])
        self.user_id = str(data["user_id"])
        self.doctor_id = str(data["doctor_id"])
        self.rating = data["rating"]
        self.comment = data.get("comment", "")
        self.timestamp = data["timestamp"]

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'doctor_id': self.doctor_id,
            'rating': self.rating,
            'comment': self.comment,
            'timestamp': self.timestamp
        }

class Appointment:
    def __init__(self, data):
        self.id = str(data.get("_id", ObjectId()))
        self.patient_id = data.get("patient_id")
        self.doctor_id = data.get("doctor_id")
        self.date = data.get("date")
        self.time = data.get("time")
        self.status = data.get("status", "pending")

    def to_dict(self):
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "date": self.date,
            "time": self.time,
            "status": self.status
        }

@login_manager.user_loader
def load_user(user_id):
    # Check both collections for the user
    user_data = doctors_collection.find_one({"_id": ObjectId(user_id)}) or users_collection.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None
def user_list():
    users_data = users_collection.find()
    users = [User(data).to_dict() for data in users_data]
    return render_template("users.html", users=users)
@app.route('/user_list')
def user_list():
    users_data = users_collection.find()
    users = [User(data).to_dict() for data in users_data]
    return render_template("user_list.html", users=users)
@app.route('/users')
def users():
    return render_template("users.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        role = request.form.get("role", "user")
        specialization = request.form.get("specialization")
        location = request.form.get("location")
        about = request.form.get("about")
        experience = request.form.get("experience")
        contact = request.form.get("contact")
        online = False
        rating = 0

        # Validate form data
        if not first_name or not last_name or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        # Email validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address.", "danger")
            return redirect(url_for("register"))

        # Contact validation (basic phone number check)
        if not re.match(r"^\+?\d{10,15}$", contact):
            flash("Please enter a valid phone number.", "danger")
            return redirect(url_for("register"))

        # Handle file upload for avatar
        avatar = request.files.get('doctorAvatar')
        if avatar:
            if avatar.mimetype not in ['image/png', 'image/jpg', 'image/jpeg']:
                flash("Please upload a valid image file (png, jpg, jpeg) for the avatar.", "danger")
                return redirect(url_for("register"))
            filename = secure_filename(avatar.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            relative_path = os.path.relpath(file_path, 'static')  # Make the path relative to 'static' folder
            avatar.save(file_path)
        else:
            relative_path = None

        # Handle file uploads for medical documents
        medical_license = request.files.get('medical_license')
        medical_school_certificate = request.files.get('medical_school_certificate')
        nysc_certificate = request.files.get('nysc_certificate')

        def save_document(doc):
            if doc:
                if doc.mimetype != 'application/pdf':
                    flash("Please upload a valid PDF file for the medical documents.", "danger")
                    return None
                doc_filename = secure_filename(doc.filename)
                doc_path = os.path.join(app.config['UPLOAD_FOLDER'], doc_filename)
                doc_relative_path = os.path.relpath(doc_path, 'static')
                doc.save(doc_path)
                return doc_relative_path
            return None

        medical_license_path = save_document(medical_license)
        medical_school_certificate_path = save_document(medical_school_certificate)
        nysc_certificate_path = save_document(nysc_certificate)

        # If role is doctor, ensure medical documents are provided
        if role == "doctor" and (not medical_license_path or not medical_school_certificate_path or not nysc_certificate_path):
            flash("All medical documents are required for doctor registration.", "danger")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(password, method='scrypt')

        # Create user document
        user_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hashed_password,
            "role": role,
            "specialization": specialization,
            "location": location,
            "about": about,
            "experience": experience,
            "contact": contact,
            "avatar": relative_path,
            "online": online,
            "rating": rating,
            "messages": [],
            "medical_license": medical_license_path,
            "medical_school_certificate": medical_school_certificate_path,
            "nysc_certificate": nysc_certificate_path,
            "verified": False
        }
        users_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hashed_password,
            "contact": contact,
            "avatar": relative_path,
            "role": role
        }

        try:
            # Insert user into the appropriate collection
            if role == "doctor":
                doctors_collection.insert_one(user_data)
                doctors = doctors_collection.find()
                for doctor in doctors:
                    if '\\' in doctor['avatar']:
                        updated_avatar = doctor['avatar'].replace('\\', '/')
                        doctors_collection.update_one(
                            {'_id': doctor['_id']},
                            {'$set': {'avatar': updated_avatar}}
                        )
                flash("Registration successful! Your account is under review.", "success")
                return redirect(url_for("review"))

            if role == "user":
                users_collection.insert_one(users_data)
                users = users_collection.find()
                for user in users:
                    if '\\' in user['avatar']:
                        updated_avatar = user['avatar'].replace('\\', '/')
                        users_collection.update_one(
                            {'_id': user['_id']},
                            {'$set': {'avatar': updated_avatar}}
                        )
                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for("login"))

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/review")
def review():
    return render_template("review.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = None

        # Find the doctor
        doctor = doctors_collection.find_one({"email": email})
        if doctor and check_password_hash(doctor['password'], password):
            if doctor.get("verified"):  # Check if the doctor is verified
                user = User(doctor)
                session['doctor_id'] = str(doctor['_id'])

                # Update status to online for doctors
                doctors_collection.update_one(
                    {"_id": doctor["_id"]},
                    {"$set": {"online": True}}
                )
                
                flash("Login successful! Welcome, Doctor.", "success")
            else:
                flash("Your account is still under review. Please wait for verification.", "danger")
                return redirect(url_for("login"))

        # If not found, try to find a normal user
        if not user:
            normal_user = users_collection.find_one({"email": email})
            if normal_user and check_password_hash(normal_user['password'], password):
                user = User(normal_user)
                session['user_id'] = str(normal_user['_id'])
                
                flash("Login successful! Welcome.", "success")
        
        if user:
            login_user(user)
            if user.role == 'doctor':
                return redirect(url_for('doctors_dashboard'))
            else:
                return redirect(url_for('vitals'))
        else:
            flash('Login failed. Check your email and password.', "error")

    return render_template('login.html')

@app.route("/send_message", methods=["POST"])
def send_message():
    try:
        data = request.get_json()
        sender_id = data.get("sender_id")
        receiver_id = data.get("receiver_id")
        content = data.get("content")

        # Ensure all required fields are provided
        if not sender_id or not receiver_id or not content:
            return jsonify({"error": "Missing required fields"}), 400

        message_data = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "content": content,
            "timestamp": datetime.utcnow()
        }

        # Insert the message into the database
        message_id = messages_collection.insert_one(message_data).inserted_id
        return jsonify({"message": "Message sent", "message_id": str(message_id)}), 201

    except Exception as e:
        # Log the error
        
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/add_review', methods=['POST'])
@login_required
def add_review():
    doctor_id = request.form['doctor_id']
    rating = int(request.form['rating'])
    comment = request.form['comment']
    
    new_review = {
        "user_id": ObjectId(current_user.id),
        "doctor_id": ObjectId(doctor_id),
        "rating": rating,
        "comment": comment,
        "timestamp": datetime.utcnow()
    }
    reviews_collection.insert_one(new_review)
    flash("Review added!")
    return redirect(url_for('some_view'))

@app.route('/reply', methods=['POST'])
@login_required
def reply():
    data = request.form
    

    message_id = data.get('message_id')
    content = data.get('content')
    receiver_id = data.get('receiver_id')

    if not message_id or not content or not receiver_id:
        return jsonify({"error": "Message ID, receiver ID, and content are required"}), 400

    reply_data = {
        "sender_id": current_user.id,
        "receiver_id": receiver_id,
        "message_id": message_id,
        "content": content,
        "timestamp": datetime.utcnow()
    }

    replies_collection.insert_one(reply_data)

    return redirect(url_for('messages'))


@app.route('/get-response', methods=['POST'])
def get_response():
    try:
        data = request.json
        user_input = data.get('input', '')
        if not user_input:
            raise ValueError("No input provided")

        user_id = session.get('user_id')

        # Retrieve conversation history from the database
        conversation_history = conversations_collection.find_one({'user_id': user_id}, {'_id': 0, 'history': 1})
        conversation_history = conversation_history['history'] if conversation_history else []

        # Append the new user input to the conversation history
        conversation_history.append({"role": "user", "content": user_input})

        response_text = generate_response(conversation_history)

        # Append the bot response to the conversation history
        conversation_history.append({"role": "assistant", "content": response_text})

        # Update the conversation history in the database
        conversations_collection.update_one(
            {'user_id': user_id},
            {'$set': {'history': conversation_history}},
            upsert=True
        )

        log_user_activity(user_id, "chat_interaction", {"user_input": user_input, "response": response_text})

        return jsonify({'response': response_text})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500 
@app.route('/get-conversation-history', methods=['GET'])
def get_conversation_history():
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({'error': 'User not logged in'}), 401

        # Retrieve conversation history from the database
        conversation_history = conversations_collection.find_one({'user_id': user_id}, {'_id': 0, 'history': 1})
        conversation_history = conversation_history['history'] if conversation_history else []

        return jsonify({'conversation_history': conversation_history})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/weekly-active-users')
def weekly_active_users():
    end_of_day = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    start_of_week = end_of_day - timedelta(days=7)

    weekly_active_users = user_activity_collection.aggregate([
        {
            "$match": {
                "timestamp": {"$gte": start_of_week, "$lt": end_of_day}
            }
        },
        {
            "$group": {
                "_id": {
                    "day": {"$dayOfMonth": "$timestamp"},
                    "month": {"$month": "$timestamp"},
                    "year": {"$year": "$timestamp"}
                },
                "unique_users": {"$addToSet": "$user_id"}
            }
        },
        {
            "$project": {
                "date": {"$dateFromParts": {"year": "$_id.year", "month": "$_id.month", "day": "$_id.day"}},
                "unique_users_count": {"$size": "$unique_users"}
            }
        },
        {
            "$sort": {"date": 1}
        }
    ])

    data = [{"date": str(day["date"].date()), "count": day["unique_users_count"]} for day in weekly_active_users]
    return jsonify(data)
@app.route('/api/daily-active-users')
def daily_active_users():
    start_of_day = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)

    daily_active_users = user_activity_collection.aggregate([
        {
            "$match": {
                "timestamp": {"$gte": start_of_day, "$lt": end_of_day}
            }
        },
        {
            "$group": {
                "_id": "$user_id"
            }
        },
        {
            "$count": "daily_active_users"
        }
    ])

    count = list(daily_active_users)[0]['daily_active_users'] if daily_active_users else 0
    return jsonify({'count': count})

def log_user_activity(user_id, event, details=None):
    log_entry = {
        "user_id": user_id,
        "timestamp": datetime.utcnow(),
        "event": event,
        "details": details
    }
    user_activity_collection.insert_one(log_entry)
@app.route('/chatbot', methods=['POST'])
def chatbot():
    try:
        data = request.json
        user_input = data.get('message', '')

        user_id = session.get('user_id')

        # Retrieve conversation history from the database
        conversation_history = conversations_collection.find_one({'user_id': user_id}, {'_id': 0, 'history': 1})
        conversation_history = conversation_history['history'] if conversation_history else []

        # Append the new user input to the conversation history
        conversation_history.append({"role": "user", "content": user_input})

        response = generate_response(conversation_history)

        # Append the bot response to the conversation history
        conversation_history.append({"role": "assistant", "content": response})

        # Update the conversation history in the database
        conversations_collection.update_one(
            {'user_id': user_id},
            {'$set': {'history': conversation_history}},
            upsert=True
        )

        return jsonify({'reply': response})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_response(conversation_history):
    try:
        completion = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": """You are Quantum Doctor, a healthcare assistant, capable of making diagnosis based on symptoms,
                    make sure to explain diagnosis in the simplest possible way for patients to understand.
                    start by asking the patients for their name.
                    ask necessary health question about the provided medical condition to enable you make accurate diagnosis,
                    you can predict to a high degree of accuracy the potential of future occurence of an illness in days, weeks months etc after a proper understanding
                    of the underlying health pattern.
                    You were trained by a team of Machine Learning Engineers led by Engineer Igata John at QuantumLabs, 
                    a division of Quantum Innovative Tech Solutions Ltd
                    """,
                },
            ] + conversation_history
        )

        model_response = completion.choices[0].message.content.strip()
        return model_response
    except Exception as e:
        return str(e)
@app.route('/verify-doctor/<doctor_id>', methods=['POST'])
def verify_doctor(doctor_id):
    try:
        # Update the doctor document to set 'verified' to True
        doctors_collection.update_one(
            {"_id": ObjectId(doctor_id)},
            {"$set": {"verified": True}}
        )
        flash("Doctor verified successfully!", "success")
    except Exception as e:
        flash(f"An error occurred while verifying the doctor: {str(e)}", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin')
def admin_dashboard():
    doctors = list(doctors_collection.find())
    print("Doctors found:", doctors)  # Debug print
    return render_template('admin.html', doctors=doctors)


# Function to save the uploaded file
def save_file(file):
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filepath
@app.route("/doctor/<doctor_id>")
def doctor_detail(doctor_id):
    doctor_data = doctors_collection.find_one({"_id": ObjectId(doctor_id)})
    if not doctor_data:
        return "Doctor not found", 404

    doctor = Doctor(doctor_data)

    reviews_data = reviews_collection.find({"doctor_id": doctor_id})
    reviews = list(reviews_data)

    return render_template("details.html", doctor=doctor, reviews=reviews)

@app.route("/api/doctors", methods=["GET"])
def api_doctors():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    skip = (page - 1) * per_page
    doctors_data = doctors_collection.find().skip(skip).limit(per_page)
    doctors = [Doctor(doc).to_dict() for doc in doctors_data]
    total = doctors_collection.count_documents({})
    pages = (total + per_page - 1) // per_page
    
    data = {
        "doctors": doctors,
        "total": total,
        "pages": pages,
        "current_page": page,
    }
    return jsonify(data)
@app.route("/rate-doctor", methods=["POST"])
def rate_doctor():
    data = request.json
    doctor_name = data['doctor_name']
    rating = data['rating']
    doctor = doctors_collection.find_one({"name": doctor_name})
    if doctor:
        doctors_collection.update_one({"name": doctor_name}, {"$set": {"rating": rating}})
        return jsonify({"message": "Rating updated"}), 200
    return jsonify({"message": "Doctor not found"}), 404
@app.route("/get_messages/<doctor_id>", methods=["GET"])
def get_message(doctor_id):
    messages = messages_collection.find({"receiver_id": doctor_id})
    messages_list = [Message(message).to_dict() for message in messages]
    return jsonify(messages_list), 200
@app.route("/book_appointment", methods=["POST"])
def book_appointment():
    data = request.get_json()
    patient_id = data.get("patient_id")
    doctor_id = data.get("doctor_id")
    date_time_str = data.get("date")
    date_time = datetime.strptime(date_time_str, "%Y-%m-%d %H:%M")

    appointment = {
        "patient_id": patient_id,
        "doctor_id": doctor_id,
        "date": date_time.date().isoformat(),
        "time": date_time.time().isoformat(),
        "status": "pending"
    }

    result = appointments_collection.insert_one(appointment)
    return jsonify({"message": "Appointment booked successfully", "appointment_id": str(result.inserted_id)}), 201

@app.route('/', methods=['GET', 'POST'])
@login_required
def vitals():
    latest_vitals = vitals_collection.find_one({'user_id': current_user.id}, sort=[('timestamp', -1)])

    if latest_vitals is None:
        # Handle the case where there is no vitals data available
        latest_vitals = {
            'temperature': None,
            'blood_pressure': None,
            'heart_rate': None,
            'blood_oxygen': None
        }
        health_tip = "No recent vitals found to generate a health tip."
    else:
        # Get the current time and round it to the nearest hour
        now = datetime.now().replace(minute=0, second=0, microsecond=0)

        # Generate the health tip based on the latest vitals data
        health_tip = get_health_tip_for_vitals(latest_vitals, now)
    def get_status(value, normal_range, is_bp=False):
        if value is None:
            return 'No Data', 'text-muted'
        
        if is_bp:
            try:
                systolic, diastolic = map(float, value.split('/'))
                normal_systolic_range, normal_diastolic_range = normal_range
                if normal_systolic_range[0] <= systolic <= normal_systolic_range[1] and \
                   normal_diastolic_range[0] <= diastolic <= normal_diastolic_range[1]:
                    return 'Normal', 'text-success'
                else:
                    return 'Abnormal', 'text-danger'
            except (ValueError, TypeError):
                return 'Invalid Data', 'text-warning'
        else:
            try:
                value = float(value)
                if normal_range[0] <= value <= normal_range[1]:
                    return 'Normal', 'text-success'
                else:
                    return 'Abnormal', 'text-danger'
            except (ValueError, TypeError):
                return 'Invalid Data', 'text-warning'

    temperature_status, temp_color = get_status(latest_vitals['temperature'], (36.1, 37.2))
    bp_status, bp_color = get_status(latest_vitals['blood_pressure'], ((90, 120), (60, 80)), is_bp=True)
    hr_status, hr_color = get_status(latest_vitals['heart_rate'], (60, 100))
    bo_status, bo_color = get_status(latest_vitals['blood_oxygen'], (95, 100))

    return render_template('vitals.html', latest_vitals=latest_vitals,health_tip=health_tip,
                           temperature_status=temperature_status, temp_color=temp_color,
                           bp_status=bp_status, bp_color=bp_color,
                           hr_status=hr_status, hr_color=hr_color,
                           bo_status=bo_status, bo_color=bo_color)

# Dictionary to store the health tips based on user_id and timestamp to avoid regenerating too often
health_tip_cache = {}

def get_health_tip_for_vitals(latest_vitals, date_time):
    # Generate a cache key based on user_id and rounded time
    cache_key = (latest_vitals['user_id'], date_time)

    # Check if there's a cached health tip for this user and time
    if cache_key in health_tip_cache:
        return health_tip_cache[cache_key]

    # Extract individual vital signs
    heart_rate = latest_vitals.get('heart_rate')
    blood_pressure = latest_vitals.get('blood_pressure')
    temperature = latest_vitals.get('temperature')
    blood_oxygen = latest_vitals.get('blood_oxygen')

    # Create the prompt using the latest vitals
    vitals_info = f"Heart Rate: {heart_rate} bpm, " \
                  f"Blood Pressure: {blood_pressure}, " \
                  f"Body Temperature: {temperature}°F, " \
                  f"Blood Oxygen: {blood_oxygen}%"

    messages = [
        {"role": "system", "content": """You are Quantum Doctor, a healthcare assistant capable of interpreting vital signs.
                                          Make sure to extrapolate useful health insights in the simplest possible way for patients to understand. """},
        {"role": "user", "content": f"Based on the following vitals, provide a practical and actionable health tip: {vitals_info}."}
    ]

    # Request a response from the OpenAI API
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages,
        max_tokens=100,
        temperature=0.7
    )

    # Extract the health tip from the response
    health_tip = response.choices[0].message.content.strip()

    # Cache the generated health tip to avoid regenerating too often
    health_tip_cache[cache_key] = health_tip

    return health_tip

@app.route("/messages")
@login_required
def messages():
    if current_user.role != "doctor":
        flash("Access unauthorized.", "danger")
        return redirect(url_for("index"))

    # Fetch messages where the doctor is the receiver
    messages = list(messages_collection.find({"receiver_id": str(current_user.id)}))
    print("Fetched Messages: ", messages)  # Debug print

    # Fetch patient details for each message
    for message in messages:
        patient = users_collection.find_one({"_id": ObjectId(message["sender_id"])})
        if patient:
            message["patient_name"] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}"
            message['avatar'] = f"{patient.get('avatar', '')}"
        else:
            message["patient_name"] = "Unknown"
    print("Messages with Patient Names: ", messages)  # Debug print

    return render_template("message.html", messages=messages)

@app.route('/reviews/<doctor_id>')
@login_required
def get_reviews(doctor_id):
    doctor_id = ObjectId(doctor_id)
    reviews_data = reviews_collection.find({"doctor_id": doctor_id})
    reviews = [Review(data).to_dict() for data in reviews_data]
    return jsonify(reviews)
@app.route('/appointments')
@login_required
def get_appointments():
    user_id = ObjectId(current_user.id)
    appointments_data = appointments_collection.find({"user_id": user_id})
    appointments = [Appointment(data).to_dict() for data in appointments_data]
    return jsonify(appointments)


@app.errorhandler(401)
def unauthorized(error):
    return render_template("unauthorize.html"), 401

@app.route('/profile')
@login_required
def profile():
    user = {
        "name": f"{current_user.first_name} {current_user.last_name}",
        "email": current_user.email,
        "role": current_user.role,
        "avatar": current_user.avatar,
        "contact": current_user.contact,
    }
    
    # Fetch appointments
    appointments = appointments_collection.find({"patient_id": current_user.id})
    appointment_list = [Appointment(appointment).to_dict() for appointment in appointments]
    
    # Fetch messages
    messages = list(messages_collection.find({"receiver_id": str(current_user.id)}))
    for message in messages:
        doctor = users_collection.find_one({"_id": ObjectId(message["sender_id"])})
        if doctor:
            message["doctor_name"] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
            message['avatar'] = f"{doctor.get('avatar', '')}"
        else:
            message["doctor_name"] = "Unknown"
        print("Doctor details for message:", doctor)  # Debug print
    message_list = [Message(message).to_dict() for message in messages]
    
    # Fetch replies
    replies = list(replies_collection.find({"receiver_id": str(current_user.id)}))
    for reply in replies:
        doctor = users_collection.find_one({"_id": ObjectId(reply["sender_id"])})
        if doctor:
            reply["doctor_name"] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
        else:
            reply["doctor_name"] = "Unknown"
        print("Doctor details for reply:", doctor)  # Debug print
    reply_list = [Reply(reply).to_dict() for reply in replies]

    return render_template('profile.html', user=user, appointments=appointment_list, messages=message_list, replies=reply_list)

@app.route("/consultations")
def consultations():
    # Find only verified doctors
    doctors_data = doctors_collection.find({"verified": True})
    doctors = [Doctor(doctor).to_dict() for doctor in doctors_data]

    return render_template("consultations.html", doctors=doctors)

@app.route("/successful_register")
def successful_register():
    return render_template("successful_register.html")
@app.route('/get-vitals')
@login_required
def get_vitals():
    latest_vitals = vitals_collection.find_one(
        {"user_id": current_user.id},
        sort=[("timestamp", -1)]
    )
    
    if latest_vitals:
        vitals_data = {
            "temperature": latest_vitals.get("temperature"),
            "bloodPressure": latest_vitals.get("blood_pressure"),
            "heartRate": latest_vitals.get("heart_rate"),
            "bloodOxygen": latest_vitals.get("blood_oxygen")
        }
    else:
        vitals_data = {}

    return jsonify(vitals_data)
@app.route('/update-vitals', methods=['POST'])
@login_required
def update_vitals():
    vitals_data = request.get_json()

    # Extract the data from the request
    temperature = vitals_data.get('temperature')
    blood_pressure = vitals_data.get('bloodPressure')
    heart_rate = vitals_data.get('heartRate')
    blood_oxygen = vitals_data.get('bloodOxygen')
    
    # Create a new Vitals record
    new_vitals = {
        "user_id": current_user.id,
        "temperature": temperature,
        "blood_pressure": blood_pressure,
        "heart_rate": heart_rate,
        "blood_oxygen": blood_oxygen,
        "timestamp": datetime.utcnow()
    }
    
    # Save the new vitals to the database
    vitals_collection.insert_one(new_vitals)

    return jsonify({"status": "success", "message": "Vitals updated successfully!"})

@app.route("/diagnosis")
def diagnosis():
    return render_template("diagnosis.html")

@app.route("/doctors_dashboard")
@login_required
def doctors_dashboard():
    doctor_id = str(current_user.id)
    appointments_data = list(appointments_collection.find({"doctor_id": doctor_id}))
    messages = list(messages_collection.find({"receiver_id": doctor_id}))

    # Fetch patient details
    patient_ids = [appointment['patient_id'] for appointment in appointments_data]
    patients_data = users_collection.find({"_id": {"$in": [ObjectId(patient_id) for patient_id in patient_ids]}})
    patients = {str(patient['_id']): patient for patient in patients_data}

    # Merge patient names with appointments
    for appointment in appointments_data:
        patient_id = appointment['patient_id']
        if patient_id in patients:
            appointment['patient_name'] = f"{patients[patient_id]['first_name']} {patients[patient_id]['last_name']}"
            appointment['patient_avatar'] = patients[patient_id]['avatar']
            appointment['patient_contact'] = patients[patient_id]['contact']
        else:
            appointment['patient_name'] = "Unknown"
            appointment['patient_avatar'] = ""
            appointment['patient_contact']=""

    

    for message in messages:
        patient = users_collection.find_one({"_id": ObjectId(message["sender_id"])})
        if patient:
            message["patient_name"] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}"
        else:
            message["patient_name"] = "Unknown"
    

    return render_template("doctors_dashboard.html", appointments=appointments_data, messages=messages)
@app.route("/update_appointment_status", methods=["POST"])
@login_required
def update_appointment_status():
    appointment_id = request.form.get("appointment_id")
    new_status = request.form.get("status")
    
    try:
        appointments_collection.update_one(
            {"_id": ObjectId(appointment_id)},
            {"$set": {"status": new_status}}
        )
        flash("Appointment status updated successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for("doctors_dashboard"))

@app.route('/send_reply', methods=['POST'])
@login_required
def send_reply():
    if not current_user.role == 'doctor':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    message_id = data.get('message_id')
    content = data.get('content')

    if not message_id or not content:
        return jsonify({'success': False, 'error': 'Invalid input'}), 400

    original_message = messages_collection.find_one({'_id': ObjectId(message_id)})
    if not original_message:
        return jsonify({'success': False, 'error': 'Message not found'}), 404

    reply = {
        'sender_id': str(current_user.id),
        'receiver_id': original_message['sender_id'],
        'content': content,
        'timestamp': datetime.utcnow()
    }

    messages_collection.insert_one(reply)
    return jsonify({'success': True})
@app.route('/chat/<doctor_id>', methods=['GET'])
@login_required
def chat(doctor_id):
    doctor = doctors_collection.find_one({'_id': ObjectId(doctor_id)})
    if not doctor:
        flash('Doctor not found', 'danger')
        return redirect(url_for('dashboard'))

    # Ensure messages field exists
    if 'messages' not in doctor:
        doctor['messages'] = []

    # Retrieve messages between the logged-in user and the doctor
    messages = []
    for message in doctor['messages']:
        if message['sender_id'] == current_user.id or message['receiver_id'] == current_user.id:
            messages.append(message)

    return render_template('chat.html', doctor=doctor, messages=messages)

@socketio.on('send_message')
def handle_send_message_event(data):
    emit('receive_message', data, broadcast=True)

@app.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    user_role = current_user.role
    conversation_history = session.pop('conversation_history', [])
    
    if user_role == "doctor":
        doctors_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "online": False,
                "conversation_history": conversation_history
            }}
        )
    else:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "conversation_history": conversation_history
            }}
        )
    
    logout_user()
    
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port="5000")
