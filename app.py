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

# Define a path to save uploaded files
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

api_key = os.getenv("OPENAI_API_KEY")
socketio = SocketIO(app, cors_allowed_origins="*")
openai_client = OpenAI(api_key=api_key)

# Configuration for email
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "igatusjohn15@gmail.com"
app.config["MAIL_PASSWORD"] = "cxbz fymx nfim hvrr"
app.config["MAIL_DEFAULT_SENDER"] = "igatusjohn15@gmail.com"
app.config["SECURITY_PASSWORD_SALT"] = "e33f8aa37685ca765b9d5613c0e41c0b"
mail = Mail(app)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'myapp:'

Session(app)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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
        self.blood = user_data.get('blood')
        self.height = user_data.get('height')
        self.age = user_data.get('age')
        self.location = user_data.get('location')
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
            'reviews': self.reviews
        }

    def get_unread_messages(self):
        return [message for message in self.messages if not message['read']]

    def get_reviews(self):
        return self.reviews

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def _strip_static_prefix(self, avatar_path):
        if avatar_path.startswith('static/'):
            return avatar_path[len('static/'):]
        return avatar_path

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

        # Handle file upload for avatar
        avatar = request.files.get('doctorAvatar')
        if avatar:
            filename = secure_filename(avatar.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            relative_path = os.path.relpath(file_path, 'static')  # Make the path relative to 'static' folder
            avatar.save(file_path)
        else:
            relative_path = None

        # Validate form data
        if not first_name or not last_name or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
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
            "messages": []
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
                
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("register"))
        
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = None

        # Find the doctor
        doctor = doctors_collection.find_one({"email": email})
        if doctor and check_password_hash(doctor['password'], password):
            user = User(doctor)
            session['doctor_id'] = str(doctor['_id'])
            
            # Update status to online for doctors
            doctors_collection.update_one(
                {"_id": doctor["_id"]},
                {"$set": {"online": True}}
            )

        # If not found, try to find a normal user
        if not user:
            normal_user = users_collection.find_one({"email": email})
            if normal_user and check_password_hash(normal_user['password'], password):
                user = User(normal_user)
                session['user_id'] = str(normal_user['_id'])

        if user:
            login_user(user)
            if user.role == 'doctor':
                return redirect(url_for('doctors_dashboard'))
            else:
                return redirect(url_for('vitals'))
        else:
            flash('Login failed. Check your email and password.')

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
        print(f"Error: {str(e)}")
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
    print("Received form data:", data)

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

@app.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        email = request.form.get("email")
        user = users_collection.find_one({"email": email}) or doctors_collection.find_one({"email": email})
        if user:
            send_password_reset_email(user)
            flash("A password reset email has been sent.", "info")
        else:
            flash("No account associated with this email.", "error")
        return redirect(url_for("password_reset_mail_sent"))
    return render_template("recover.html")
def send_password_reset_email(user):
    token = generate_reset_token(user)
    reset_url = url_for("reset_password", token=token, _external=True)
    
    msg = Message(subject="Password Reset Request",
                  recipients=[user['email']],
                  body=f"To reset your password, visit the following link: {reset_url}\n\n"
                       "If you did not make this request, please ignore this email.")
    
    try:
        mail.send(msg)
        print(f"Sent email to {user['email']}")
    except Exception as e:
        print(f"Failed to send email: {e}")
def generate_reset_token(user):
    return serializer.dumps(user['email'], salt=app.config["SECURITY_PASSWORD_SALT"])

def confirm_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
    except:
        return False
    return email
@app.route('/get-response', methods=['POST'])
def get_response():
    try:
        data = request.json
        user_input = data.get('input', '')
        if not user_input:
            raise ValueError("No input provided")

        # Retrieve conversation history from session
        conversation_history = session.get('conversation_history', [])

        # Append the new user input to the conversation history
        conversation_history.append({"role": "user", "content": user_input})

        response_text = generate_response(conversation_history)

        # Append the bot response to the conversation history
        conversation_history.append({"role": "assistant", "content": response_text})

        # Save the updated conversation history in session
        session['conversation_history'] = conversation_history

        log_user_activity(session.get('user_id'), "chat_interaction", {"user_input": user_input, "response": response_text})

        return jsonify({'response': response_text})
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
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired.", "error")
        return redirect(url_for("recover"))
    
    if request.method == "POST":
        password = request.form.get("password")
        # Update the user's password in the database
        if users_collection.find_one({"email": email}):
            users_collection.update_one({"email": email}, {"$set": {"password": password}})
        elif doctors_collection.find_one({"email": email}):
            doctors_collection.update_one({"email": email}, {"$set": {"password": password}})
        
        flash("Your password has been reset!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)
@app.route("/password_reset_mail_sent")
def password_reset_mail_sent():
    return render_template("password_reset_mail_sent.html")

@app.route("/new_password_set")
def new_password_set():
    return render_template("new_password_set.html")

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

        # Retrieve conversation history from session
        conversation_history = session.get('conversation_history', [])

        # Append the new user input to the conversation history
        conversation_history.append({"role": "user", "content": user_input})

        response = generate_response(conversation_history)

        # Append the bot response to the conversation history
        conversation_history.append({"role": "assistant", "content": response})

        # Save the updated conversation history in session
        session['conversation_history'] = conversation_history

        return jsonify({'reply': response})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_response(conversation_history):
    try:
        # Create a chat completion using the fine-tuned GPT-3.5 Turbo model
        completion = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
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

        # Extract the model's response content
        model_response = completion.choices[0].message.content.strip()

        return model_response
    except Exception as e:
        return str(e)
@app.route('/notifications')
@login_required
def notifications():
    user_id = current_user.id
    notifications = get_notifications_for_user(user_id)
    return jsonify({"notifications": notifications})

def get_notifications_for_user(user_id):
    # Implement this function to fetch notifications for the user from your database
    notifications = [
        {"message": "Your appointment is confirmed for tomorrow."},
        {"message": "You have a new message from Dr. Jane."},
        {"message": "Remember to take your medication at 9 AM."},
    ]
    return notifications


health_tips = [
    "Stay hydrated by drinking at least 8 glasses of water a day.",
    "Take regular breaks while working to stretch and move around.",
    "Include more fruits and vegetables in your diet.",
    "Get at least 7-8 hours of sleep each night.",
    "Exercise for at least 30 minutes a day."
]
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
@app.route('/messag')
def messag():
    return render_template('message.html')

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
@app.route('/')
@login_required
def vitals():
    today = datetime.today().date()
    health_tip = get_health_tip_for_day(today)
    return render_template('vitals.html', health_tip=health_tip)


def get_health_tip_for_day(date):
    random.seed(date.toordinal())
    return random.choice(health_tips)

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
        "avatar": current_user.avatar,  # Assuming you have an avatar URL stored
        "contact": current_user.contact,
    }
    
    # Fetch appointments
    appointments = appointments_collection.find({"patient_id": current_user.id})
    appointment_list = []
    for appointment_data in appointments:
        appointment = Appointment(appointment_data).to_dict()
        
        # Fetch doctor's name
        doctor = doctors_collection.find_one({"_id": ObjectId(appointment['doctor_id'])})
        if doctor:
            appointment['doctor_name'] = f"{doctor.get('first_name', '')} {doctor.get('last_name', '')}"
        else:
            appointment['doctor_name'] = "Unknown Doctor"
        
        appointment_list.append(appointment)
    
    # Fetch messages
    messages =  list(messages_collection.find({"receiver_id": current_user.id}))
    
    for message in messages:
        doctor = users_collection.find_one({"_id": ObjectId(message["sender_id"])})
        if doctor:
            message["doctor_name"] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
            message['avatar'] = f"{doctor.get('avatar', '')}"
        else:
            message["doctor_name"] = "Unknown"
    message_list = [Message(message).to_dict() for message in messages]
        # Fetch replies
    replies = list(replies_collection.find({"receiver_id": current_user.id}))
    for reply in replies:
        doctor = users_collection.find_one({"_id": ObjectId(reply["sender_id"])})
        
        if doctor:
            reply["doctor_name"] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
            
        else:
            reply["doctor_name"] = "Unknown"

    reply_list = [Reply(reply).to_dict() for reply in replies]
    return render_template('profile.html', user=user, appointments=appointment_list, messages=message_list,replies=reply_list)

@app.route("/consultations")
def consultations():
    doctors_data = doctors_collection.find({})
    doctors = [Doctor(doctor).to_dict() for doctor in doctors_data]

    return render_template("consultations.html", doctors=doctors)



@app.route("/successful_register")
def successful_register():
    return render_template("successful_register.html")


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

        print(f"Appointment: {appointment}, Patient ID: {patient_id}")

    for message in messages:
        patient = users_collection.find_one({"_id": ObjectId(message["sender_id"])})
        if patient:
            message["patient_name"] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}"
        else:
            message["patient_name"] = "Unknown"
        print(f"Message: {message}")

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
