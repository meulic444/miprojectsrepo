from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///telemedicine.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Database Models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'patient' or 'doctor'
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # FHIR-compliant fields
    identifier = db.Column(db.String(50), unique=True)
    gender = db.Column(db.String(20))
    birth_date = db.Column(db.Date)
    address = db.Column(db.Text)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_fhir_patient(self):
        """Convert user to FHIR Patient resource format"""
        return {
            "resourceType": "Patient",
            "id": self.id,
            "identifier": [{"value": self.identifier or self.id}],
            "name": [{
                "family": self.last_name,
                "given": [self.first_name]
            }],
            "telecom": [{"system": "email", "value": self.email}],
            "gender": self.gender or "unknown",
            "birthDate": self.birth_date.isoformat() if self.birth_date else None,
            "address": [{"text": self.address}] if self.address else []
        }

class Appointment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    patient_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled
    reason = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_appointments')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_appointments')
    
    def to_fhir_appointment(self):
        """Convert appointment to FHIR Appointment resource format"""
        return {
            "resourceType": "Appointment",
            "id": self.id,
            "status": self.status,
            "start": self.start_time.isoformat(),
            "end": self.end_time.isoformat(),
            "participant": [
                {
                    "actor": {"reference": f"Patient/{self.patient_id}"},
                    "status": "accepted"
                },
                {
                    "actor": {"reference": f"Practitioner/{self.doctor_id}"},
                    "status": "accepted"
                }
            ],
            "reasonCode": [{"text": self.reason}] if self.reason else [],
            "comment": self.notes
        }

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

# API Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['email', 'password', 'role', 'first_name', 'last_name']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    # Create new user
    user = User(
        email=data['email'],
        role=data['role'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        phone=data.get('phone'),
        identifier=f"{data['role'].upper()}-{str(uuid.uuid4())[:8]}",
        gender=data.get('gender'),
        address=data.get('address')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and user.check_password(data.get('password')):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'patient':
        appointments = Appointment.query.filter_by(patient_id=user_id).order_by(Appointment.start_time.desc()).limit(5).all()
        recent_messages = Message.query.filter_by(recipient_id=user_id).order_by(Message.timestamp.desc()).limit(5).all()
    else:  # doctor
        appointments = Appointment.query.filter_by(doctor_id=user_id).order_by(Appointment.start_time.desc()).limit(5).all()
        recent_messages = Message.query.filter_by(recipient_id=user_id).order_by(Message.timestamp.desc()).limit(5).all()
    
    return jsonify({
        'user': user.to_fhir_patient() if user.role == 'patient' else {
            'id': user.id,
            'name': f"{user.first_name} {user.last_name}",
            'role': user.role,
            'email': user.email
        },
        'appointments': [apt.to_fhir_appointment() for apt in appointments],
        'messages': [{
            'id': msg.id,
            'sender': f"{msg.sender.first_name} {msg.sender.last_name}",
            'content': msg.content[:100] + '...' if len(msg.content) > 100 else msg.content,
            'timestamp': msg.timestamp.isoformat(),
            'read': msg.read
        } for msg in recent_messages]
    })

@app.route('/api/appointments', methods=['GET'])
@jwt_required()
def get_appointments():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'patient':
        appointments = Appointment.query.filter_by(patient_id=user_id).all()
    else:
        appointments = Appointment.query.filter_by(doctor_id=user_id).all()
    
    return jsonify([apt.to_fhir_appointment() for apt in appointments])

@app.route('/api/appointments', methods=['POST'])
@jwt_required()
def book_appointment():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'patient':
        return jsonify({'error': 'Only patients can book appointments'}), 403
    
    data = request.get_json()
    
    # Get available doctor (simplified - just get first doctor)
    doctor = User.query.filter_by(role='doctor').first()
    if not doctor:
        return jsonify({'error': 'No doctors available'}), 400
    
    start_time = datetime.fromisoformat(data['start_time'])
    appointment = Appointment(
        patient_id=user_id,
        doctor_id=doctor.id,
        start_time=start_time,
        end_time=start_time + timedelta(hours=1),
        reason=data.get('reason', 'General consultation')
    )
    
    db.session.add(appointment)
    db.session.commit()
    
    return jsonify(appointment.to_fhir_appointment()), 201

@app.route('/api/patients', methods=['GET'])
@jwt_required()
def get_patients():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    # Get patients who have appointments with this doctor
    patients = db.session.query(User).join(
        Appointment, User.id == Appointment.patient_id
    ).filter(Appointment.doctor_id == user_id).distinct().all()
    
    return jsonify([patient.to_fhir_patient() for patient in patients])

@app.route('/api/messages', methods=['GET'])
@jwt_required()
def get_messages():
    user_id = get_jwt_identity()
    recipient_id = request.args.get('with')
    
    if recipient_id:
        # Get conversation between two users
        messages = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.recipient_id == recipient_id)) |
            ((Message.sender_id == recipient_id) & (Message.recipient_id == user_id))
        ).order_by(Message.timestamp).all()
    else:
        # Get all messages for user
        messages = Message.query.filter(
            (Message.sender_id == user_id) | (Message.recipient_id == user_id)
        ).order_by(Message.timestamp.desc()).all()
    
    return jsonify([{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_name': f"{msg.sender.first_name} {msg.sender.last_name}",
        'recipient_id': msg.recipient_id,
        'recipient_name': f"{msg.recipient.first_name} {msg.recipient.last_name}",
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat(),
        'read': msg.read
    } for msg in messages])

@app.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    message = Message(
        sender_id=user_id,
        recipient_id=data['recipient_id'],
        content=data['content']
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify({'message': 'Message sent successfully'}), 201

@app.route('/api/sample-data', methods=['GET'])
def get_sample_data():
    """Return sample FHIR data for demonstration"""
    sample_patient = {
        "resourceType": "Patient",
        "id": "sample-patient-1",
        "identifier": [{"value": "PATIENT-12345"}],
        "name": [{"family": "Doe", "given": ["John"]}],
        "telecom": [{"system": "email", "value": "john.doe@email.com"}],
        "gender": "male",
        "birthDate": "1985-06-15",
        "address": [{"text": "123 Main St, City, State 12345"}]
    }
    
    sample_observation = {
        "resourceType": "Observation",
        "id": "sample-obs-1",
        "status": "final",
        "code": {"text": "Blood Pressure"},
        "subject": {"reference": "Patient/sample-patient-1"},
        "valueQuantity": {"value": 120, "unit": "mmHg"},
        "component": [
            {"code": {"text": "Systolic"}, "valueQuantity": {"value": 120, "unit": "mmHg"}},
            {"code": {"text": "Diastolic"}, "valueQuantity": {"value": 80, "unit": "mmHg"}}
        ]
    }
    
    return jsonify({
        "patient": sample_patient,
        "observations": [sample_observation]
    })

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create sample users if they don't exist
    if not User.query.filter_by(email='doctor@example.com').first():
        doctor = User(
            email='doctor@example.com',
            role='doctor',
            first_name='Dr. Sarah',
            last_name='Johnson',
            identifier='DOC-001',
            gender='female'
        )
        doctor.set_password('password123')
        db.session.add(doctor)
    
    if not User.query.filter_by(email='patient@example.com').first():
        patient = User(
            email='patient@example.com',
            role='patient',
            first_name='John',
            last_name='Doe',
            identifier='PAT-001',
            gender='male',
            birth_date=datetime(1985, 6, 15).date(),
            address='123 Main St, City, State 12345'
        )
        patient.set_password('password123')
        db.session.add(patient)
    
    db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, port=5000)