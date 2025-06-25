
from flask import Flask, request, jsonify, send_file
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo.errors import ServerSelectionTimeoutError  
import os
import uuid
import datetime
import smtplib
from email.mime.text import MIMEText
import mimetypes

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/aits'
app.config['JWT_SECRET_KEY'] = 'fb3e956cd537c3ffaacd57cbd25c13702a0633d3c05da671313f0556e959f83d'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pptx', 'docx', 'xlsx'}
app.config['EMAIL_SENDER'] = 'sabeelsyed19121@gmail.com'
app.config['EMAIL_PASSWORD'] = 'tcnr qalt lybc hwlv'
app.config['BASE_URL'] = 'http://localhost:5000'

try:
    mongo = PyMongo(app)
    print("MongoDB connected successfully")
except ServerSelectionTimeoutError as e:
    print(f"MongoDB connection failed: {e}")
    exit(1)

jwt = JWTManager(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the File Sharing System'}), 200

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def send_verification_email(email, token):
    msg = MIMEText(f'Verify your email: {app.config["BASE_URL"]}/verify-email/{token}')
    msg['Subject'] = 'Email Verification'
    msg['From'] = app.config['EMAIL_SENDER']
    msg['To'] = email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.set_debuglevel(1)
        server.login(app.config['EMAIL_SENDER'], app.config['EMAIL_PASSWORD'])
        server.send_message(msg)
        
@app.route('/ops/login', methods=['POST'])
def ops_login():
    data = request.get_json()
    user = mongo.db.users.find_one({'email': data['email'], 'role': 'ops'})
    if user and check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({'access_token': access_token, 'message': 'success'}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/ops/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': current_user, 'role': 'ops'})
    if not user:
        return jsonify({'message': 'Unauthorized'}), 403
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        file.save(file_path)
        mongo.db.files.insert_one({
            '_id': file_id,
            'filename': filename,
            'uploaded_by': current_user,
            'upload_date': datetime.datetime.utcnow()
        })
        return jsonify({'message': 'File uploaded successfully', 'file_id': file_id}), 201
    return jsonify({'message': 'Invalid file type'}), 400

@app.route('/client/signup', methods=['POST'])
def client_signup():
    data = request.get_json()
    if mongo.db.users.find_one({'email': data['email']}):
        return jsonify({'message': 'Email already exists'}), 400
    verification_token = str(uuid.uuid4())
    hashed_password = generate_password_hash(data['password'])
    user_id = mongo.db.users.insert_one({
        'email': data['email'],
        'password': hashed_password,
        'role': 'client',
        'verified': False,
        'verification_token': verification_token
    }).inserted_id
    encrypted_url = f"{app.config['BASE_URL']}/verify-email/{verification_token}"
    send_verification_email(data['email'], verification_token)
    return jsonify({'message': 'Please verify your email', 'encrypted_url': encrypted_url}), 201

@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    user = mongo.db.users.find_one({'verification_token': token})
    if not user:
        return jsonify({'message': 'Invalid token'}), 400
    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'verified': True, 'verification_token': None}}
    )
    return jsonify({'message': 'Email verified successfully'}), 200

@app.route('/client/login', methods=['POST'])
def client_login():
    data = request.get_json()
    user = mongo.db.users.find_one({'email': data['email'], 'role': 'client'})
    if user and check_password_hash(user['password'], data['password']) and user['verified']:
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({'access_token': access_token, 'message': 'success'}), 200
    return jsonify({'message': 'Invalid credentials or unverified email'}), 401

@app.route('/client/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': current_user, 'role': 'client'})
    if not user:
        return jsonify({'message': 'Unauthorized'}), 403
    files = mongo.db.files.find()
    file_list = [{
        'file_id': f['_id'],
        'filename': f['filename'],
        'upload_date': f['upload_date']
    } for f in files]
    return jsonify({'files': file_list, 'message': 'success'}), 200

@app.route('/client/download/<file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': current_user, 'role': 'client'})
    if not user:
        return jsonify({'message': 'Unauthorized'}), 403
    file = mongo.db.files.find_one({'_id': file_id})
    if not file:
        return jsonify({'message': 'File not found'}), 404
    download_token = str(uuid.uuid4())
    mongo.db.download_tokens.insert_one({
        '_id': download_token,
        'file_id': file_id,
        'user_id': current_user,
        'expires': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    })
    download_url = f"{app.config['BASE_URL']}/secure-download/{download_token}"
    return jsonify({'download_link': download_url, 'message': 'success'}), 200

@app.route('/secure-download/<token>', methods=['GET'])
@jwt_required()
def secure_download(token):
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': current_user, 'role': 'client'})
    if not user:
        return jsonify({'message': 'Unauthorized'}), 403
    download_token = mongo.db.download_tokens.find_one({
        '_id': token,
        'user_id': current_user,
        'expires': {'$gt': datetime.datetime.utcnow()}
    })
    if not download_token:
        return jsonify({'message': 'Invalid or expired token'}), 403
    file = mongo.db.files.find_one({'_id': download_token['file_id']})
    if not file:
        return jsonify({'message': 'File not found'}), 404
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], download_token['file_id'])
    return send_file(
        file_path,
        as_attachment=True,
        attachment_filename=file['filename'],
        mimetype=mimetypes.guess_type(file['filename'])[0]
    )

# Test Cases
def test_app():
    client = app.test_client()
    
    def test_ops_login():
        response = client.post('/ops/login', json={'email': 'ops@example.com', 'password': 'password123'})
        assert response.status_code == 401
    
    def test_upload_file():
        mongo.db.users.insert_one({'_id': 'test_ops', 'email': 'ops@test.com', 'password': generate_password_hash('password'), 'role': 'ops'})
        login_response = client.post('/ops/login', json={'email': 'ops@test.com', 'password': 'password'})
        token = login_response.json['access_token']
        with open('test.docx', 'wb') as f:
            f.write(b'Test content')
        response = client.post('/ops/upload',
            headers={'Authorization': f'Bearer {token}'},
            data={'file': (open('test.docx', 'rb'), 'test.docx')}
        )
        assert response.status_code == 201
    
    def test_client_signup():
        response = client.post('/client/signup', json={'email': 'client@test.com', 'password': 'password123'})
        assert response.status_code == 201
        assert 'encrypted_url' in response.json
    
    def test_email_verify():
        user = mongo.db.users.insert_one({'email': 'verify@test.com', 'password': 'hashed', 'role': 'client', 'verified': False, 'verification_token': 'test_token'})
        response = client.get('/verify-email/test_token')
        assert response.status_code == 200
    
    def test_client_login():
        mongo.db.users.insert_one({'email': 'client@test.com', 'password': generate_password_hash('password'), 'role': 'client', 'verified': True})
        response = client.post('/client/login', json={'email': 'client@test.com', 'password': 'password'})
        assert response.status_code == 200
    
    def test_list_files():
        mongo.db.users.insert_one({'_id': 'test_client', 'email': 'client@test.com', 'password': 'hashed', 'role': 'client', 'verified': True})
        login_response = client.post('/client/login', json={'email': 'client@test.com', 'password': 'password'})
        token = login_response.json['access_token']
        response = client.get('/client/files', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
    
    def test_download_file():
        mongo.db.users.insert_one({'_id': 'test_client', 'email': 'client@test.com', 'password': 'hashed', 'role': 'client', 'verified': True})
        mongo.db.files.insert_one({'_id': 'test_file', 'filename': 'test.docx', 'uploaded_by': 'test_ops', 'upload_date': datetime.datetime.utcnow()})
        login_response = client.post('/client/login', json={'email': 'client@test.com', 'password': 'password'})
        token = login_response.json['access_token']
        response = client.get('/client/download/test_file', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert 'download_link' in response.json

if __name__ == '__main__':
    app.run(debug=True)
