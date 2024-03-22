from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt

app = Flask(__name__)
#databsae creat-import read all
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Online-shop.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'your_secret_key'

#creat tables User
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(80), unique=True, nullable=False)

#def creat tables 
# @app.before_first_request
def create_tables():
    db.create_all()



#token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split(" ")
            if len(auth_header) == 2:
                token = auth_header[1]
            else:
                return jsonify({'message': 'Bearer token not found'}), 401
        else:
            return jsonify({'message': 'Authorization header is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

#home
@app.route('/')
def hello():
    return 'Hello, World!'

#Get Profile
@app.route('/profile', methods=['GET'])
@token_required
#call def token this login
def profile(current_user):
    return jsonify({
        'username': current_user.username,
        'email':current_user.email,
        'role':current_user.role
        #add
    })


#register User
@app.route('/user/register', methods=['POST'])
def register():
    data = request.json
    # chek filed value Yes OR No?
    if not all(k in data and data[k] for k in ['username', 'password', 'email']):
        return jsonify({'error': 'Missing data!'}), 400
    

    username = data['username']
    password = data['password']
    email = data['email']

    # بررسی اینکه آیا کاربری با همین ایمیل یا نام کاربری وجود دارد
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'User already exists'}), 409

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash,role='customer')
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

#Login User
@app.route('/user/login', methods=['POST'])
def login():
    data = request.json

    if not all(k in data and data[k] for k in ['username', 'password']):
        return jsonify({'error': 'Missing data!'}), 400
    
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        token = jwt.encode({'username': username,'role':'User'}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(debug=True)