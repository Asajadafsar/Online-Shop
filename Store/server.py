from functools import wraps
from flask import Flask
from flask import request
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import jwt


app = Flask(__name__)
#databsae creat-import read all
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Online-shop.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'your_secret_key'

#creat tables User
class User(db.Model):
    user_id = db.Column(db.Integer,unique=True, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    registration_date = db.Column(db.Date, nullable=False)
    role = db.Column(db.String(80), nullable=False)


#creat Customer table
# # class Customer(db.Model):
#     customer_id = db.Column(db.Integer,unique=True, primary_key=True)
#     username = db.Column(db.String(50), nullable=False)
#     email = db.Column(db.String(100), nullable=False)
#     phone_number = db.Column(db.String(15), nullable=False)
#     registration_date = db.Column(db.Date, nullable=False)

# Product Browsing
class Product(db.Model):
    product_id = db.Column(db.Integer,unique=True, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.DECIMAL(10, 2), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('Category.category_id'), nullable=False)
    image = db.Column(db.String(100), nullable=False)

# Orders
class Order(db.Model):
    order_id = db.Column(db.Integer,unique=True, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.customer_id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False)
    total_amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    status = db.Column(db.String(20), nullable=False)

# Order Details
class OrderDetail(db.Model):
    order_detail_id = db.Column(db.Integer,unique=True, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.order_id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.product_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.DECIMAL(10, 2), nullable=False)

# Categories
class Category(db.Model):
    category_id = db.Column(db.Integer,unique=True, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    parent_category_id = db.Column(db.Integer, db.ForeignKey('category.category_id'))
    created_at = db.Column(db.DateTime, nullable=False)

# Payments
class Payment(db.Model):
    payment_id = db.Column(db.Integer,unique=True, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.order_id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False)

# Shipping Addresses
class ShippingAddress(db.Model):
    address_id = db.Column(db.Integer,unique=True, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.customer_id'), nullable=False)
    recipient_name = db.Column(db.String(100), nullable=False)
    address_line1 = db.Column(db.String(255), nullable=False)
    address_line2 = db.Column(db.String(255))
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), nullable=False)

# Feedback
class Feedback(db.Model):
    feedback_id = db.Column(db.Integer,unique=True, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.customer_id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.order_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    feedback_date = db.Column(db.DateTime, nullable=False)

# Create AdminLogs table
class AdminLogs(db.Model):
    __tablename__ = 'AdminLogs'  # Define the table name explicitly
    log_id = db.Column(db.Integer, unique=True, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    action_date = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)

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
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

#home
@app.route('/')
def hello():
    return 'Hello, World!'



############################
#Customer View:
#Account Management


#Get Profile
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    customer_user = User.query.get(current_user.user_id)
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role,
        'phone_number': customer_user.phone_number,
        'registration_date': customer_user.registration_date
        #add
    })

#edit Profile
@app.route('/profile/edit', methods=['PUT'])
@token_required
def edit_profile(current_user):
    data = request.json
    user_to_update = User.query.get(current_user.user_id)

    if user_to_update:
        # Update email if provided
        if 'email' in data and data['email']:
            user_to_update.email = data['email']

        # Update phone number if provided
        if 'phone_number' in data and data['phone_number']:
            user_to_update.phone_number = data['phone_number']

        # Update password if provided
        if 'password' in data and data['password']:
            user_to_update.password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        db.session.commit()
        return jsonify({'message': 'Success! Profile Updated.'}), 200
    else:
        return jsonify({'error': 'User not found'}), 404
    

#Reset Password
@app.route('/user/reset-password', methods=['PUT'])
@token_required
def reset_password(current_user):
    data = request.json

    if 'new_password' in data:
        current_user.password_hash = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        db.session.commit()
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'error': 'New password not provided'}), 400


#register User
@app.route('/user/register', methods=['POST'])
def register():
    data = request.json
    
    if not all(k in data and data[k] for k in ['username', 'password', 'email', 'phone_number']):
        return jsonify({'error': 'Missing data!'}), 400

    username = data['username']
    password = data['password']
    email = data['email']
    phone_number = data['phone_number']

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'User already exists'}), 409

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    registration_date = datetime.now().date()

    new_user = User(username=username, email=email, password_hash=password_hash, phone_number=phone_number, registration_date=registration_date, role='customer')
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
        token = jwt.encode({'user_id': user.user_id, 'role': user.role}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

############################

#Admin View:
#Customers Management-Users Management



# Create AdminLogs table
def create_adminlogs(user_id, action, ip_address):
    new_log = AdminLogs(user_id=user_id, action=action, action_date=datetime.now(), ip_address=ip_address)
    db.session.add(new_log)
    db.session.commit()

# Add Admin or Customer
@app.route('/admin/add_user', methods=['POST'])
@token_required
def add_user(current_user):
    data = request.json

    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can add users'}), 401

    if not all(k in data for k in ['username', 'password', 'email', 'phone_number', 'role']):
        return jsonify({'error': 'Missing data! Required fields: username, password, email, phone_number, role'}), 400

    username = data['username']
    password = data['password']
    email = data['email']
    phone_number = data['phone_number']
    role = data['role']

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'User already exists'}), 409
    
    registration_date = datetime.now().date()
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash, phone_number=phone_number, role=role, registration_date=registration_date)
    db.session.add(new_user)
    db.session.commit()

    # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'add_user', request.remote_addr)

    return jsonify({'message': 'User created successfully'}), 201

# Delete admin OR customer
@app.route('/admin/home/delete/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    if current_user.role == 'admin':
        user_to_delete = User.query.get(user_id)
        
        if user_to_delete is None:
            return jsonify({'error': 'User not found!'}), 404

        # Delete Customer if the user to delete has a 'customer' role
        if user_to_delete.role == 'customer':
            customer_to_delete = User.query.filter_by(user_id=user_id).first()
            
            if customer_to_delete:
                db.session.delete(customer_to_delete)

        db.session.delete(user_to_delete)
        db.session.commit()

        # Log admin action in AdminLogs table
        create_adminlogs(current_user.user_id, 'delete_user', request.remote_addr)

        return jsonify({'message': 'User deleted successfully'}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401

# Edit user information
@app.route('/admin/home/edit/<int:user_id>', methods=['POST'])
@token_required
def edit_user(current_user, user_id):
    data = request.json

    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can edit users'}), 401

    user_to_update = User.query.get(user_id)
    
    if user_to_update is None:
        return jsonify({'error': 'User not found!'}), 404

    if 'username' in data:
        user_to_update.username = data['username']
    if 'email' in data:
        user_to_update.email = data['email']
    if 'password' in data:
        user_to_update.password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    if 'phone_number' in data:
        user_to_update.phone_number = data['phone_number']
    if 'role' in data:
        user_to_update.role = data['role']

    db.session.commit()

    # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'edit_user', request.remote_addr)

    return jsonify({'message': 'User updated successfully'}), 200

# More route functions and AdminLogs implementation can be added similarly for other admin actions.


#get list customers
@app.route('/admin/home/customers', methods=['GET'])
@token_required
def get_customers(current_user):
    if current_user.role == 'admin':
        customers_info = User.query.filter_by(role='customer').all()

        customers_data = []
        for customer_info in customers_info:
            registration_date_str = customer_info.registration_date.strftime('%Y-%m-%d') if customer_info.registration_date is not None else None

            customer_dict = {
                'username': customer_info.username,
                'email': customer_info.email,
                'role': customer_info.role,
                'user_id': customer_info.user_id,
                'phone_number': customer_info.phone_number,
                'registration_date': registration_date_str
            }
            customers_data.append(customer_dict)

        return jsonify({'customers': customers_data}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401



#get List admins
@app.route('/admin/home/admins', methods=['GET'])
@token_required
def get_admins(current_user):
    if current_user.role == 'admin':
        admins_info = db.session.query(User.username, User.email, User.user_id, User.phone_number) \
            .filter(User.role == 'admin').all()

        admins_data = []
        for admin_info in admins_info:
            admin_dict = {
                'username': admin_info.username,
                'email': admin_info.email,
                'role': 'admin',
                'user_id': admin_info.user_id,
                'phone_number': admin_info.phone_number
            }
            admins_data.append(admin_dict)

        return jsonify({'admins': admins_data}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401


# Add products
@app.route('/admin/home/products/add', methods=['POST'])
@token_required
def add_product(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can add products'}), 401

    data = request.json
    name = data.get('name')
    price = data.get('price')
    description = data.get('description')
    image = data.get('image')
    category_id = data.get('category_id')

    if not all([name, price, description, image, category_id]):
        return jsonify({'error': 'Missing data! Required fields: name, price, description, image, category_id'}), 400

    new_product = Product(name=name, price=price, description=description, image=image, category_id=category_id)
    db.session.add(new_product)
    db.session.commit()

    # Retrieve the product_id after committing
    product_id = new_product.product_id

    return jsonify({'message': 'Product added successfully', 'product_id': product_id}), 201

    

#get list products
@app.route('/admin/home/products', methods=['GET'])
@token_required
def get_Product(current_user):
    if current_user.role == 'admin':
        Product_info = db.session.query(Product.name, Product.product_id, Product.price, Product.category_id, Product.description, Product.image)

        Product_data = []
        for info in Product_info:
            admin_dict = {
                'product_id': info.product_id,
                'name': info.name,
                'price': info.price,
                'category_id': info.category_id,
                'description': info.description,
                'image': info.image
            }
            Product_data.append(admin_dict)

        return jsonify({'Product': Product_data}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401


#delete product
@app.route('/admin/home/products/delete/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    if current_user.role == 'admin':
        product = Product.query.get(product_id)
        if product:
            db.session.delete(product)
            db.session.commit()
            return jsonify({'message': 'Product deleted successfully'}), 200
        else:
            return jsonify({'error': 'Product not found'}), 404
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401

# Edit product
@app.route('/admin/home/products/edit/<int:product_id>', methods=['PUT'])
@token_required
def edit_product(current_user, product_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can edit products'}), 401

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.json

    # Update product fields if present in the request data
    if 'name' in data:
        product.name = data['name']
    if 'price' in data:
        product.price = data['price']
    if 'description' in data:
        product.description = data['description']
    if 'image' in data:
        product.image = data['image']
    if 'category_id' in data:
        product.category_id = data['category_id']

    db.session.commit()

    return jsonify({'message': 'Product updated successfully'}), 200

#############



if __name__ == '__main__':
    app.run(debug=True)