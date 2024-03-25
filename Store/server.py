from functools import wraps
from flask import Flask, request, jsonify
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
    role = db.Column(db.String(80), nullable=False)


#creat Customer table
class Customer(db.Model):
    customer_id = db.Column(db.Integer,unique=True, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    registration_date = db.Column(db.Date, nullable=False)

# Product Browsing
class Product(db.Model):
    product_id = db.Column(db.Integer,unique=True, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.DECIMAL(10, 2), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.category_id'), nullable=False)

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

#creat table Admin log
class AdminLogs(db.Model):
    log_id = db.Column(db.Integer,unique=True, primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey('User.user_id'), nullable=False)
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

#Get Profile
@app.route('/profile', methods=['GET'])
@token_required
#call def token this login
def profile(current_user):
    customer_user=Customer.query.get(current_user.user_id)
    return jsonify({
        'username': current_user.username,
        'email':current_user.email,
        'role':current_user.role,
        'phone_number':customer_user.phone_number
        #add
    })

#edit Profile
#edit password(*ejbar)
@app.route('/profile/edit', methods=['PUT'])
@token_required
def edit_profile(current_user):
    data = request.json
    username = data.get('username')
    password_hash=data.get('password')
    phone_number=data.get('phone_number')
    email=data.get('email')
    if username is not None and  password_hash is not None and phone_number is not None and email is not None:
        user_to_update = User.query.get(current_user.user_id)
        if user_to_update:
             user_to_update.username = username
             user_to_update.email = email
             user_to_update.password_hash=bcrypt.generate_password_hash(password_hash).decode('utf-8')
             db.session.commit()
             customer_to_update=Customer.query.get(current_user.user_id)
             customer_to_update.phone_number=phone_number
             customer_to_update.username=username
             customer_to_update.email=email
             db.session.commit()
             return jsonify({'message': 'sucsess Profile Update.!'}), 200
        else:
            return 'User not found'
    else :
        return jsonify({'message': 'Not send True!'}), 400
    

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
    # chek filed value Yes OR No?
    if not all(k in data and data[k] for k in ['username', 'password', 'email']):
        return jsonify({'error': 'Missing data!'}), 400
    

    username = data['username']
    password = data['password']
    email = data['email']

    # chek user mojood by email
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'User already exists'}), 409

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash,role='customer')
    db.session.add(new_user)
    db.session.commit()
    # print (new_user)
    #match user id this customer id
    new_user_id = new_user.user_id
    now = datetime.now()
    #Str to class
    formatted_date = datetime.strptime('2024-03-24 07:06:34', '%Y-%m-%d %H:%M:%S')
    #basic datetime
    formatted_date_str = formatted_date.strftime('%Y-%m-%d %H:%M:%S')
    phone_number = data.get('phone_number', None)
    new_customer = Customer(username=username, email=email, phone_number=phone_number, registration_date=formatted_date, customer_id=new_user_id)
    db.session.add(new_customer)
    db.session.commit()
    # print (new_customer)
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
        token = jwt.encode({'user_id': user.user_id,'role':'User'}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

######

#add admin
@app.route('/admin/home/add', methods=['POST'])
@token_required
def add_admin(current_user):
    if current_user.role == 'admin':
        data = request.json
        if not all(k in data and data[k] for k in ['username', 'password', 'email']):
            return jsonify({'error': 'Missing data!'}), 400

        username = data['username']
        password = data['password']
        email = data['email']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            return jsonify({'error': 'User already exists'}), 409

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=password_hash, role='admin')
        db.session.add(new_user)
        db.session.commit()

        new_user_id = new_user.user_id
        now = datetime.now()
        
        # # Logging admin action in adminlogs table
        # new_log = AdminLog(user_id=new_user_id, action='Created a new admin user', action_date=now, ip_address=request.remote_addr)
        # db.session.add(new_log)
        # db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401


#delete USers(admin OR customer)
@app.route('/admin/home/delete/<int:user_id>', methods=['DELETE'])
@token_required
def delete_admin(current_user, user_id):
    if current_user.role == 'admin':
        user_to_delete = User.query.get(user_id)

        if user_to_delete is None:
            return jsonify({'error': 'User not found!'}), 404

        if user_to_delete.role == 'customer':
            customer_to_delete = Customer.query.filter_by(user_id=user_id).first()

            if customer_to_delete:
                db.session.delete(customer_to_delete)

        db.session.delete(user_to_delete)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401


#get all Users list
@app.route('/admin/home', methods=['POST'])
@token_required
def get_users_for_admin(current_user):
    if current_user.role == 'admin':
        users = db.session.query(User.user_id, User.username, User.email, Customer.customer_id, Customer.phone_number, User.role) \
            .all()

        users_data = []
        for user in users:
            user_data = {
                'username': user.username,
                'email': user.email,
                'user_id': user.user_id,
                'customer_id': user.customer_id,
                'phone_number': user.phone_number,
                'role': user.role,
            }
            users_data.append(user_data)

        return jsonify({'users': users_data}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401



# Edit user information
@app.route('/admin/home/edit', methods=['POST'])
@token_required
def edit_user(current_user):
    if current_user.role == 'admin':
        data = request.json
        if not all(k in data and data[k] for k in ['username', 'role', 'phone_number', 'password', 'email']):
            return jsonify({'error': 'Missing data!'}), 400

        username = data['username']
        role = data['role']
        phone_number = data['phone_number']
        password = data['password']
        email = data['email']

        user = User.query.filter_by(username=username).first()
        if user is None:
            return jsonify({'error': 'User not found'}), 404

        user.role = role
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()

        customer = Customer.query.filter_by(username=username).first()
        if customer:
            customer.phone_number = phone_number
            db.session.commit()
            
            if role != 'customer':
                customer = Customer.query.filter_by(username=username).first()
                if customer:
                    db.session.delete(customer)
                    db.session.commit()

        return jsonify({'message': 'User information updated successfully'}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401



        
#get list customer
@app.route('/admin/home/customers', methods=['GET'])
@token_required
def get_customers(current_user):
    if current_user.role == 'admin':
        customers_info = db.session.query(User.username, User.email, User.user_id, Customer.customer_id, Customer.phone_number, Customer.registration_date) \
            .join(Customer, Customer.username==User.username).all()

        customers_data = []
        for customer_info in customers_info:
            customer_dict = {
                'username': customer_info.username,
                'email': customer_info.email,
                'role': 'customer',
                'user_id': customer_info.user_id,
                'customer_id': customer_info.customer_id,
                'phone_number': customer_info.phone_number,
                'registration_date': customer_info.registration_date.strftime('%Y-%m-%d')
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
        admins_info = db.session.query(User.username, User.email, User.user_id) \
            .filter(User.role == 'admin').all()

        admins_data = []
        for admin_info in admins_info:
            admin_dict = {
                'username': admin_info.username,
                'email': admin_info.email,
                'role': 'admin',
                'user_id': admin_info.user_id,
            }
            admins_data.append(admin_dict)

        return jsonify({'admins': admins_data}), 200
    else:
        return jsonify({'error': 'Unauthorized access!'}), 401


#add category


#add parent 


#############

# Browse products by category
@app.route('/products/<category>', methods=['GET'])
def browse_products(category):
    products = Product.query.filter_by(category_id=category).all()
    product_list = []
    for product in products:
        product_data = {
            'product_id': product.product_id,
            'name': product.name,
            'description': product.description,
            'price': str(product.price),
            #'image': product.image
        }
        product_list.append(product_data)
    return jsonify({'products': product_list})


# View product details
@app.route('/product/<product_id>', methods=['GET'])
def view_product(product_id):
    product = Product.query.get(product_id)
    if product:
        product_data = {
            'product_id': product.product_id,
            'name': product.name,
            'description': product.description,
            'price': str(product.price),
            #'image': product.image
        }
        return jsonify(product_data)
    else:
        return jsonify({'message': 'Product not found'}), 404


# Add product to the shopping cart
@app.route('/add-to-cart', methods=['POST'])
@token_required
def add_to_cart(current_user):
    data = request.json
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    if not product_id or not quantity:
        return jsonify({'error': 'Product ID and quantity are required'}), 400

    # Here you can implement the logic to add the product to the user's shopping cart
    # For example, you can create a new table/model to store cart items and associate them with the user

    return jsonify({'message': 'Product added to cart successfully'}), 200

# Shopping Cart
# View items added to the shopping cart
@app.route('/cart', methods=['GET'])
@token_required
def view_cart(current_user):
    # Here you can implement the logic to retrieve the items in the user's shopping cart
    # For example, fetch cart items associated with the current user from the database
    # Return the cart items in the response
    return jsonify({'message': 'Viewing shopping cart'}), 200



# Adjust quantities or remove items from the cart
@app.route('/cart/update', methods=['PUT'])
@token_required
def update_cart(current_user):
    data = request.json
    # Implement the logic to adjust quantities or remove items from the shopping cart
    # For example, update the quantity of a specific item in the cart or remove an item from the cart
    return jsonify({'message': 'Shopping cart updated'}), 200



# Proceed to checkout
@app.route('/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    # Here you can implement the logic to initiate the checkout process
    # Including entering shipping and billing information, selecting payment method, and placing the order
    return jsonify({'message': 'Proceeding to checkout'}), 200

# Checkout Process
# Enter shipping and billing information
@app.route('/checkout/shipping-billing', methods=['POST'])
@token_required
def enter_shipping_billing(current_user):
    data = request.json
    # Implement the logic to enter shipping and billing information
    # This can include storing the shipping address, billing address, and other necessary information
    return jsonify({'message': 'Shipping and billing information entered successfully'}), 200


# Select payment method
@app.route('/checkout/payment-method', methods=['POST'])
@token_required
def select_payment_method(current_user):
    data = request.json
    # Implement the logic to select the payment method
    # This can include choosing from available payment options like credit card, PayPal, etc.
    return jsonify({'message': 'Payment method selected successfully'}), 200

# Place the order
@app.route('/checkout/place-order', methods=['POST'])
@token_required
def place_order(current_user):
    data = request.json
    # Implement the logic to place the order
    # This can include finalizing the order details, generating an order confirmation, etc.
    return jsonify({'message': 'Order placed successfully'}), 200

# Order History
@app.route('/orders/history', methods=['GET'])
@token_required
def view_order_history(current_user):
    orders = Order.query.filter_by(customer_id=current_user.customer_id).all()
    order_history = []
    for order in orders:
        order_data = {
            'order_id': order.order_id,
            'order_date': order.order_date,
            'total_amount': str(order.total_amount),
            'status': order.status
        }
        order_history.append(order_data)
    return jsonify({'order_history': order_history})

# Order Tracking
@app.route('/orders/track/<order_id>', methods=['GET'])
@token_required
def track_order(current_user, order_id):
    order = Order.query.filter_by(order_id=order_id, customer_id=current_user.customer_id).first()
    if order:
        # Implementation for tracking order shipments and status updates
        # You can include information about the shipment status, estimated delivery date, etc.
        return jsonify({'message': 'Tracking order status for order ID {}'.format(order_id)})
    else:
        return jsonify({'error': 'Order not found or unauthorized access to order'}), 404

if __name__ == '__main__':
    app.run(debug=True)