#import
from functools import wraps
import json
import os
import dateutil.parser
from werkzeug.utils import secure_filename
from flask_cors import CORS
from sqlalchemy import func
from decimal import Decimal
from flask import Flask,render_template
from flask import request
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import send_file
from flask_bcrypt import Bcrypt
# from migration import *
from datetime import datetime, timedelta
from flask import make_response
from sqlalchemy import or_, and_,desc, asc
from model import db, User, Product, Order, OrderDetail, Category, Payment, ShippingAddress, Feedback, AdminLogs,Notification
import uuid
import random
import jwt
from sqlalchemy.orm import joinedload , subqueryload

###############################################
url_picture="http://localhost:5000/static/home/images/"
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Online-shop.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)

with app.app_context():
    db.create_all()

bcrypt = Bcrypt(app)

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, expose_headers=['Content-Range', 'X-Total-Count'])
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'home', 'images')

# اطمینان حاصل کنید که پوشه مورد نظر وجود دارد، اگر نیست، آن را ایجاد کنید
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
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



@app.route('/', methods=['GET'])
def display_home():
    # # Get search query parameter from request URL
    # search_query = request.args.get('search_query', '')

    # # Initialize query to fetch products
    # query = Product.query

    # # Filter products by search query if provided
    # if search_query:
    #     query = query.filter(Product.name.ilike(f'%{search_query}%'))

    # # Select random 6 products with minimal information
    # random_products = query.order_by(func.random()).limit(6).all()

    # # Prepare product info
    # products_info = []
    # for product in random_products:
    #     product_info = {
    #         'name': product.name,
    #         'price': float(product.price),
    #         'image': product.image
    #     }
    #     products_info.append(product_info)

    # # Fetch parent categories
    # parent_categories = Category.query.all()
    # categories_info = [{'name': category.name} for category in parent_categories]
    # # Return JSON response
    # return jsonify({'products': products_info, 'categories': categories_info}), 200
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('home.html', products=products,categories=categories)


###############################################

#Customer View:

#search product
@app.route('/search_product')
def search_product():
    search_query = request.args.get('name', '')

    products = Product.query.filter(Product.name.ilike(f'%{search_query}%')).all()

    product_data = []
    for product in products:
        product_data.append({
            'product_id': product.product_id,
            'name': product.name,
            'description': product.description,
            'price': str(product.price),
            'category_id': product.category_id,
            'image': product.image
        })

    return jsonify(product_data)


@app.route('/profile' ,  methods=['GET'])
def view_profile():
    return render_template('profile.html')

# Get Profile
@app.route('/profiles', methods=['GET'])
@token_required
def profile(current_user):
    customer_user = User.query.get(current_user.user_id)
    return jsonify(username=current_user.username, email=current_user.email, role=current_user.role, phone_number=customer_user.phone_number, registration_date=customer_user.registration_date)


# @app.route('/profile/edit', methods=['GET'])
# def get_edit_profile():
#     # Render the HTML template for editing profile
#     return render_template('edit-profile.html')

@app.route('/profile/edit', methods=['PUT'])
@token_required
def put_edit_profile(current_user):
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




#read file register.html
@app.route('/user/register', methods=['GET'])
def get_register():
    return render_template('register.html')

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


#read file login.html
@app.route('/user/login', methods=['GET'])
def get_login():
    return render_template('login.html')


#read file about.html
@app.route('/about', methods=['GET'])
def get_about():
    return render_template('about.html')

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

#read file rest-passowrd.html
@app.route('/reset-password', methods=['GET'])
def get_restpassowrd():
    return render_template('rest-passowrd.html')


# Reset Password
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json

    if not all(k in data and data[k] for k in ['username', 'new_password']):
        return jsonify({'error': 'Missing data!'}), 400

    username = data['username']
    new_password = data['new_password']

    user = User.query.filter_by(username=username).first()

    if user:
        # Update the password
        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password_hash = password_hash
        db.session.commit()

        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'error': 'User not found'}), 404
    
# View Product Details
@app.route('/product/<int:product_id>', methods=['GET'])
def view_product_details(product_id):
    product = Product.query.get(product_id)
    if product:
        category = Category.query.get(product.category_id)
        category_name = category.name if category else 'Uncategorized'
        
        product_info = {
            'name': product.name,
            'description': product.description,
            'price': float(product.price),
            'image': product.image,
            'category': category_name
        }
        return render_template('product.html', product=product_info)
    else:
        return jsonify({'error': 'Product not found'}), 404


# Route for 404 page
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

# browsing products by category
@app.route('/products/category/<int:category_id>', methods=['GET'])
def browse_products_by_category(category_id):
    products = Product.query.filter_by(category_id=category_id).all()
    if products:
        products_info = []
        for product in products:
            products_info.append({
                'name': product.name,
                'description': product.description,
                'price': float(product.price),
                'image': product.image,
                'product_id':product.product_id
            })
        return render_template('category.html', products_info=products_info), 200
    else:
        return jsonify({'message': 'No products found in this category'}), 404


# Add Product to Shopping Cart
@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
@token_required
def add_to_cart(current_user, product_id):
    data = request.form  
    quantity = int(data.get('quantity', 1)) 
    
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    order = Order.query.filter_by(user_id=current_user.user_id, status='imperfect').first()
    if not order:
        order = Order(user_id=current_user.user_id, order_date=datetime.now(), total_amount=0, status='imperfect')
        db.session.add(order)
        db.session.commit()
    
    order_detail = OrderDetail(order_id=order.order_id, product_id=product_id, quantity=quantity, unit_price=product.price)
    db.session.add(order_detail)
    db.session.commit()
    #Update all amount
    order.total_amount += product.price * quantity
    db.session.commit()
    
    return jsonify({'message': 'Product added to cart successfully'}), 200


@app.route('/view-cart' ,  methods=['GET'])
def view_cart_render():
    return render_template('cart.html')

# View Shopping Cart
@app.route('/cart-view', methods=['GET'])
@token_required
def view_cart(current_user):
    order = Order.query.filter_by(user_id=current_user.user_id, status='imperfect').first()
    if not order:
        return jsonify({'message': 'Your cart is empty'}), 200
    
    order_details = OrderDetail.query.filter_by(order_id=order.order_id).all()
    if not order_details:
        return jsonify({'message': 'Your cart is empty'}), 200
    
    total_amount = order.total_amount
    cart_info = {'total_amount': total_amount, 'products': []}
    for order_detail in order_details:
        product = Product.query.get(order_detail.product_id)
        cart_info['products'].append({
           'image': product.image,
            'product_id': order_detail.product_id,
            'name': product.name,
            'quantity': order_detail.quantity,
            'unit_price': float(order_detail.unit_price),
            'total_price': float(order_detail.unit_price * order_detail.quantity)
        })
    
    return jsonify(cart_info), 200

# Remove Product from Shopping Cart
@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
@token_required
def remove_from_cart(current_user, product_id):
    order = Order.query.filter_by(user_id=current_user.user_id, status='imperfect').first()
    if not order:
        return jsonify({'error': 'No active order found'}), 404
    
    order_detail = OrderDetail.query.filter_by(order_id=order.order_id, product_id=product_id).first()
    if not order_detail:
        return jsonify({'error': 'Product not found in the cart'}), 404
    
    # Update total amount of the order
    order.total_amount -= order_detail.unit_price * order_detail.quantity
    db.session.delete(order_detail)
    db.session.commit()

    return jsonify({'message': 'Product removed from cart successfully'}), 200


@app.route('/checkout' ,  methods=['GET'])
def view_checkout():
    return render_template('checkout.html')


#checkout
@app.route('/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    data = request.json
    
    # Check if the user has a default shipping address
    if current_user.default_shipping_address and data.get('use_default_address', False):
        # Retrieve the default shipping address
        default_address = ShippingAddress.query.get(current_user.default_shipping_address)
        
        if default_address:
            # Use the default shipping address for checkout
            shipping_address = default_address
        else:
            return jsonify({'error': 'Default shipping address not found'}), 404
    else:
        # Validate new shipping address data
        required_fields = ['recipient_name', 'address_line1', 'city', 'state', 'postal_code', 'country']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Incomplete shipping address data'}), 400
        
        # Create a new shipping address record
        shipping_address = ShippingAddress(
            user_id=current_user.user_id,  # Set the user_id correctly
            recipient_name=data['recipient_name'],
            address_line1=data['address_line1'],
            city=data['city'],
            state=data['state'],
            postal_code=data['postal_code'],
            country=data['country']
        )
        db.session.add(shipping_address)
        db.session.commit()

    # Continue with the rest of the checkout process
    
    # Payment method is assumed to be 'cash on delivery' by default
    payment_method = data.get('payment_method', 'cash on delivery')
    if payment_method not in ['cash on delivery', 'paypal']:
        return jsonify({'error': 'Invalid payment method'}), 400
    
    # Create payment record
    order = Order.query.filter_by(user_id=current_user.user_id, status='imperfect').first()
    if not order:
        return jsonify({'error': 'No active order found'}), 404
    
    payment = Payment(
        order_id=order.order_id,
        payment_method=payment_method,
        amount=order.total_amount,
        payment_date=datetime.now()
    )
    db.session.add(payment)
    db.session.commit()
    
    # Update order status to pending
    order.status = 'pending'
    db.session.commit()
    
    # Generate and return order details in PDF format
    order_details = OrderDetail.query.filter_by(order_id=order.order_id).all()
    pdf_data = []
    for order_detail in order_details:
        product = Product.query.get(order_detail.product_id)
        pdf_data.append({
            'order_id': order.order_id,
            'product_id': order_detail.product_id,
            'name': product.name,
            'quantity': order_detail.quantity,
            'unit_price': float(order_detail.unit_price),
            'total_price': float(order_detail.unit_price * order_detail.quantity)
        })
    
    # In real application, generate PDF using a library like ReportLab
    # Here, we're just returning JSON for simplicity
    notification = Notification(user_id=current_user.user_id, message='Order placed successfully')
    db.session.add(notification)
    db.session.commit()
    return jsonify(pdf_data), 200


@app.route('/pending-orders', methods=['GET'])
def view_pending():
    # Query the database to get pending orders
    pending_orders = Order.query.filter_by(user_id=17,status='pending').all()
    
    # Pass the list of orders and the current user to the template
    return render_template('pending_orders.html', orders=pending_orders)


@app.route('/pending-orders-api', methods=['GET'])
@token_required
def view_pending_orders(current_user):
    pending_orders = Order.query.filter_by(user_id=current_user.user_id, status='pending').all()
    if not pending_orders:
        return jsonify({'message': 'No pending orders found'}), 200
    
    order_info = []
    for order in pending_orders:
        order_info.append({
            'order_id': order.order_id,
            'total_amount': order.total_amount,
            'order_date': order.order_date.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return jsonify(order_info), 200



# # Track Order Shipments
# @app.route('/track-order/<int:order_id>', methods=['GET'])
# @token_required
# def track_order_shipment(current_user, order_id):
#     # Find the order with the given order_id
#     order = Order.query.filter_by(user_id=current_user.user_id, order_id=order_id).first()
#     if not order:
#         return jsonify({'error': 'Order not found'}), 404

#     # Get all order details related to this order
#     order_details = OrderDetail.query.filter_by(order_id=order_id).all()
#     if not order_details:
#         return jsonify({'error': 'No order details found for this order'}), 404

#     # Prepare order information including product names and total price
#     order_info = {
#         'order_id': order.order_id,
#         'status': order.status,
#         'total_amount': float(order.total_amount),
#         'products': []
#     }

#     # Get product names and prices from the order details
#     for order_detail in order_details:
#         product = Product.query.get(order_detail.product_id)
#         if product:
#             order_info['products'].append({
#                 'product_name': product.name,
#                 'price': float(order_detail.unit_price),
#                 'quantity': order_detail.quantity,
#                 'total_price': float(order_detail.unit_price * order_detail.quantity)
#             })

#     return jsonify(order_info), 200



@app.route('/history', methods=['GET'])
def user_orders():
    return render_template('user_orders.html')

# Route to view all orders for the current user
@app.route('/user-orders', methods=['GET'])
@token_required
def view_user_orders(current_user):
    all_orders_info = []

    user_orders = Order.query.filter_by(user_id=current_user.user_id).all()

    for order in user_orders:
        found_order_details = False
        order_details = OrderDetail.query.filter_by(order_id=order.order_id).all()

        if not order_details:
            continue

        order_info = {
            'order_id': order.order_id,
            'status': order.status,
            'total_amount': float(order.total_amount),
            'products': []
        }

        for order_detail in order_details:
            product = Product.query.get(order_detail.product_id)
            if product:
                order_info['products'].append({
                    'product_name': product.name,
                    'price': float(order_detail.unit_price),
                    'quantity': order_detail.quantity,
                    'total_price': float(order_detail.unit_price * order_detail.quantity)
                })
            found_order_details = True

        if found_order_details:
            all_orders_info.append(order_info)
        else:
            return jsonify({'error': f'No order details found for order with ID {order.order_id}'}), 404

    return jsonify(all_orders_info), 200


@app.route('/request-return/<int:order_id>', methods=['POST'])
def request_return(order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    if order.status != 'delivered':
        return jsonify({'error': 'Returns can only be requested for delivered orders'}), 400
    
    # Logic for customer return request, like updating order status to 'return requested'
    order.status = 'return requested'
    db.session.commit()
    notification = Notification(user_id=order.user_id, message='Return requested for Order ID {}'.format(order_id))
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Return requested successfully'}), 200




@app.route('/feedback', methods=['POST'])
@token_required
def add_feedback(current_user):
    data = request.json
    
    # Check if required fields are present
    required_fields = ['order_id', 'rating']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Incomplete feedback data'}), 400
    
    order_id = data['order_id']
    rating = data['rating']
    comment = data.get('comment', None)
    
    # Check if the order exists and belongs to the current user
    order = Order.query.filter_by(order_id=order_id).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    # # Check if the order has already been reviewed
    # existing_feedback = Feedback.query.filter_by(order_id=order_id).first()
    # if existing_feedback:
    #     return jsonify({'error': 'Feedback for this order already exists'}), 400
    
    # Save the feedback to the database
    new_feedback = Feedback(
        user_id=current_user.user_id,
        order_id=order_id,
        rating=rating,
        comment=comment,
        feedback_date=datetime.now()
    )
    db.session.add(new_feedback)
    db.session.commit()
    
    return jsonify({'message': 'Feedback added successfully'}), 201


#read file feedback.html
@app.route('/feedback', methods=['GET'])
def get_feedback():
    return render_template('feedback.html')

# read file notif.html
@app.route('/view-notifications', methods=['GET'])
def get_notif():
    return render_template('notif.html')




# Route to get notifications for the current user with token_required decorator
@app.route('/get-notifications', methods=['GET'])
@token_required
def get_user_notifications(current_user):
    notifications = Notification.query.filter_by(user_id=current_user.user_id).all()
    notification_messages = [n.message for n in notifications]

    return jsonify({'notifications': notification_messages})
# @app.route('/logout', methods=['GET'])
# @token_required
# def logout(current_user):
#     resp = make_response(jsonify({'message': 'Logged out successfully'}), 200)
#     resp.set_cookie('Authorization', '', expires=0)  # Clear the Authorization token from the cookie
#     return resp

############################

#Admin View:

#trand product
@app.route('/admin/home/trending_products', methods=['GET'])
@token_required
def trending_products(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view trand prodcut'}), 401
    trending_products = db.session.query(OrderDetail.product_id, func.sum(OrderDetail.quantity).label('total_quantity')).\
        group_by(OrderDetail.product_id).\
        order_by(func.sum(OrderDetail.quantity).desc()).limit(10).all()
    products_data = []
    for product_id, total_quantity in trending_products:
        product = db.session.query(Product).filter_by(product_id=product_id).first()
        if product:
            product_data = {
                'product_id': product.product_id,
                'name': product.name,
                'total_quantity': total_quantity
            }
            products_data.append(product_data)

    return jsonify(products_data)

#Overview of key performance indicators (KPIs) such as total sales,revenue, and number of order
@app.route('/admin/home/KPIs', methods=['GET'])
@token_required
def get_admin_kpis(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view KPIs'}), 401

    total_sales = db.session.query(func.sum(Order.total_amount)).scalar() or 0
    total_revenue = db.session.query(func.sum(Payment.amount)).scalar() or 0
    total_orders = db.session.query(func.count(Order.order_id)).scalar() or 0

    kpis = {
        'total_sales': total_sales,
        'total_revenue': total_revenue,
        'total_orders': total_orders
    }

    return jsonify(kpis), 200



# Create AdminLogs table
def create_adminlogs(user_id, action, ip_address):
    new_log = AdminLogs(user_id=user_id, action=action, action_date=datetime.now(), ip_address=ip_address)
    db.session.add(new_log)
    db.session.commit()

# Add Admin or Customer
@app.route('/customer', methods=['POST'])
def add_user():
    data = request.json
    username = data['username']
    password = data['password']
    email = data['email']
    phone_number = data['phone_number']
    role = data['role']

    # Check if user already exists
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'User already exists'}), 409

    registration_date = datetime.now().date()
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user instance
    new_user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        phone_number=phone_number,
        role=role,
        registration_date=registration_date
    )

    db.session.add(new_user)
    db.session.commit()

    # Return the appropriate data structure for react-admin
    return jsonify({
        'id': new_user.user_id,  # Ensure that we return an 'id' key as react-admin expects
        'username': username,
        'email': email,
        'phone_number': phone_number,
        'role': role,
        'registration_date': registration_date.strftime('%Y-%m-%d')
}), 201

# Delete admin OR customer
@app.route('/customer/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully', 'id': user_id}), 200




@app.route('/customer/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.phone_number = data.get('phone_number', user.phone_number)
    user.role = data.get('role', user.role)
  

    if 'password' in data:
        user.password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    db.session.commit()

    return jsonify({
        'id': user.user_id,
        'username': user.username,
        'email': user.email,
        'phone_number': user.phone_number,
        'role': user.role,
        'registration_date': user.registration_date.strftime('%Y-%m-%d') if user.registration_date else None

    }), 200
@app.route('/customer/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user_data = {
        'id': user.user_id,
        'username': user.username,
        'email': user.email,
        'phone_number': user.phone_number,
         'role': user.role,
        'registration_date': user.registration_date.strftime('%Y-%m-%d') if user.registration_date else None

    }

    return jsonify(user_data), 200

# Get list customers with search functionality
@app.route('/customer', methods=['GET'])
def get_customers():
    sort_query = json.loads(request.args.get('sort', '["id", "ASC"]'))
    sort_field, sort_order = sort_query
    if sort_field == 'id':
        sort_field = 'user_id'
    filter_query = json.loads(request.args.get('filter', '{}'))
    search_filters = []
    if 'email' in filter_query:
        search_filters.append(User.email.ilike(f"%{filter_query['email']}%"))
    if 'username' in filter_query:

        search_filters.append(User.username.ilike(f"%{filter_query['username']}%"))
    if 'phone_number' in filter_query:
        search_filters.append(User.phone_number.ilike(f"%{filter_query['phone_number']}%"))

    search_filter = and_(*search_filters) if search_filters else True

    query = User.query.filter(User.role == 'customer', search_filter)
    total = query.count()

    # Handle range
    range_header = json.loads(request.args.get('range', '[0, 9]'))
    start, end = range_header
    pagination = query.order_by(
        getattr(User, sort_field).desc() if sort_order == 'DESC' else getattr(User, sort_field)
    )[start:end+1]

    customers_info = pagination

    customers_data = [{
        'id': customer.user_id,
        'username': customer.username,
        'email': customer.email,
        'role': customer.role,
        'phone_number': customer.phone_number,
        'registration_date': customer.registration_date.strftime('%Y-%m-%d') if customer.registration_date else None
    } for customer in customers_info]

    response = jsonify(customers_data)
    response.headers['X-Total-Count'] = total
    response.headers['Content-Range'] = f'customers {start}-{end}/{total}'
    return response

   

  









# Add products
@app.route('/products', methods=['POST'])
def add_product():
    file = request.files['image']
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        return jsonify({'error': 'No image provided'}), 400

    new_product = Product(
        name=request.form['name'],
        description=request.form['description'],
        price=request.form['price'],
        category_id=request.form['category_id'],
        image=filename  # Save the path as needed
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'id': new_product.product_id, 'name': new_product.name}), 201

    



@app.route('/products', methods=['GET'])
def get_products():
    sort_query = json.loads(request.args.get('sort', '["id", "ASC"]'))
    sort_field, sort_order = sort_query
    if sort_field == 'id':
        sort_field = 'product_id'
    filter_query = json.loads(request.args.get('filter', '{}'))
    search_filters = []
    if 'name' in filter_query:
        search_filters.append(Product.name.ilike(f"%{filter_query['name']}%"))
    if 'category_id' in filter_query:
        search_filters.append(Product.category_id == filter_query['category_id'])
    if 'price' in filter_query:
        search_filters.append(Product.price == filter_query['price'])

    search_filter = and_(*search_filters) if search_filters else True

    query = Product.query.filter(search_filter)
    total = query.count()

    # Handle range for pagination
    range_header = json.loads(request.args.get('range', '[0, 9]'))
    start, end = range_header
    pagination = query.order_by(
        desc(getattr(Product, sort_field)) if sort_order == 'DESC' else asc(getattr(Product, sort_field))
    )[start:end+1]

    products_info = pagination

    products_data = [{
        'id': product.product_id,
        'name': product.name,
        'description': product.description,
        'price': float(product.price),
        'category_id': product.category_id,
        'image': url_picture+product.image
    } for product in products_info]

    response = jsonify(products_data)
    response.headers['X-Total-Count'] = total
    response.headers['Content-Range'] = f'products {start}-{end}/{total}'
    return response



@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    product_data = {
        'id': product.product_id,
        'name': product.name,
        'description': product.description,
        'price': float(product.price),
        'category_id': product.category_id,
        'image': url_picture+product.image
    }
    return jsonify(product_data), 200



@app.route('/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200


@app.route('/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.json
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.category_id = data.get('category_id', product.category_id)
    product.image = data.get('image', product.image)

    db.session.commit()
    return jsonify({'message': 'Product updated successfully'}), 200




@app.route('/categories', methods=['GET'])
def get_categories():
    sort_query = json.loads(request.args.get('sort', '["id", "ASC"]'))
    sort_field, sort_order = sort_query
    if sort_field == 'id':
        sort_field = 'category_id'
    filter_query = json.loads(request.args.get('filter', '{}'))
    search_filters = []
    if 'name' in filter_query:
        search_filters.append(Category.name.ilike(f"%{filter_query['name']}%"))

    if 'parent_category_id' in filter_query:
        search_filters.append(Category.parent_category_id == filter_query['parent_category_id'])

    search_filter = and_(*search_filters) if search_filters else True

    query = Category.query.filter(search_filter)
    total = query.count()

    # Handle range for pagination
    range_header = json.loads(request.args.get('range', '[0, 9]'))
    start, end = range_header
    pagination = query.order_by(
        desc(getattr(Category, sort_field)) if sort_order == 'DESC' else asc(getattr(Category, sort_field))
    )[start:end+1]

    categories_info = pagination

    categories_data = [{
        'id': category.category_id,
        'name': category.name,
        'description': category.description,
        'parent_category_id': category.parent_category_id,
        'created_at': category.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for category in categories_info]

    response = jsonify(categories_data)
    response.headers['X-Total-Count'] = total
    response.headers['Content-Range'] = f'categories {start}-{end}/{total}'
    return response

@app.route('/categories/<int:category_id>', methods=['GET'])
def get_category(category_id):
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404

    return jsonify({
        'id': category.category_id,
        'name': category.name,
        'description': category.description,
        'parent_category_id': category.parent_category_id,
        'created_at': category.created_at.strftime('%Y-%m-%d %H:%M:%S')
    })


# Delete Category
@app.route('/categories/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    category = Category.query.get(category_id)
    if category is None:
        return jsonify({'error': 'Category not found'}), 404

    db.session.delete(category)
    db.session.commit()
    return jsonify({'message': 'Category deleted successfully'}), 200


# Edit Category
@app.route('/categories/<int:category_id>', methods=['PUT'])
def update_category(category_id):
    category = Category.query.get(category_id)
    if category is None:
        return jsonify({'error': 'Category not found'}), 404

    data = request.json
    category.name = data.get('name', category.name)
    category.description = data.get('description', category.description)
    category.parent_category_id = data.get('parent_category_id', category.parent_category_id)

    db.session.commit()
    return jsonify({'message': 'Category updated successfully', 'category': {
        'id': category.category_id,
        'name': category.name,
        'description': category.description,
        'parent_category_id': category.parent_category_id,
        'created_at': category.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }}), 200

@app.route('/categories', methods=['POST'])
def add_category():
    data = request.json
    name = data.get('name')
    description = data.get('description')
    parent_category_id = data.get('parent_category_id', None)  # Optional
    created_at_str = data.get('created_at', datetime.utcnow().isoformat())  # استفاده از زمان فعلی اگر ارائه نشده

    try:
        # تجزیه رشته تاریخ به شیء datetime
        created_at = dateutil.parser.parse(created_at_str)
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    if not name or not description:
        return jsonify({'error': 'Name and description are required'}), 400

    new_category = Category(
        name=name,
        description=description,
        parent_category_id=parent_category_id,
        created_at=created_at
    )
    db.session.add(new_category)
    db.session.commit()

    return jsonify({
        'id': new_category.category_id,
        'name': new_category.name,
        'description': new_category.description,
        'parent_category_id': new_category.parent_category_id,
        'created_at': new_category.created_at.isoformat()
    }), 201







# View Admin Logs with search functionality
@app.route('/admin/home/logs', methods=['GET'])
@token_required
def view_admin_logs(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view logs'}), 401

    # Get search query parameters from request URL
    search_query = request.args.get('search_query', '')  # Example: ?search_query=login

    # Initialize the query
    query = AdminLogs.query

    # Filter admin logs based on the search query
    if search_query:
        query = query.filter(or_(AdminLogs.user_id.ilike(f'%{search_query}%'),
                                 AdminLogs.action.ilike(f'%{search_query}%'),
                                 AdminLogs.ip_address.ilike(f'%{search_query}%')))
    else:
        query = query.filter(AdminLogs.log_id == -1)  # This ensures that no logs are returned if search_query is empty

    # Execute the query
    admin_logs = query.all()

    logs_data = []
    for log in admin_logs:
        log_info = {
            'log_id': log.log_id,
            'user_id': log.user_id,
            'action': log.action,
            'action_date': log.action_date.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': log.ip_address
        }
        logs_data.append(log_info)

    return jsonify({'admin_logs': logs_data}), 200



# GET List of Orders for Admin with search functionality
@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order_details(order_id):
    order = Order.query.options(
        db.joinedload(Order.order_details).joinedload(OrderDetail.product)
    ).get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    order_details = [{
        'order_detail_id': detail.order_detail_id,
        'product_id': detail.product.product_id,
        'product_name': detail.product.name,
        'product_description': detail.product.description,
        'image':url_picture+ detail.product.image,
        'quantity': detail.quantity,
        'unit_price': str(detail.unit_price),
        'total_price': str(detail.quantity * detail.unit_price)
    } for detail in order.order_details]

    order_info = {
        'id': order.order_id,
        'user_id': order.user_id,
        'order_date': order.order_date.strftime('%Y-%m-%d'),
        'total_amount': str(order.total_amount),
        'status': order.status,
        'details': order_details
    }

    return jsonify(order_info)



@app.route('/orders', methods=['GET'])
def get_orders():
    sort_query = json.loads(request.args.get('sort', '["id", "ASC"]'))
    sort_field, sort_order = sort_query
    if sort_field == 'id':
        sort_field = 'order_id'

    
    query = Order.query.options(
        joinedload(Order.order_details).joinedload(OrderDetail.product)
    )

    # Apply sorting and pagination
    orders = Order.query.options(
        subqueryload(Order.order_details).joinedload(OrderDetail.product)
    ).all()

    orders_data = []
    for order in orders:
        details = [{
            'order_detail_id': detail.order_detail_id,
            'product_id': detail.product.product_id,
            'product_name': detail.product.name,
            'product_description': detail.product.description,
            'image':url_picture+ detail.product.image,
            'quantity': detail.quantity,
            'unit_price': str(detail.unit_price),
            'total_price': str(detail.quantity * detail.unit_price)
        } for detail in order.order_details]

        order_info = {
            'id': order.order_id,
            'user_id': order.user_id,
            'order_date': order.order_date.strftime('%Y-%m-%d'),
            'total_amount': str(order.total_amount),
            'status': order.status,
            'details': details
        }
        orders_data.append(order_info)

    response = jsonify(orders_data)
    response.headers['X-Total-Count'] = len(orders_data)
    response.headers['Content-Range'] = f'orders 0-{len(orders_data)-1}/{len(orders_data)}'
    return response



@app.route('/orders/<int:order_id>', methods=['PUT'])
def update_order(order_id):
    order = Order.query.get(order_id)
    if order is None:
        return jsonify({'error': 'order not found'}), 404

    data = request.json
    order.status = data.get('status', order.name)
   

    db.session.commit()
    return jsonify({'message': 'Category updated successfully', 'order': {
        'id': order.order_id,
        'user_id': order.user_id,
        'total_amount': order.total_amount,
        'status': order.status,
        'order_date': order.order_date.strftime('%Y-%m-%d %H:%M:%S')
    }}), 200




# Delete Category
@app.route('/orders/<int:order_id>', methods=['DELETE'])
def delete_order(order_id):
    order = Order.query.get(order_id)
    if order is None:
        return jsonify({'error': 'order not found'}), 404

    db.session.delete(order)
    db.session.commit()
    return jsonify({'message': 'order deleted successfully'}), 200



# View imperfect orders for admin
@app.route('/admin/home/imperfect-orders', methods=['GET'])
@token_required
def view_imperfect_orders(current_user):
    # Check if the current user is an admin
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view imperfect orders'}), 401

    # Find imperfect orders
    imperfect_orders = Order.query.filter_by(status='imperfect').all()
    if not imperfect_orders:
        return jsonify({'message': 'No imperfect orders found'}), 200
    
    # Prepare order information
    order_info = []
    for order in imperfect_orders:
        order_info.append({
            'order_id': order.order_id,
            'total_amount': float(order.total_amount),
            'order_date': order.order_date.strftime("%Y-%m-%d %H:%M:%S"),
            'user_id': order.user_id
        })
    
    return jsonify(order_info), 200

# Cancel pending orders for admin
@app.route('/admin/home/cancel-order/<int:order_id>', methods=['DELETE'])
@token_required
def cancel_pending_order(current_user, order_id):
    # Check if the current user is an admin
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can cancel orders'}), 401

    # Find the order by order_id
    order = Order.query.filter_by(order_id=order_id, status='pending').first()
    if not order:
        return jsonify({'error': 'Order not found or not pending'}), 404

    # Cancel the order
    order.status = 'canceled'
    db.session.commit()

    # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'cancel_order', request.remote_addr)
    notification = Notification(user_id=order.user_id, message='Order canceled for Order ID {}'.format(order_id))
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Order canceled successfully'}), 200




# Generate Invoice for Admin
@app.route('/admin/home/generate-invoice/<int:order_id>', methods=['GET'])
@token_required
def generate_invoice(current_user, order_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can generate invoices'}), 401

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    order_details = OrderDetail.query.filter_by(order_id=order_id).all()
    if not order_details:
        return jsonify({'message': 'No order details found for this order'}), 200

    # Prepare invoice data
    invoice_data = {
        'invoice_id': f'INV{order.order_id}',
        'user_id': order.user_id,
        'order_date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'),
        'total_amount': order.total_amount,
        'status': order.status,
        'products': []
    }

    for order_detail in order_details:
        product = Product.query.get(order_detail.product_id)
        if product:
            product_info = {
                'product_name': product.name,
                'quantity': order_detail.quantity,
                'unit_price': order_detail.unit_price,
                'total_price': order_detail.quantity * order_detail.unit_price
            }
            invoice_data['products'].append(product_info)

    # Here you can implement the logic to generate an invoice PDF or packing slip
    create_adminlogs(current_user.user_id, 'Generate Invoice', request.remote_addr)
    return jsonify(invoice_data), 200



# View list of all payment transactions with search functionality
@app.route('/admin/home/payment-transactions', methods=['GET'])
@token_required
def view_payment_transactions(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view payment transactions'}), 401

    # Get search query parameters from request URL
    search_query = request.args.get('search_query', '')  # Example: ?search_query=payment

    # Initialize query
    query = Payment.query.join(Order).filter(Order.status != 'imperfect')

    # Filter by payment method and amount if provided
    if search_query:
        query = query.filter(or_(Payment.payment_method.ilike(f'%{search_query}%'),
                                 Payment.amount.ilike(f'%{search_query}%')))

    # Execute the query
    payments = query.all()

    # Prepare payment information for response
    payment_info = []
    for payment in payments:
        payment_info.append({
            'payment_id': payment.payment_id,
            'order_id': payment.order_id,
            'amount': float(payment.amount),
            'payment_method': payment.payment_method,
            'payment_date': payment.payment_date.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify(payment_info), 200



# View payment details including amount and payment method
@app.route('/admin/home/payment-details/<int:payment_id>', methods=['GET'])
@token_required
def view_payment_details(current_user, payment_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view payment details'}), 401
    
    payment = Payment.query.get(payment_id)
    if not payment:
        return jsonify({'error': 'Payment not found'}), 404
    
    order = Order.query.get(payment.order_id)
    if not order:
        return jsonify({'error': 'Associated order not found'}), 404
    
    payment_details = {
        'payment_id': payment.payment_id,
        'order_id': payment.order_id,
        'amount': float(payment.amount),
        'payment_method': payment.payment_method,
        'payment_date': payment.payment_date.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return jsonify(payment_details), 200



#Return processed
@app.route('/admin/home/process-return/<int:order_id>', methods=['PUT'])
@token_required
def process_return(current_user, order_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can process returns'}), 401
    
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    if order.status != 'return requested':
        return jsonify({'error': 'Return can only be processed for orders with "return requested" status'}), 400
    
    # Perform return process here...
    # For example, update inventory, issue refund, change order status to 'returned', etc.
    order.status = 'returned'
    db.session.commit()
    create_adminlogs(current_user.user_id, 'Return processed', request.remote_addr)
    notification = Notification(user_id=order.user_id, message='Return processed for Order ID {}'.format(order_id))
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Return processed successfully'}), 200



# Admin View List of All Saved and search Shipping Addresses
@app.route('/admin/home/view-shipping-addresses', methods=['GET'])
@token_required
def view_shipping_addresses(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view shipping addresses'}), 401

    # Get search query parameters from request URL
    search_query = request.args.get('search_query', '')  # Example: ?search_query=John

    # Initialize query
    query = ShippingAddress.query

    # Filter shipping addresses based on the search query
    if search_query:
        query = query.filter(or_(ShippingAddress.recipient_name.ilike(f'%{search_query}%'),
                                 ShippingAddress.address_line1.ilike(f'%{search_query}%'),
                                 ShippingAddress.address_line2.ilike(f'%{search_query}%'),
                                 ShippingAddress.city.ilike(f'%{search_query}%'),
                                 ShippingAddress.state.ilike(f'%{search_query}%'),
                                 ShippingAddress.postal_code.ilike(f'%{search_query}%'),
                                 ShippingAddress.country.ilike(f'%{search_query}%')))

    # Execute the query
    shipping_addresses = query.all()

    # Prepare shipping address information for response
    shipping_addresses_info = []
    for address in shipping_addresses:
        shipping_addresses_info.append({
            'address_id': address.address_id,
            'user_id': address.user_id,
            'recipient_name': address.recipient_name,
            'address_line1': address.address_line1,
            'address_line2': address.address_line2,
            'city': address.city,
            'state': address.state,
            'postal_code': address.postal_code,
            'country': address.country
        })

    return jsonify(shipping_addresses_info), 200


# Admin Edit Existing Shipping Address
@app.route('/admin/home/edit-shipping-address/<int:address_id>', methods=['PUT'])
@token_required
def edit_shipping_address(current_user, address_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can edit shipping addresses'}), 401

    address = ShippingAddress.query.get(address_id)
    if not address:
        return jsonify({'error': 'Shipping address not found'}), 404

    data = request.json

    address.recipient_name = data.get('recipient_name', address.recipient_name)
    address.address_line1 = data.get('address_line1', address.address_line1)
    address.address_line2 = data.get('address_line2', address.address_line2)
    address.city = data.get('city', address.city)
    address.state = data.get('state', address.state)
    address.postal_code = data.get('postal_code', address.postal_code)
    address.country = data.get('country', address.country)

    db.session.commit()
    create_adminlogs(current_user.user_id, 'Shipping address updated', request.remote_addr)
    return jsonify({'message': 'Shipping address updated successfully'}), 200


# Admin Delete Shipping Address
@app.route('/admin/home/delete-shipping-address/<int:address_id>', methods=['DELETE'])
@token_required
def delete_shipping_address(current_user, address_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can delete shipping addresses'}), 401

    address = ShippingAddress.query.get(address_id)
    if not address:
        return jsonify({'error': 'Shipping address not found'}), 404

    db.session.delete(address)
    db.session.commit()
    create_adminlogs(current_user.user_id, 'Shipping address deleted', request.remote_addr)
    return jsonify({'message': 'Shipping address deleted successfully'}), 200




# View list of all customer feedback submissions with search functionality
@app.route('/admin/home/feedback-submissions', methods=['GET'])
@token_required
def view_feedback_submissions(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view feedback submissions'}), 401

    # Get search query parameters from request URL
    search_query = request.args.get('search_query', '')

    # Initialize query
    query = Feedback.query.join(User).join(Order)

    # Filter by search query if provided
    if search_query:
        query = query.filter(or_(Feedback.order_id.ilike(f'%{search_query}%'),
                                 User.username.ilike(f'%{search_query}%'),
                                 Feedback.rating.ilike(f'%{search_query}%')))

    # Execute the query
    feedback_list = query.all()

    # Prepare feedback information for response
    feedback_info = []
    for feedback in feedback_list:
        feedback_info.append({
            'feedback_id': feedback.feedback_id,
            'user_id': feedback.user_id,
            'order_id': feedback.order_id,
            'rating': feedback.rating,
            'comment': feedback.comment,
            'feedback_date': feedback.feedback_date.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify(feedback_info), 200


# View feedback details including comments and ratings
@app.route('/admin/home/feedback-submissions/<int:feedback_id>', methods=['GET'])
@token_required
def view_feedback_details(current_user, feedback_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view feedback details'}), 401

    # Get the feedback details by feedback_id
    feedback = Feedback.query.get(feedback_id)

    if not feedback:
        return jsonify({'error': 'Feedback not found'}), 404

    # Prepare feedback details for response
    feedback_info = {
        'feedback_id': feedback.feedback_id,
        'user_id': feedback.user_id,
        'order_id': feedback.order_id,
        'rating': feedback.rating,
        'comment': feedback.comment,
        'feedback_date': feedback.feedback_date.strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify(feedback_info), 200



if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0")