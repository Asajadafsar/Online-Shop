#import
from functools import wraps
from sqlalchemy import func
from decimal import Decimal
from flask import Flask,render_template
from flask import request
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from migration import *
from datetime import datetime, timedelta
from flask import make_response
from sqlalchemy import or_
from model import db, User, Product, Order, OrderDetail, Category, Payment, ShippingAddress, Feedback, AdminLogs
import uuid
import random
import jwt
###############################################

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Online-shop.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)
bcrypt = Bcrypt(app)


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
    # Select random 6 products with minimal information
    random_products = Product.query.order_by(func.random()).limit(6).all()

    # Prepare product info
    products_info = []
    for product in random_products:
        product_info = {
            'name': product.name,
            'price': float(product.price),
            'image': product.image
        }
        products_info.append(product_info)

    # Fetch parent categories
    # parent_categories = Category.query.filter_by(parent_category_id=None).all()
    parent_categories = Category.query.filter_by().all()
    categories_info = [{'name': category.name} for category in parent_categories]

    # Return JSON response
    return jsonify({'products': products_info, 'categories': categories_info}), 200


###############################################

#Customer View:

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
        return jsonify(product_info), 200
    else:
        return jsonify({'error': 'Product not found'}), 404


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
                'image': product.image
            })
        return jsonify(products_info), 200
    else:
        return jsonify({'message': 'No products found in this category'}), 404


# Add Product to Shopping Cart
@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
@token_required
def add_to_cart(current_user, product_id):
    data = request.json
    quantity = data.get('quantity', 1)  # Default quantity is 1 if not provided
    
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    order = Order.query.filter_by(user_id=current_user.user_id, status='imperfect').first()
    if not order:
        # Create a new order if the user doesn't have an active one
        order = Order(user_id=current_user.user_id, order_date=datetime.now(), total_amount=0, status='imperfect')
        db.session.add(order)
        db.session.commit()
    
    order_detail = OrderDetail(order_id=order.order_id, product_id=product_id, quantity=quantity, unit_price=product.price)
    db.session.add(order_detail)
    db.session.commit()
    
    # Update total amount of the order
    order.total_amount += product.price * quantity
    db.session.commit()
    
    return jsonify({'message': 'Product added to cart successfully'}), 200

# View Shopping Cart
@app.route('/view-cart', methods=['GET'])
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
            'product_id': order_detail.product_id,
            'name': product.name,
            'quantity': order_detail.quantity,
            'unit_price': float(order_detail.unit_price),
            'total_price': float(order_detail.unit_price * order_detail.quantity)
        })
    
    # In real application, generate PDF using a library like ReportLab
    # Here, we're just returning JSON for simplicity
    return jsonify(pdf_data), 200



@app.route('/pending-orders', methods=['GET'])
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


# Track Order Shipments
@app.route('/track-order/<int:order_id>', methods=['GET'])
@token_required
def track_order_shipment(current_user, order_id):
    # Find the order with the given order_id
    order = Order.query.filter_by(user_id=current_user.user_id, order_id=order_id).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    # Get all order details related to this order
    order_details = OrderDetail.query.filter_by(order_id=order_id).all()
    if not order_details:
        return jsonify({'error': 'No order details found for this order'}), 404

    # Prepare order information including product names and total price
    order_info = {
        'order_id': order.order_id,
        'status': order.status,
        'total_amount': float(order.total_amount),
        'products': []
    }

    # Get product names and prices from the order details
    for order_detail in order_details:
        product = Product.query.get(order_detail.product_id)
        if product:
            order_info['products'].append({
                'product_name': product.name,
                'price': float(order_detail.unit_price),
                'quantity': order_detail.quantity,
                'total_price': float(order_detail.unit_price * order_detail.quantity)
            })

    return jsonify(order_info), 200


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
    order = Order.query.filter_by(order_id=order_id, user_id=current_user.user_id).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    # Check if the order has already been reviewed
    existing_feedback = Feedback.query.filter_by(order_id=order_id).first()
    if existing_feedback:
        return jsonify({'error': 'Feedback for this order already exists'}), 400
    
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





@app.route('/logout', methods=['GET'])
@token_required
def logout(current_user):
    resp = make_response(jsonify({'message': 'Logged out successfully'}), 200)
    resp.set_cookie('Authorization', '', expires=0)  # Clear the Authorization token from the cookie
    return resp




############################

#Admin View:



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
@app.route('/admin/home/add_user', methods=['POST'])
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


# Get list customers with search functionality
@app.route('/admin/home/customers', methods=['GET'])
@token_required
def get_customers(current_user):
    if current_user.role == 'admin':
        # Get search query parameters from request URL
        search_query = request.args.get('search_query', '')  # Example: ?search_query=john
        search_filter = or_(User.username.ilike(f'%{search_query}%'),
                            User.user_id.ilike(f'%{search_query}%'),
                            User.email.ilike(f'%{search_query}%'),
                            User.phone_number.ilike(f'%{search_query}%'))

        # Filter customers based on the search query
        customers_info = User.query.filter(User.role == 'customer', search_filter).all()

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





# Get List admins with search functionality
@app.route('/admin/home/admins', methods=['GET'])
@token_required
def get_admins(current_user):
    if current_user.role == 'admin':
        # Get search query parameters from request URL
        search_query = request.args.get('search_query', '')  # Example: ?search_query=john

        # Filter admins based on the search query
        admins_info = db.session.query(User.username, User.email, User.user_id, User.phone_number) \
            .filter(User.role == 'admin') \
            .filter(or_(User.username.ilike(f'%{search_query}%'),
                        User.email.ilike(f'%{search_query}%'),
                        User.user_id.ilike(f'%{search_query}%'),
                        User.phone_number.ilike(f'%{search_query}%'))).all()

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

    # Check if the product already exists
    existing_product = Product.query.filter_by(name=name).first()
    if existing_product:
        return jsonify({'error': 'Product already exists!'}), 409

    new_product = Product(name=name, price=price, description=description, image=image, category_id=category_id)
    db.session.add(new_product)
    db.session.commit()


    # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'add_product', request.remote_addr)
    return jsonify({'message': 'Product added successfully'}), 201

    

# Get list products with search functionality
@app.route('/admin/home/products', methods=['GET'])
@token_required
def get_products(current_user):
    if current_user.role == 'admin':
        # Get search query parameters from request URL
        search_query = request.args.get('search_query', '')  # Example: ?search_query=apple

        # Filter products based on the search query
        products_info = Product.query.filter(or_(Product.name.ilike(f'%{search_query}%'),
                                                 Product.description.ilike(f'%{search_query}%'),
                                                 Product.product_id.ilike(f'%{search_query}%'),
                                                 Product.price.ilike(f'%{search_query}%'),
                                                 Product.category_id.ilike(f'%{search_query}%'))).all()

        products_data = []
        for info in products_info:
            product_dict = {
                'product_id': info.product_id,
                'name': info.name,
                'price': info.price,
                'category_id': info.category_id,
                'description': info.description,
                'image': info.image
            }
            products_data.append(product_dict)

        return jsonify({'products': products_data}), 200
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
            # Log admin action in AdminLogs table
            create_adminlogs(current_user.user_id, 'delete_product', request.remote_addr)
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
    # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'edit_product', request.remote_addr)
    return jsonify({'message': 'Product updated successfully'}), 200



# Add Category
@app.route('/admin/home/categories/add', methods=['POST'])
@token_required
def add_category(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can add categories'}), 401

    data = request.json
    name = data.get('name')
    description = data.get('description')
    parent_category_id = data.get('parent_category_id', None)
    created_at = datetime.now()

    new_category = Category(name=name, description=description, parent_category_id=parent_category_id, created_at=created_at)
    db.session.add(new_category)
    db.session.commit()
    # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'add_category', request.remote_addr)
    return jsonify({'message': 'Category added successfully'}), 201

# Delete Category
@app.route('/admin/home/categories/delete/<int:category_id>', methods=['DELETE'])
@token_required
def delete_category(current_user, category_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can delete categories'}), 401

    category = Category.query.get(category_id)
    if category:
        db.session.delete(category)
        db.session.commit()
        # Log admin action in AdminLogs table
        create_adminlogs(current_user.user_id, 'delete_category', request.remote_addr)
        return jsonify({'message': 'Category deleted successfully'}), 200
    else:
        return jsonify({'error': 'Category not found'}), 404

# Edit Category
@app.route('/admin/home/categories/edit/<int:category_id>', methods=['PUT'])
@token_required
def edit_category(current_user, category_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can edit categories'}), 401

    category = Category.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404

    data = request.json

    if 'name' in data:
        category.name = data['name']
    if 'description' in data:
        category.description = data['description']
    if 'parent_category_id' in data:
        category.parent_category_id = data['parent_category_id']

    db.session.commit()
   # Log admin action in AdminLogs table
    create_adminlogs(current_user.user_id, 'edit_category', request.remote_addr)
    return jsonify({'message': 'Category updated successfully'}), 200


# List Categories with search functionality
@app.route('/admin/home/categories', methods=['GET'])
@token_required
def get_categories(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access! Only admins can view categories'}), 401

    # Get search query parameters from request URL
    search_query = request.args.get('search_query', '')  # Example: ?search_query=electronics

    # Filter categories based on the search query
    categories = Category.query.filter(or_(Category.name.ilike(f'%{search_query}%'),
                                           Category.category_id.ilike(f'%{search_query}%'),
                                           Category.description.ilike(f'%{search_query}%'),
                                           Category.parent_category_id.ilike(f'%{search_query}%'))).all()

    categories_data = []
    for category in categories:
        data = {
            'category_id': category.category_id,
            'name': category.name,
            'description': category.description,
            'parent_category_id': category.parent_category_id,
            'created_at': category.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        categories_data.append(data)

    return jsonify({'categories': categories_data}), 200



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
@app.route('/admin/home/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    if current_user.role == 'admin':
        # Get search query parameters from request URL
        search_query = request.args.get('search_query', '')  # Example: ?search_query=123

        # Filter orders based on the search query
        orders = Order.query.filter(or_(Order.user_id.ilike(f'%{search_query}%'),
                                        Order.total_amount.ilike(f'%{search_query}%'),
                                        Order.status.ilike(f'%{search_query}%'))).all()

        orders_data = []
        for order in orders:
            order_info = {
                'order_id': order.order_id,
                'user_id': order.user_id,
                'order_date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'),
                'total_amount': order.total_amount,
                'status': order.status
            }
            orders_data.append(order_info)

        return jsonify({'orders': orders_data}), 200
    else:
        return jsonify({'error': 'Unauthorized access! Only admins can view orders'}), 401


    
# GET Detailed Order Information for Admin
@app.route('/admin/home/orders/<int:order_id>', methods=['GET'])
@token_required
def get_order_details(current_user, order_id):
    if current_user.role == 'admin':
        order = Order.query.get(order_id)

        if not order:
            return jsonify({'error': 'Order not found'}), 404

        order_details = OrderDetail.query.filter_by(order_id=order_id).all()
        if not order_details:
            return jsonify({'message': 'No order details found for this order'}), 200

        products_data = []
        total_amount = 0
        for order_detail in order_details:
            product = Product.query.get(order_detail.product_id)
            if product:
                product_info = {
                    'product_name': product.name,
                    'quantity': order_detail.quantity,
                    'unit_price': order_detail.unit_price,
                    'total_price': order_detail.quantity * order_detail.unit_price
                }
                total_amount += order_detail.quantity * order_detail.unit_price
                products_data.append(product_info)

        order_info = {
            'order_id': order.order_id,
            'user_id': order.user_id,
            'order_date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'),
            'total_amount': total_amount,
            'status': order.status,
            'products': products_data
        }

        return jsonify(order_info), 200
    else:
        return jsonify({'error': 'Unauthorized access! Only admins can view order details'}), 401


# PUT Update Order Status for Admin
@app.route('/admin/home/orders_update/<int:order_id>/', methods=['PUT'])
@token_required
def update_order_status(current_user, order_id):
    if current_user.role == 'admin':
        data = request.get_json()

        order = Order.query.get(order_id)
        if not order:
            return jsonify({'error': 'Order not found'}), 404

        if 'status' in data:
            order.status = data['status']
            db.session.commit()
            create_adminlogs(current_user.user_id, 'Update Order Status', request.remote_addr)
            return jsonify({'message': 'Order status updated successfully'}), 200
        else:
            return jsonify({'error': 'Status field is required for updating order'}), 400
    else:
        return jsonify({'error': 'Unauthorized access! Only admins can update order status'}), 401


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