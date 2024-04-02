#import
from sqlalchemy import func
from decimal import Decimal
from flask import Flask,render_template
from flask import request
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from sqlalchemy import or_
import uuid
###############################################


db = SQLAlchemy()


#creat tables User
class User(db.Model):
    user_id = db.Column(db.Integer,unique=True, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    registration_date = db.Column(db.Date, nullable=False)
    role = db.Column(db.String(80), nullable=False)
    default_shipping_address=db.Column(db.Integer)


# Product Browsing
class Product(db.Model):
    __tablename__ = 'Product'
    product_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.DECIMAL(10, 2), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('Category.category_id'), nullable=False)
    image = db.Column(db.String(100), nullable=False)

# Orders
class Order(db.Model):
    __tablename__ = 'Orders'
    order_id = db.Column(db.Integer,unique=True, primary_key=True,autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False)
    total_amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    status = db.Column(db.String(20), nullable=False)

# Order Details
class OrderDetail(db.Model):
    __tablename__ = 'OrderDetails'
    order_detail_id = db.Column(db.Integer,unique=True, primary_key=True,autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('Orders.order_id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('Product.product_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.DECIMAL(10, 2), nullable=False)

# Categories
class Category(db.Model):
    __tablename__ = 'Category'  # Define the table name explicitly
    category_id = db.Column(db.Integer,unique=True, primary_key=True,autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    parent_category_id = db.Column(db.Integer, db.ForeignKey('Category.category_id'))
    created_at = db.Column(db.DateTime, nullable=False)

# Payments
class Payment(db.Model):
    __tablename__ = 'Payments'   
    payment_id = db.Column(db.Integer,unique=True, primary_key=True,autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('Orders.order_id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False)

# Shipping Addresses
class ShippingAddress(db.Model):
    __tablename__ = 'ShippingAddresses'
    address_id = db.Column(db.Integer,unique=True, primary_key=True,autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    recipient_name = db.Column(db.String(100), nullable=False)
    address_line1 = db.Column(db.String(255), nullable=False)
    address_line2 = db.Column(db.String(255))
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), nullable=False)

# Feedback
class Feedback(db.Model):
    feedback_id = db.Column(db.Integer,unique=True, primary_key=True,autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('Orders.order_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    feedback_date = db.Column(db.DateTime, nullable=False)


# Create AdminLogs table
class AdminLogs(db.Model):
    __tablename__ = 'AdminLogs'  # Define the table name explicitly
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    action_date = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)

