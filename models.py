from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from flask_login import UserMixin, login_manager
from flask_bcrypt import Bcrypt


db = SQLAlchemy()
bcrypt = Bcrypt()

class User(UserMixin, db.Model):
    id  = db.Column(db.Integer , primary_key = True )
    username = db.Column(db.String(30),unique = True, nullable=False)
    email = db.Column(db.String(150),unique = True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    

class Admin(db.Model,UserMixin):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.Integer, default=0, nullable=False)
    reset_token = db.Column(db.String(200), nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)


def create_default_admin(bcrypt):
    existing_admin = Admin.query.filter_by(email="admin@example.com").first()
    if existing_admin:
        print("Default admin already exists. Skipping creation.")
        return

    hashed_password = bcrypt.generate_password_hash("admin123").decode("utf-8")
    admin = Admin(
        email="admin@example.com",
        password=hashed_password,
        role=0  
    )
    db.session.add(admin)
    db.session.commit()
    print("Default admin created successfully.")
    
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)  
    type_description = db.Column(db.Text, nullable=True)
    photo = db.Column(db.String(100), nullable=True)
    stock = db.Column(db.Integer, default=0)
    category = db.relationship('Category', backref='products', lazy=True)
    rating = db.Column(db.Integer, default=0)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f'<Product {self.name}>'
    

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self):
        return f'{self.name}'


class Order(db.Model):
    __tablename__ = 'orders'  
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.String(100), nullable=True)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    is_paid = db.Column(db.Boolean, default=False)  
    delivery_date = db.Column(db.DateTime, nullable=True)  
    razorpay_order_id = db.Column(db.String(255), unique=True)  

    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    product = db.relationship('Product', backref=db.backref('orders', lazy=True))

    def __init__(self, user_id, product_id, quantity, created_by):
        self.user_id = user_id
        self.product_id = product_id
        self.quantity = quantity
        self.created_by = created_by

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    razorpay_order_id = db.Column(db.String(100), unique=True, nullable=False)
    razorpay_payment_id = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
