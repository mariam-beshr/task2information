from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import pymysql

# Initialize app
app = Flask(__name__)

# Database Configuration
app.config['SECRET_KEY'] = 'mariam'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/beshrstore'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'mariam'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Function to Create Database if Not Exists
def create_database():
    connection = pymysql.connect(host='localhost', user='root', password='')
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS beshrstore")
    connection.close()

create_database()  # Ensure the database exists before connecting

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# Create Tables
with app.app_context():
    db.create_all()

# User Registration
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(name=data['name'], username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))  # Ensure identity is a string
        return jsonify({'token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Update User Details
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    data = request.get_json()
    user = User.query.get(id)
    if user:
        user.name = data.get('name', user.name)
        user.username = data.get('username', user.username)
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    return jsonify({'message': 'User not found'}), 404

# Add New Product
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.get_json()
    new_product = Product(
        pname=data['pname'],
        description=data.get('description', ''),
        price=data['price'],
        stock=data['stock']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully'}), 201

# Get All Products
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([
        {'pid': p.pid, 'pname': p.pname, 'description': p.description, 
         'price': p.price, 'stock': p.stock, 'created_at': p.created_at} for p in products
    ])

# Get Single Product by ID
@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    product = Product.query.get(pid)
    if product:
        return jsonify({'pid': product.pid, 'pname': product.pname, 
                        'description': product.description, 'price': product.price, 
                        'stock': product.stock, 'created_at': product.created_at})
    return jsonify({'message': 'Product not found'}), 404

# Update Product Details
@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.get_json()
    product = Product.query.get(pid)
    if product:
        product.pname = data.get('pname', product.pname)
        product.description = data.get('description', product.description)
        product.price = data.get('price', product.price)
        product.stock = data.get('stock', product.stock)
        db.session.commit()
        return jsonify({'message': 'Product updated successfully'})
    return jsonify({'message': 'Product not found'}), 404

# Delete Product
@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    product = Product.query.get(pid)
    if product:
        db.session.delete(product)
        db.session.commit()
        return jsonify({'message': 'Product deleted successfully'})
    return jsonify({'message': 'Product not found'}), 404

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
