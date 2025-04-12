import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
import re

from flask import Flask ,render_template,flash,redirect,url_for,session,request,jsonify ,abort
from forms import RegisterForm,LoginForm, AddManagerForm,AdminLoginForm ,AddProductForm,ValidationError
from models import db, User,Admin, Product, create_default_admin,Category,Order
from flask_bcrypt import Bcrypt
from functools import wraps
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
import secrets
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
import requests
from flask_login import current_user,login_user,LoginManager,login_required
import razorpay
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
def create_app():
    """
    Creates and configures the Flask application.
    Initializes necessary components such as SQLAlchemy, Bcrypt for password hashing,
    file upload configurations, and ensures required directories and tables exist.
    Returns:app (Flask): The Flask application instance.
    """
    

    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    
    # OAuth Configuration
    app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
    
    oauth = OAuth(app)
    app.secret_key = os.getenv("FLASK_SECRET")
    

    RAZORPAY_KEY_ID = "your_key_id"
    RAZORPAY_KEY_SECRET = "your_secret_key"

    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


    
    bcrypt = Bcrypt()
    db.init_app(app)
    bcrypt.init_app(app)

    appConf = {
    "OAUTH2_CLIENT_ID": "your_google_clicent_id",
    "OAUTH2_CLIENT_SECRET": "your_client_secret",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "your_flask_secret_id",
    "FLASK_PORT": 5000
}
    app.secret_key = appConf.get("FLASK_SECRET")
    

    oauth.register(
        "myApp",
        client_id=appConf.get("OAUTH2_CLIENT_ID"),
        client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
    )

    with app.app_context():
        db.create_all()
        create_default_admin(bcrypt)


    app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif','webp'}
   

    # Ensure the upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Allowed file extensions function
    def allowed_file(filename):
        """
         bool: True if the file extension is allowed, False otherwise.
        """
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# function: The decorated function that checks for session login.
    def login_required(f):
        @wraps(f)
        def decorated_function(*args,**kwargs):
            if 'usr_id' not in session:
                return redirect(url_for('login'))
            return f(*args,**kwargs)
        return decorated_function


    # The decorated function that checks for admin access.
    def admin_required(*roles):
        def wrapper(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not any(role in session for role in roles):
                    flash('Access denied. Login with the correct role.', 'danger')
                    return redirect(url_for('admin_login'))

                return f(*args, **kwargs)
            
            return decorated_function
        return wrapper


    @app.route("/signin-google")
    def googleCallback():
        """
        fetch access token and ID token using authorization code and
        fetch user data using personDataUrl more spefically email ,
        check if the user already exists in the database ,
        if the user does not exist, create a new user
        """
        token = oauth.myApp.authorize_access_token()

        personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses"
        personData = requests.get(personDataUrl, headers={
            "Authorization": f"Bearer {token['access_token']}"
        }).json()
        token["personData"] = personData
        
        user = User.query.filter_by(email=token["personData"]["emailAddresses"][0]["value"]).first()

        if not user:
            user = User(
                username=token["personData"]["names"][0]["displayName"],
                email=token["personData"]["emailAddresses"][0]["value"],
                password=None,  
            )
            db.session.add(user)
            db.session.commit()

        session["usr_id"] = user.id
        session["username"] = user.username
        session["email"] = user.email
        flash('You have been logged in!', 'success')
        return redirect(url_for("dashboard"))



    @app.route("/google-login")
    def googleLogin():
        if "usr_id" in session:
            abort(404)
        return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))



    def is_valid_password(password):
        """
        Ensure the password is at least 7 characters and contains a number and letter
        """
        if len(password) > 5:
            raise ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Za-z]', password):
            raise ValidationError("Password must contain at least one letter.")
        if not re.search(r'[0-9]', password):
            raise ValidationError("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")



    @app.route('/')
    def home():
        """
        redirect to login function.

        Functionality:
            - Calls `redirect(url_for('login'))` to navigate users to the login page.
         Output:
            - Redirects the user to the login route.

        """
        return redirect(url_for('login'))


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Handles user authentication and login.

        Parameter
            - email (str): User's email address.
            - password (str): User's password.

        Functionality:
            - Validates the submitted form.
            - Checks if the user exists in the database.
            - Verifies the password using bcrypt hashing.
            - Stores user ID and username in the session upon successful login.
            - Redirects to the dashboard or the next requested page.
            - Displays error messages if authentication fails.

        Output:
            - On success: Redirects to the dashboard or the requested page.
            - On failure: Displays a flash message and reloads the login page.

        """
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            print("Form validation passed")
            if user:
                try:
                    if bcrypt.check_password_hash(user.password, form.password.data):
                        session['usr_id'] = user.id
                        session['username'] = user.username
                        print("Password validation correct")
                        flash('You have been logged in!', 'success')
                        next_page = request.args.get('next')
                        return redirect(next_page or url_for('dashboard'))
                    else:
                        flash('Invalid email or password.', 'danger')
                except Exception as e:
                    print(f"Error during password check: {e}")
                    flash('An error occurred during login. Please try again.', 'danger')
            else:
                flash('Invalid email or password.', 'danger')
        return render_template('login.html', form=form)

    

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """
        Handles user registration.

        Parameter
            - username (str): The desired username.
            - email (str): The user's email address.
            - password (str): The user's chosen password.

        Functionality:
            - Retrieves username, email, and password from the form.
            - Hashes the password using bcrypt before storing it in the database.
            - Creates a new user record and attempts to save it.
            - If registration is successful, redirects to the login page.
            - If an error occurs, rolls back the database transaction and displays an error message.

        Output:
            - Redirects to the login page upon successful registration.
            - Renders the registration page for GET requests or in case of failure.

        """
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  
            new_user = User(username=username,
                            email=email,
                            password=hashed_password)            
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful!', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Error: Could not register user.', 'danger')
                print(e)
        return render_template('register.html')



    @app.route('/dashboard')
    @login_required
    def dashboard():
        """
        Displays the dashboard with paginated product listings.

        Parameter:
            - page (int, optional): The current page number (default: 1).

        Functionality:
            - Retrieves paginated product data.
            - Displays up to 6 products per page.

        Output:
            - Renders the dashboard page with paginated product listings.

        """
        page = request.args.get('page', 1, type=int)
        per_page = 6
        pagination = Product.query.paginate(page=page, per_page=per_page)
        return render_template('dashboard.html',pagination=pagination)
   
    

    @app.route('/buy/<int:product_id>', methods=['POST'])
    def buy(product_id):
        """
        Handles product purchases by updating order details.

        Parameter:
            - product_id (int): The ID of the product being purchased.
            - quantity (int): The quantity of the product the user wants to buy.

        Functionality:
            - Checks if the user is logged in.
            - Validates the quantity input.
            - Verifies product availability.
            - Deducts the purchased quantity from stock.
            - Updates existing order details or creates a new order entry.
            - Commits the order to the database.

        Output:
            - Redirects to the dashboard with a success message if purchase is successful.
            - Redirects to the dashboard with an error message if there are issues (e.g., insufficient stock).

        """
        if 'usr_id' not in session:
            flash("You need to log in first!", "error")
            return redirect(url_for('login'))

        user_id = session['usr_id']
        print(f"Logged in user ID: {user_id}")

        try:
            quantity = request.form.get('quantity', type=int)
            if not quantity or quantity <= 0:
                flash("Invalid quantity selected.", "error")
                return redirect(url_for('dashboard'))

            product = Product.query.get_or_404(product_id)
            if product.stock < quantity:
                flash(f"Not enough stock available. Only {product.stock} left.", "error")
                return redirect(url_for('dashboard'))
            
            product.stock -= quantity

            order_item = Order.query.filter_by(user_id=user_id, product_id=product_id).first()
            if order_item:
                order_item.quantity += quantity
            else:
                created_by = session['username']  
                order_item = Order(user_id=user_id, product_id=product_id, quantity=quantity, created_by=created_by)
                db.session.add(order_item)

            db.session.commit()
            flash(f"{quantity}x {product.name} added to your order! Remaining stock: {product.stock}", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            print(f"Error processing order: {str(e)}")
            flash("There was an issue processing your order. Please try again.", "error")
            return redirect(url_for('dashboard'))



    @app.route('/your_order')
    def order():
        """
        Displays the user's order summary.

        Variable:
            - usr_id (int): The ID of the logged-in user.

        Functionality:
            - Checking if the user is logged in.
            - Retrieves all order items associated with the logged-in user.
            -  Convert to paisa (Razorpay requires amount in paisa)
            - active_orders: Checking if there are any unpaid orders for the user

        Output:
            - Renders the 'your_order.html' template with order details and total price.
        """
        if 'usr_id' not in session:
            flash("You need to log in first!", "error")
            return redirect(url_for('login'))

        user_id = session['usr_id']
        print(f"Logged in user ID: {user_id}")

        # Retrieve all order items associated with the logged-in user
        order_items = Order.query.filter_by(user_id=user_id).all()

        # Checking if there are any unpaid orders for the user
        active_orders = Order.query.filter_by(user_id=user_id, is_paid=False).all()
        if not active_orders:
            flash("No active orders. You cannot access this page.", "info")
            return redirect(url_for('dashboard')) 
        total_price = sum(item.product.price * item.quantity for item in order_items)

        if not active_orders:
            flash("No active orders", "info")

        amount_in_paisa = total_price * 100  

        order_data = {
            "amount": amount_in_paisa,
            "currency": "INR",
            "payment_capture": "1"  
        }
        
        razorpay_order = razorpay_client.order.create(order_data)
        razorpay_order_id = razorpay_order['id']

        # Saving razorpay_order_id in the Order table (only for unpaid orders)
        order = Order.query.filter_by(user_id=user_id, is_paid=False).first()  
        if order:
            order.razorpay_order_id = razorpay_order_id
            db.session.commit()

        return render_template(
            'your_order.html',
            order_items=order_items,
            total_price=total_price,
            key_id=RAZORPAY_KEY_ID,
            amount=amount_in_paisa,
            order_id=razorpay_order_id,
            order=order,
            active_orders=active_orders  
        )
        

    @app.route('/payment_success', methods=['POST'])
    def payment_success():
        """    
            Handles the success response after a Razorpay payment is completed.

        Steps:
            1. Retrieve payment details (payment ID, order ID, and signature) from the form.
            2. Verify the payment signature with Razorpay's utility method.
            3. Update the order status in the database, marking it as paid and setting the delivery date.
            4. Display a success or error message to the user.

            Returns:
                redirect: Redirects the user to the 'order' page with an appropriate flash message.
        """
        payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        signature = request.form.get('razorpay_signature')

        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }

        try:
            razorpay_client.utility.verify_payment_signature(params_dict)

            # Update order as paid and set delivery date
            order = Order.query.filter_by(razorpay_order_id=razorpay_order_id).first()
            if order:
                order.is_paid = True
                order.delivery_date = datetime.utcnow() + timedelta(days=5)  
                db.session.commit()

            flash("Payment successful! Your delivery will arrive in 5 to 7 days.", "success")
        except:
            flash("Payment verification failed!", "error")

        return redirect(url_for('order'))



    @app.route('/cancel_order_item/<int:item_id>', methods=['POST'])
    def cancel_order_item(item_id):
        """
        Cancels a specific order item for the logged-in user.

        Parameter:
            - item_id (int): The ID of the order item to be canceled.
            - usr_id (int): The ID of the logged-in user.

        Functionality:
            - Checking if the user is logged in.
            - Verifing whether the order item belongs to the logged-in user.
            - If found, deletes the order item from the database.
            - If not found, displays an error message.

        Output:
            - Redirects to the order summary page with a success or error message.

        """
        if 'usr_id' not in session:
            flash("You need to log in first!", "error")
            return redirect(url_for('login'))

        user_id = session['usr_id']
        order_item = Order.query.filter_by(id=item_id, user_id=user_id).first()

        if order_item:
            db.session.delete(order_item)
            db.session.commit()
            flash("Order item cancelled successfully", "success")
        else:
            flash("Order item not found or unauthorized action", "error")
        return redirect(url_for('order'))


#             ----------------------  Admin ----------------------------------

    

    @app.route('/admin_login', methods=['GET', 'POST'])
    def admin_login():
        """
        Handles admin login functionality.

        Parameter
            - AdminEmail (str): Admin's email address.
            - AdminPassword (str): Admin's password.

        Functionality:
            - Retrieves admin details from the database using the provided email.
            - Validates the password using bcrypt hashing.
            - If authentication is successful:
                - Creates a session for the logged-in admin.
                - Redirects to the respective dashboard based on admin role (SuperAdmin or Product Manager).
            - If authentication fails, displays an error message.

        Output:
            - Redirect to the admin dashboard on successful login.
            - Render the admin login page with an error message on failure.

        """
        if request.method == 'POST':
            email = request.form['AdminEmail']
            password = request.form['AdminPassword']
            admin = Admin.query.filter_by(email=email).first()
            if admin and bcrypt.check_password_hash(admin.password, password):
                if admin.role == 0:  # SuperAdmin
                    session['SuperAdmin'] = admin.email
                    flash('SuperAdmin logout in successfully!', 'success')
                    return redirect(url_for('admin_dashboard'))
                elif admin.role == 1:  # Retailer
                    session['ProductManager'] = admin.email
                    flash('Product Manager logout in successfully!', 'success')
                    return redirect(url_for('product_manager_dashboard'))
                elif admin.role == 2:
                    session['Retailer'] = admin.email 
                    flash('Retailer logout in successfully!', 'success')
                    return redirect(url_for('product_manager_dashboard'))
            else:
                flash('Invalid email or password. Please try again.', 'danger')
        return render_template('admin_login.html')



    @app.route('/register_admin', methods=['GET', 'POST'])
    @admin_required('SuperAdmin' ,'ProductManager','Retailer')
    def register_admin():
        """
        Handles admin registration functionality.

        Parameter:
            - email (str): New admin's email.
            - password (str): New admin's password (hashed before storage).
            - role (int): Role of the new admin (0 for SuperAdmin, 1 for Product Manager,2 for Retailer).
            - current_user.role (int): Role of the logged-in user.

        Functionality:
            - Ensures only SuperAdmins can access this route.
            - Hashes the password before storing it in the database.
            - Adds the new admin to the database and commits the transaction.
            - Displays success or error messages based on the operation result.

        Output:
            - Redirect to the admin dashboard upon successful registration.
            - Render the admin registration page with an error message on failure.

        """
        # if current_user.role != 0:
        #     flash('You do not have permission to add an admin.', 'danger')
        #     return redirect(url_for('dashboard'))
        if not session.get('SuperAdmin'):
            print("SuperAdmin Session not found")
            return redirect('/admin_login') 
        
        form = AddManagerForm()
        if form.validate_on_submit():
            existing_admin = Admin.query.filter_by(email=form.email.data).first()
            if existing_admin:
                flash("Error: Email is already registered!", 'danger')
                return redirect(url_for('register_admin'))

            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_admin = Admin(
                email=form.email.data,
                password=hashed_password,
                role=form.role.data  
            )
            try:
                db.session.add(new_admin)
                db.session.commit()
                if form.role.data == 0:
                    flash("New SuperAdmin added successfully!", 'success')
                elif form.role.data == 1:
                    flash("New Product Manager added successfully!", 'success')
                elif form.role.data == 2:
                    flash("New Retailer added successfully!", 'success')
            
                flash('Admin registered successfully!', 'success')
                return redirect(url_for('admin_login'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error: {e}", 'danger')
        return render_template('register_admin.html', form=form)
        


    @app.route('/admin_dashboard')
    @admin_required('SuperAdmin')
    def admin_dashboard():
        """
        Displays the admin dashboard with user and product statistics.

        Functionality:
            - Checks if the logged-in user is a SuperAdmin.
            - Fetches the total count of users and products from the database.
            - Renders the admin dashboard template with the retrieved data.

        Output:
            - Redirects to login if the session is invalid.
            - Displays the admin dashboard with user and product counts.

        """
        if not session.get('SuperAdmin'):
            print("SuperAdmin Session not found")
            return redirect('/login')  
        try:
            total_users = User.query.count()
            total_products = Product.query.count()
            print(f"Total Users: {total_users}, Total Products: {total_products}")
        
            return render_template('admin_dashboard.html', 
                                total_users=total_users, 
                                total_products=total_products)
        
        except Exception as e:
            print(f"Error: {str(e)}")
            return "An error occurred while fetching data.", 500




    @app.route('/admin_forgot_password', methods=['GET', 'POST'])
    def admin_forgot_password():
        """
            Handles admin password reset requests.

        Variable:
            - email (str): Admin's email address.

        Functionality:
            - Checks if the email exists in the Admin database.
            - Generates a secure reset token.
            - Sets an expiration time for the token (1 hour).
            - Stores the token and expiration time in the database.
            - Informs the admin to check their email for the reset token.

        Output:
            - Redirects to the admin login page with a reset token if successful.
            - Displays an error message if the email is not found.
        """ 
        if request.method == 'POST':
            email = request.form['email']
            admin = Admin.query.filter_by(email=email).first()           
            if admin:
                reset_token = secrets.token_urlsafe(64)
                expiration_time = datetime.utcnow() + timedelta(hours=1)               
                admin.reset_token = reset_token
                admin.token_expiration = expiration_time
                db.session.commit()
                flash('Password reset token generated. Please check your email.', 'info')
                return render_template('admin_login.html', 
                                       reset_token=reset_token)
            else:
                flash('Admin email not found. Please check and try again.', 'danger')
                return redirect(url_for('admin_login'))



    @app.route('/admin_reset_password', methods=['GET', 'POST'])
    def admin_reset_password():
        """
        Handles admin password reset using a reset token.

        Parameter:
            - reset_token (str): Token provided in the reset email.

        Functionality:
            - Verifies if the token exists and is valid.
            - If valid, allows the admin to reset the password.
            - Updates the admin's password and clears the reset token.

        Output:
            - Redirects to the admin login page upon successful reset.
            - Displays an error if the token is invalid.

         """
        token = request.args.get('reset_token')  
        # new_password = request.form['new_password']
        # confirm_password = request.form['confirm_password'] 
        admin = Admin.query.filter_by(reset_token=token).first()
        if admin:
            db.session.commit()
            flash('Password successfully reset! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        else:
            flash('Invalid token. Please try again.', 'danger')
            return redirect(url_for('admin_login'))


    @app.route('/user_forgot_password', methods=['GET', 'POST'])
    def user_forgot_password():
        """
        Handles user password reset requests.

        Variable:
            - email (str): User's email address.

        Functionality:
            - Checks if the email exists in the User database.
            - Generates a secure reset token.
            - Sets an expiration time for the token (1 hour).
            - Stores the token and expiration time in the database.
            - Informs the user to check their email for the reset token.

        Output:
            - Redirects to the user login page with a reset token if successful.
            - Displays an error message if the email is not found.

        """ 
        if request.method == 'POST':
            email = request.form['email']
            user = User.query.filter_by(email=email).first()
            if user:
                reset_token = secrets.token_urlsafe(64)
                expiration_time = datetime.utcnow() + timedelta(hours=1)                
                user.reset_token = reset_token
                user.token_expiration = expiration_time
                db.session.commit()
                flash('Password reset token generated. Please check your email.', 'info')
                return render_template('login.html', 
                                       reset_token=reset_token)
            else:
                flash('Admin email not found. Please check and try again.', 'danger')
                return redirect(url_for('login'))



    @app.route('/user_reset_password', methods=['GET', 'POST'])
    def user_reset_password():
        """
        Handles user password reset using a reset token.

        Parameter:
            - reset_token (str): Token provided in the reset email.

        Functionality:
            - Verifies if the token exists and is valid.
            - If valid, allows the user to reset the password.
            - Updates the user's password and clears the reset token.

        Output:
            - Redirects to the user login page upon successful reset.
            - Displays an error if the token is invalid.

        """
        token = request.args.get('reset_token')  
        user = User.query.filter_by(reset_token=token).first()
        if user:             
            db.session.commit()
            flash('Password successfully reset! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid token. Please try again.', 'danger')
            return redirect(url_for('login'))



    

    @app.route('/list_users', methods=['GET'])
    def list_users():
        """
        Displays a paginated list of admins and users.

        Functionality:
            - Checks if the logged-in user is a SuperAdmin.
            - If not authenticated, redirects to the admin login page.
            - Fetches users and admins separately.
            - Implements pagination (5 users per page) for the user list.

        Parameter:
            - page (int): The page number for pagination (default is 1).

        Output:
            - Renders 'list_users.html' with:
                - `admins`: List of all admins.
                - `users`: List of all users.
                - `pagination`: Paginated user list.

        """
        if 'SuperAdmin' not in session:
            flash('Access denied. You must be logged in as a SuperAdmin.', 'danger')
            return redirect(url_for('admin_login'))
        page = request.args.get('page', 1, type=int)
        per_page = 5
        pagination = Product.query.paginate(page=page,
                                            per_page=per_page) 
        admins = Admin.query.all()
        users = User.query.all()
        return render_template('list_users.html', 
                               admins=admins, 
                               users=users,
                               pagination=pagination)



    @app.route('/add_manager', methods=['GET', 'POST'])
    def add_manager():
        """
        allows a SuperAdmin to add a new manager.

        functionality:
            - Ensures that only SuperAdmins can access this route.
            - Displays a form to add a new manager.
            - Validates form inputs (email, password, role).
            - Checks if the email is already in use.
            - Hashes the password before storing it.
            - Saves the new manager to the database.

        variable:
                - email (str): Email of the new manager.
                - password (str): Password for the new manager.
                - role (str): Assigned role.

        output:
            - On success, redirects to the list_users page with a success message.
            - On failure, shows an error message and reloads the form.

        """
        if 'SuperAdmin' not in session:
            flash('Access denied.', 'danger')
            return redirect(url_for('admin_login'))

        form = AddManagerForm()  
        if request.method == 'POST' and form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            role = form.role.data  
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            existing_admin = Admin.query.filter_by(email=email).first()

            if existing_admin:
                flash('This email is already taken.', 'danger')
                return redirect(url_for('add_manager'))
            new_manager = Admin(email=email, 
                                password=hashed_password, 
                                role=role)
            db.session.add(new_manager)
            db.session.commit()
            flash('Added successfully!', 'success')
            return redirect(url_for('list_users'))
        return render_template('add_manager.html', form=form)


    @app.route('/list_products')
    def list_products():
        """
        Displays a paginated list of products.

        functionality:
            - checking if the logged-in user is a SuperAdmin.
            - If authenticated, fetches and paginates the product list (5 products per page).
            - If not authenticated, redirects to the admin login page.

         parameter:
            - page (int): The page number for pagination (default is 1).

        Output:
            - renders 'list_products.html' with:
                - `pagination`: Paginated product list.

        """
        if 'SuperAdmin' in session:
            page = request.args.get('page', 1, type=int)
            per_page = 5
            pagination = Product.query.paginate(page=page, per_page=per_page)
            return render_template('list_products.html', pagination=pagination)
        
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_login'))



    @app.route('/add_user', methods=['GET', 'POST'])
    def add_user():
        """
        Allows a SuperAdmin to add a new user.

        functionality:
            - Ensures that only SuperAdmins can access this route.
            - Validates form inputs (username, email, password).
            - Checks if the email is already registered.
            - Hashes the password before storing it in the database.
            - Saves the new user and redirects to the user list.

        variable:
            - username (str): The username of the new user.
            - email (str): The email address of the new user.
            - password (str): The password for the new user.

        output:
            - On success, redirects to the list_users page with a success message.
            - On failure, shows an error message and reloads the form.

        """
        if 'SuperAdmin' not in session:
            flash('Access denied. You must be logged in as a SuperAdmin.', 'danger')
            return redirect(url_for('admin_login'))

        username = request.form.get('username') 
        email = request.form.get('email') 
        password = request.form.get('password')    
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_user'))
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('list_users'))
        hashed_password = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_password)

        db.session.add(user)
        db.session.commit()

        flash('User added successfully!', 'success')
        return redirect(url_for('list_users'))




    @app.route('/update_password/<int:user_id>', methods=['GET', 'POST'])
    def update_password(user_id):
        """
        Allows a SuperAdmin to update an admin's password.

        - Retrieves the admin by their ID.
        - If POST:
            - Hashes and updates the password.
            - Commits changes to the database.
            - Flashes a success message and redirects to the user list.
        - If GET:
            - Renders the password update form.

        Returns:
            - Redirects to 'list_users' on success.
            - Renders 'update_password.html' if accessed via GET.

        """
        user = Admin.query.get_or_404(user_id)
        if request.method == 'POST':
            new_password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('list_users'))
        return render_template('update_password.html', user=user)



    @app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
    def update_user(user_id):
        """
        Allows a SuperAdmin to update user details.

        - Checks if 'SuperAdmin' is in session.
        - If POST:
            - Updates username, email, and optionally password.
            - Commits changes to the database.
            - Flashes a success message and redirects.
        - If GET:
            - Renders the user update form.

        Returns:
            - Redirects to 'list_users' on success.
            - Redirects to 'admin_login' if unauthorized.
            - Renders 'update_user.html' if accessed via GET.
    
        """
        if 'SuperAdmin' in session:
            user = User.query.get_or_404(user_id)
            if request.method == 'POST':
                user.username = request.form['username']
                user.email = request.form['email']
                if request.form['password']:
                    user.password = generate_password_hash(request.form['password'])

                db.session.commit()
                flash('User updated successfully!', 'success')
                return redirect(url_for('list_users'))
            return render_template('update_user.html', user=user)
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_login'))



    @app.route('/delete_admin/<int:admin_id>', methods=['GET', 'POST'])
    def delete_admin(admin_id):
        """
        Allows a SuperAdmin to delete an admin from the database.

        - Checks if 'SuperAdmin' is in session.
        - Retrieves the admin by ID.
        - Deletes the admin from the database.
        - Flashes a success message and redirects.

        Returns:
            - Redirects to 'list_users' on success.
            - Redirects to 'admin_login' if unauthorized.
        """
        admin = Admin.query.get_or_404(admin_id)
        db.session.delete(admin)
        db.session.commit()
        flash('Admin deleted successfully!', 'success')
        return redirect(url_for('list_users'))


    @app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
    def delete_user(user_id):
        """
        Allows a SuperAdmin to delete a user.

        - Retrieves the user by their ID.
        - Deletes the user from the database.
        - Flashes a success message and redirects.

        Returns:
            - Redirects to 'list_users' on success.
            - Redirects to 'admin_login' if unauthorized.

        """
        user = User.query.get_or_404(user_id)  
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        return redirect(url_for('list_users'))



    @app.route('/api/products')
    def get_products():
        """
        Retrieves all products from the database and returns them as JSON.
        If no products exist, returns an empty response with a message.
   
        """
        products = Product.query.all()  
        products_list = [
            {'name': product.name, 
             'price': product.price, 
             'photo': product.photo, 
             'category': product.category, 
             'type_description': product.type_description
             }
            for product in products
        ]
        return jsonify(products_list)


    @app.route('/admin/add_product', methods=['GET', 'POST'])
    @admin_required
    def add_product():
        """
        Allows an admin to add a new product.

        - If the form is submitted with valid data:
            - Creates a new product.
            - Adds it to the database.
            - Redirects to the admin dashboard.
        - If GET:
            - Renders the add product form.

        Returns:
            - Redirects to 'admin_dashboard' on success.
            - Renders 'add_product.html' if accessed via GET.
        """
        form = AddProductForm()
        if form.validate_on_submit():
            product = Product(name=form.product_name.data, price=form.product_price.data)
            db.session.add(product)
            db.session.commit()
            flash('Product has been added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('add_product.html', form=form)



    @app.route('/add_product', methods=['GET', 'POST'])
    def add_product():
        """
        Handles adding a new product to the database. Validates the form data, including product 
        name, price, category, type description, stock, and photo. If the data is valid, the product 
        is saved to the database. Displays appropriate flash messages in case of success or error.
        
        return: The rendered template with the product form or a redirection to the product list page.
        
        """
        
        category = None
        categories = Category.query.all()  
        if request.method == 'POST':
            product_name = request.form.get('product_name')
            product_price = request.form.get('product_price')
            category_name = request.form.get('category') 
            type_description = request.form.get('type_description')
            stock = request.form.get('stock')
            rating = db.Column(db.Integer, default=0)
            photo = request.files.get('photo')

            if not product_name or not type_description:
                flash("Product name and type description are required.", "error")
                return render_template('add_product.html', 
                                    category=category, 
                                    categories=[category.name for category in categories])
            try:
                product_price = float(product_price)
                if product_price <= 0:
                    raise ValueError
            except ValueError:
                flash("Product price must be a positive number.", "error")
                return render_template('add_product.html', 
                                    category=category, 
                                    categories=[category.name for category in categories])
            try:
                stock = int(stock)
                if stock < 0:
                    raise ValueError
            except ValueError:
                flash("Stock quantity must be a non-negative integer.", "error")
                return render_template('add_product.html', categories=categories)

            if not photo or not photo.filename:
                flash("Product photo is required.", "error")
                return render_template('add_product.html', 
                                    category=category, 
                                    categories=[category.name for category in categories])
            if not allowed_file(photo.filename):
                flash("Invalid file type. Please upload an image file (png, jpg, jpeg, gif).", "error")
                return render_template('add_product.html', 
                                    category=category, 
                                    categories=[category.name for category in categories])

            category = Category.query.filter_by(name=category_name).first()

            filename = secure_filename(photo.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(filepath)
            rating = 0 
            product = Product(
                name=product_name,
                price=product_price,
                category=category,  
                stock= stock,
                type_description=type_description,
                rating=rating,  
                photo=filename
            )
            db.session.add(product)
            db.session.commit()           
            flash("Product added successfully!", "success")
            return redirect(url_for('list_products'))
        return render_template('add_product.html', 
                            category=category, 
                            categories=[category.name for category in categories])




# ----------------------------  Admin Manager  --------------------


    @app.route('/product_manager_dashboard', methods=['GET'])
    def product_manager_dashboard():
        """
        Displays the Product Manager dashboard with a paginated list of products and category filtering.

        Functionality:
            - Checks if the logged-in user is a Product Manager.
            - Fetches and paginates the product list (5 products per page).
            - Allows filtering by product category.
            - If the user is not authenticated as a Product Manager, redirects to the admin login page.

        Parameters:
            - page (int): The page number for pagination (default is 1).
            - category (str): The selected category for filtering (optional).
        
        Render:
            - Renders 'product_manager_dashboard.html' with 'pagination': Paginated product list, 
            'categories': Available categories, and 'selected_category': Currently selected category.
        """
        if 'ProductManager' in session:
            selected_category = request.args.get('category', '')
            
            categories = db.session.query(Product.category).distinct().all()
            categories = [category[0] for category in categories] 
            
            query = Product.query
            
            if selected_category:
                query = query.filter(Product.category == selected_category)

            page = request.args.get('page', 1, type=int)
            per_page = 5
            pagination = query.paginate(page=page, per_page=per_page)

            return render_template('product_manager_dashboard.html', 
                                pagination=pagination, 
                                categories=categories, 
                                selected_category=selected_category)
        
        flash('Access denied. You must be logged in as a Product Manager.', 'danger')
        return redirect(url_for('admin_login'))




    @app.route('/add_category', methods=['GET', 'POST'])
    def add_category():
        """
        This route allows the admin to add a new category. It checks if the category already exists 
        in the database before creating it. If the category is created successfully, a success message is 
        flashed. If the category already exists, an error message is shown.
        
        return: The rendered template for adding a category or a redirection to the same page.
        """
        categories = Category.query.all()  
        if request.method == 'POST':
            new_category = request.form['new_category'].strip()  
            existing_category = Category.query.filter_by(name=new_category).first()
            if existing_category:
                flash("Category already exists.", "error")
                return redirect(url_for('add_category'))
            try:
                category = Category(name=new_category)
                db.session.add(category)
                db.session.commit()
                flash("Category added successfully!", "success")
            except IntegrityError:
                db.session.rollback()
                flash("An error occurred while adding the category.", "error")
            return redirect(url_for('add_category'))
        return render_template('add_category.html',
                                categories=categories)



    @app.route('/delete_category/<int:category_id>', methods=['POST'])
    def delete_category(category_id):
        """
        This route deletes a category after checking if it is linked to any products. If the category is linked 
        to products, it cannot be deleted. A success or error message is flashed based on the outcome.
        
        param category_id: The ID of the category to be deleted.
        return: A redirection to the category management page.
       
        """
        category = Category.query.get(category_id)
        if category:
            if category.products:
                flash("Cannot delete category. It is linked to existing products.", "error")
            else:
                db.session.delete(category)
                db.session.commit()
                flash("Category deleted successfully!", "success")
        else:
            flash("Category not found.", "error")       
        return redirect(url_for('add_category'))  
    

    
    @app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
    def edit_product(product_id):
        """
        Allows an admin to update product details, including name, price, category, stock, type description, and photo.

        Functionality:
            - Retrieves the product by its ID.
            - Updates the product's details based on form input.
            - If a new photo is provided, uploads and saves it.
            - Displays a success message.
            - Redirects to the list of products page.

        Parameter:
            - product_id (int): The ID of the product to be edited.
            - product_name (str): The new name for the product.              
            - product_price (float): The new price for the product.
            - category (str): The category name for the product.
            - stock (int): The stock quantity for the product.
            - type_description (str): The type description for the product.
            - photo (file): An optional new photo for the product.

        Output:
            - On success, redirects to the list of products page with a success message.

        """
        categories = Category.query.all() 
        product = Product.query.get_or_404(product_id)
        if request.method == 'POST':
            product.name = request.form['product_name']
            product.price = request.form['product_price']
            category_name = request.form['category']
            product.stock = int(request.form.get('stock', product.stock))
            category = Category.query.filter_by(name=category_name).first()
            if category:
                product.category = category 
            else:
                flash("Category not found", "error")

            product.type_description = request.form.get('type_description','')
            photo = request.files.get('photo')
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(filepath)
                product.photo = filename 
            db.session.commit()
            print("Updated Stock:", product.stock)
            return redirect(url_for('list_products'))  
        return render_template('edit_product.html',
                                product=product ,
                                categories=[category.name for category in categories])


    @app.route('/edit_manager/<int:product_id>', methods=['GET', 'POST'])
    def edit_manager(product_id):
        """
            Allows an admin to update product details from the manager dashboard, including name, price, category, stock, type description, and photo.

        Functionality:
            - Retrieves the product by its ID.
            - Updates the product's details based on form input.
            - If a new photo is provided, uploads and saves it.
            - Displays a success message.
            - Redirects to the manager dashboard.

        Parameter:
            - product_id (int): The ID of the product to be edited.
            - Form Data:
                - product_name (str): The new name for the product.
                - product_price (float): The new price for the product.
                - category (str): The category name for the product.
                - stock (int): The stock quantity for the product.
                - type_description (str): The type description for the product.
                - photo (file): An optional new photo for the product.

        return:
           - Redirects to 'product_manager_dashboard' after successfully editing the product.
        """
        categories = Category.query.all() 
        product = Product.query.get_or_404(product_id)
        if request.method == 'POST':
            product.name = request.form['product_name']
            product.price = request.form['product_price']
            category_name = request.form['category']
            product.stock = int(request.form.get('stock', product.stock)) 
            category = Category.query.filter_by(name=category_name).first()
            if category:
                product.category = category  
            else:
                flash("Category not found", "error")

            product.type_description = request.form.get('type_description','')
            photo = request.files.get('photo')
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(filepath)
                product.photo = filename 
            db.session.commit()
            print("Updated Stock:", product.stock)
            return redirect(url_for('product_manager_dashboard'))  
        return render_template('edit_manager.html',
                                product=product ,
                                categories=[category.name for category in categories])


    
    @app.route('/delete_product/<int:product_id>', methods=['GET'])
    def delete_product(product_id):
        """
        Allows an admin to delete a product from the database.

        Functionality:
            - Retrieves the product by its ID.
            - Deletes the product from the database.
            - Redirects the admin to the list of products page after deletion.

        Parameter:
            - product_id (int): The ID of the product to be deleted.

        Returns:
            - Redirects to 'list_products' or the previous page after successfully deleting the product.
        """
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        # return redirect(url_for('list_products'))  
        return redirect(request.referrer or url_for('list_products'))


    @app.route('/product_manager_add_product', methods=['GET', 'POST'])
    def product_manager_add_product():
        """
        Allows a Product Manager to add a new product to the database.

        functionality:
            - Checking the user is logged in as a Product Manager.
            - If the form is valid, the product is added to the database with all the required details.
            - If the form is invalid, the error messages are displayed.
            - Displays a success message and redirects to the product manager dashboard.

        form Data:
                - product_name (str): The name of the product.
                - product_price (float): The price of the product.
                - category (int): The category ID for the product.
                - stock (int): The quantity of the product in stock.
                - type_description (str): The type description of the product.
                - photo (file): An optional product photo.

        Returns:
            - redirects to 'product_manager_dashboard' after successfully adding the product.
        """
        if 'ProductManager' not in session:
            flash('Access denied. You must be logged in as a Product Manager.', 'danger')
            return redirect(url_for('admin_login'))

        form = AddProductForm()

        if form.validate_on_submit():
            print("Form Validated!")  
            print("Received Data:", request.form)  
            print("Received Files:", request.files)  

            filename = None
            if form.photo.data:
                filename = secure_filename(form.photo.data.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])

                form.photo.data.save(filepath)

            product = Product(
                name=form.product_name.data,
                price=form.product_price.data,
                category_id=form.category.data,
                stock=form.stock.data,
                type_description=form.type_description.data,
                photo=filename  
            )
            db.session.add(product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('product_manager_dashboard'))

        else:
            print("Form Errors:", form.errors) 

        return render_template('product_manager_add_product.html', form=form, categories=Category.query.all())



    @app.route('/logout')
    @login_required
    def logout():
        """
        Logs out the user by clearing their session data.

        Functionality:
            - Checks which type of user is logged in (regular user, admin, or superadmin).
            - Based on the user type, removes their respective session data.
            - Displays a success message indicating successful logout.
            - Redirects the user to the appropriate page after logout (login page or home page).

        Session data:
                - usr_id (str): User ID of the logged-in user.
                - username (str): Username of the logged-in user.
                - AdminEmail (str): Email of the logged-in admin.
                - SuperAdmin (str): SuperAdmin role in the session.

        Returns:
            - Redirects to 'login' page if a regular user logs out.
            - Redirects to 'home' page if an admin or superadmin logs out.
        """
        if session.get('usr_id') and session.get('username'):
            session.pop('usr_id')
            session.pop('username')
            flash('You have been logged out!!!','success')
            return redirect(url_for('login'))
        
        elif session.get('AdminEmail'):
            session.pop('AdminEmail')
            flash('You have been logout from Admin Page!!!','success')
            return redirect(url_for('home'))
        
        elif 'SuperAdmin' in session:
            session.pop('SuperAdmin')
            flash('You have been logged out!', 'success')
            return redirect(url_for('home'))


    
    
    return app
    
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True,port=5000)

# if __name__ == '__main__':
#     app = create_app()
#     app.run(debug=True,port=5001)