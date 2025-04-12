import re
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField, FloatField, SelectField,TextAreaField,FileField,IntegerField
from wtforms.validators import DataRequired,Length,Email,EqualTo,ValidationError ,NumberRange
from flask_wtf.file import FileField, FileRequired
from models import User,Category



def is_valid_password(password):
    """
    Ensure the password is at least 8 characters, contains a number, and a letter.
    """
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Za-z]', password):
        raise ValidationError("Password must contain at least one letter.")
    if not re.search(r'[0-9]', password):
        raise ValidationError("Password must contain at least one number.")


def is_valid_gmail(email):
    """
    Ensure the email is a valid Gmail address.
    """
    if not email.endswith('@gmail.com'):
        raise ValidationError("Please use a valid Gmail address.")




class RegisterForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(),Length(min=2,max=100)])
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_password = PasswordField('confirm_password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Sign up')
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose another.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered. Please choose another.')

class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField('Login')


class AdminLoginForm(FlaskForm):
    AdminEmail = StringField('AdminEmail',validators=[DataRequired(),Email()])
    AdminPassword = PasswordField('AdminPassword',validators=[DataRequired()])
    submit = SubmitField('Login')


class AddManagerForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[(1, 'Product Manager'),(2, 'Retailer')], coerce=int, validators=[DataRequired()])
    submit = SubmitField('Register')

class AddProductForm(FlaskForm):
    product_name = StringField('Product Name', validators=[DataRequired(), Length(min=2, max=100)])
    product_price = FloatField('Product Price', validators=[DataRequired() ,NumberRange(min=1)])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])  
    type_description = TextAreaField('Type Description', validators=[DataRequired()])  
    photo = FileField('Upload Photo', validators=[FileRequired()])
    stock = IntegerField('stock',validators=[DataRequired(), NumberRange(min=0,max=100000)])
    submit = SubmitField('Add Product')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.category.choices = [(category.id, category.name) for category in Category.query.all()]


class OrderForm(FlaskForm):
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1, message="Quantity must be at least 1")])
    submit = SubmitField('Buy Now')