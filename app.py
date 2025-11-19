# import necessary modules and libraries

from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,SelectField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from datetime import datetime

# making flask app(object)

app = Flask(__name__)

# <<MySQL Configuration>>

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'app_user'
app.config['MYSQL_PASSWORD'] = 'strong_password'
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)

# include current year into all templates

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Creating Registration Form

class RegisterForm(FlaskForm):
    #fill the necessary fields
    name = StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    role = SelectField("Role (Admin/Staff)", choices=[('Admin', 'Admin'), ('Staff', 'Staff')], validators=[DataRequired()])
    phone = StringField("Phone",validators=[DataRequired()])
    city = StringField("City",validators=[DataRequired()])
    country = StringField("Country",validators=[DataRequired()])
    submit = SubmitField("Register")
    
    
     # validator for email field
    def validate_email(self,field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where email=%s",(field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')
            
    # validator for role field
    def validate_role(self, field):
        valid_roles = ['Admin', 'Staff']
        if field.data not in valid_roles:
            raise ValidationError('Role must be either "Admin" or "Staff".')
    

# Creating Login Form

class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")


# creating routes

@app.route('/')
def index():
    # If the user is logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    return render_template('index.html')


# Registration Route 

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data
        phone = form.phone.data
        city = form.city.data
        country = form.country.data

        # bcrypt password hashing using utf-8 encoding and stored into database as string
        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt()).decode('utf-8')

        # store data into database 
        cursor = mysql.connection.cursor()
        
       #SQL insertion with given order
        sql = """
        INSERT INTO users (name, email, password, role, phone, city, country) 
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (name, email, hashed_password, role, phone, city, country)
        
        cursor.execute(sql, values)
        
        mysql.connection.commit()
        cursor.close()
        
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html',form=form)

# Login Route for login purpose
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        #check order of fields
        cursor.execute("SELECT * FROM users WHERE email=%s",(email,))
        user = cursor.fetchone()
        cursor.close()
        
        # Assuming 'role' is the 5th column based on the typical INSERT order.
        if user:
            stored_pw = user[3]
            if isinstance(stored_pw, bytes):
                stored_pw_bytes = stored_pw
            else:
                stored_pw_bytes = stored_pw.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_pw_bytes):
                session['user_id'] = user[0]
                role_val = user[4]
                if isinstance(role_val, bytes):
                    role_val = role_val.decode('utf-8')
                session['user_role'] = role_val
                return redirect(url_for('dashboard'))

        flash("Login failed. Please check your email and password")
        return redirect(url_for('login'))

    return render_template('login.html',form=form)

# Dashboard Route for dashboard 
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        #SELECT fetching user details
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            user_role = session.get('user_role', 'Staff') 
            return render_template('dashboard.html', user=user, user_role=user_role)
            
    return redirect(url_for('login'))

#user router for users for searching
@app.route('/users', methods=['GET'])
def list_users():
    #  Authentication Check
    if 'user_id' not in session:
        flash("Please log in to view this page.")
        return redirect(url_for('login'))

    #  Authorization Check (Only Admin)
    if session.get('user_role') != 'Admin':
        flash("Access Denied: Only Administrators can view the user list.")
        return redirect(url_for('dashboard'))

    # Search and Filter Logic
    search_term = request.args.get('search')  # Searched by name or email
    country_filter = request.args.get('country') # Filtering by country

    base_query = "SELECT id, name, email, role, phone, city, country FROM users"
    conditions = []
    query_params = []

    # Filtering by Country
    if country_filter:
        conditions.append("country = %s")
        query_params.append(country_filter)

    # Searching by Name or Email
    if search_term:
        search_like = f"%{search_term}%"
        
        if conditions:
            conditions.append(f"AND (name LIKE %s OR email LIKE %s)")
        else:
            conditions.append(f"(name LIKE %s OR email LIKE %s)")
            
        query_params.extend([search_like, search_like])


    # Construct Final Query
    if conditions:
        final_query = base_query + " WHERE " + " ".join(conditions)
    else:
        final_query = base_query

    cursor = mysql.connection.cursor()
    cursor.execute(final_query, tuple(query_params))
    users = cursor.fetchall()
    cursor.close()
    
    # dynamic filter dropdown
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT DISTINCT country FROM users WHERE country IS NOT NULL")
    countries = [row[0] for row in cursor.fetchall()]
    cursor.close()

    return render_template('users.html', 
                            users=users, 
                            search_term=search_term, 
                            country_filter=country_filter,
                            countries=countries)


# user details route
@app.route('/users/<int:user_id>', methods=['GET'])
def user_details(user_id):
    # Authentication Check
    if 'user_id' not in session:
        flash("Please log in to view this page.")
        return redirect(url_for('login'))

    logged_in_user_id = session.get('user_id')
    logged_in_user_role = session.get('user_role')

    # Authorization Check: 
    is_admin = (logged_in_user_role == 'Admin')
    is_self = (logged_in_user_id == user_id)

    if not is_admin and not is_self:
        flash("Access Denied: You can only view your own details.")
        return redirect(url_for('dashboard'))

    # fetching user details without password
    cursor = mysql.connection.cursor()
    sql = "SELECT id, name, email, role, phone, city, country FROM users WHERE id=%s"
    cursor.execute(sql, (user_id,))
    user_details_tuple = cursor.fetchone()
    cursor.close()

    if not user_details_tuple:
        flash("User not found.")
        return redirect(url_for('dashboard'))

    user_details_keys = ['id', 'name', 'email', 'role', 'phone', 'city', 'country']
    user_details = dict(zip(user_details_keys, user_details_tuple))

    return render_template('user_details.html', user=user_details, is_admin=is_admin)

# logout route for logout 
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))



# running the app
if __name__ == '__main__':
    app.run(debug=True)