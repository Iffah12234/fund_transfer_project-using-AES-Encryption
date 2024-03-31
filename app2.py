from flask import Flask, render_template, request, redirect, url_for, session
import pymysql
import cryptography
from flask import jsonify
from cryptography.fernet import Fernet
import re
from datetime import datetime
from flask import session
from flask import flash
import random
import string
from flask_mail import Mail, Message


app = Flask(__name__)
app.secret_key = '7G5j8oD#sF!2h@Kl'  # Set a secret key for session management

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'users',
}

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'CipherVaultinfo@gmail.com'
app.config['MAIL_PASSWORD'] = 'vpymndpcgyaagwwo'
app.config['MAIL_DEFAULT_SENDER'] = 'CipherVaultinfo@gmail.com'

mail = Mail(app)

otp_storage = {}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp(email, otp):
    subject = "Password Reset OTP"
    body = f"Hello,\n\nYour One-Time Password (OTP) for resetting your password is: {otp}\n\nIf you didn't request this OTP, please ignore this message.\n\nPlease do not share this OTP with anyone for security reasons.\n\n\nBest regards,\nThe CipherVault Team"
    message = Message(subject, recipients=[email], body=body)
    mail.send(message)



@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form['email']
        # Check if email exists in the database
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM newusers WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()
        if user:
            otp = generate_otp()
            otp_storage[email] = otp
            send_otp(email, otp)
            # Set success message to be displayed in the template
            success_message = 'An OTP has been sent to your email. Please check your inbox.'
            return render_template('resetpassword.html', success_message=success_message)
        else:
            # Render the template with an error message if email is not registered
            error_message = 'Email not registered.'
            return render_template('forgotpassword.html', error_message=error_message)
    # Render the template for GET request
    return render_template('forgotpassword.html')




@app.route('/resetpassword', methods=['GET', 'POST'])
def resetpassword():
    email = request.args.get('email')
    error_message = None
    success_message = None

    if not email or email not in otp_storage:
        error = 'Invalid request.'
        return render_template('login.html',  error=error)

    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        if otp == otp_storage[email]:
            # Reset password in the database
            conn = pymysql.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("UPDATE newusers SET password = %s WHERE email = %s", (new_password, email))
            conn.commit()
            conn.close()
            del otp_storage[email]
            success_message = 'Password reset successfully.'
            return render_template('login.html',success_message=success_message)
        else:
            error_message = 'Invalid OTP.'
    
    return render_template('resetpassword.html', email=email, error_message=error_message, success_message=success_message)



# Generate a key for AES encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Encrypt the password using AES
def encrypt_password(password):
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt the password using AES
def decrypt_password(encrypted_password):
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
        return decrypted_password
    except cryptography.fernet.InvalidToken:
        print("Invalid token: Failed to decrypt password.")
        return None



# @app.before_request
# def before_request():
#     # Check if the session has timed out
#     if 'user_id' in session:
#         last_activity = session.get('_last_activity')
#         if last_activity is not None and datetime.now(timezone.utc) - last_activity > app.permanent_session_lifetime:
#             # Session has timed out, clear the session
#             print("Session timed out. Clearing session for user:", session['user_id'])
#             session.clear()
#             return redirect(url_for('login'))
#     else:
#         print("No active session found.")

#     # Update the last activity time for the session
#     session['_last_activity'] = datetime.now(timezone.utc)
#     print("Session last activity updated:", session['_last_activity'])






def is_password_complex(password):
    # Check minimum length
    if len(password) < 12:
        return False
    
    # Check for at least one uppercase letter    
    if not re.search(r'[A-Z]', password):
        return False    
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    
    # Check for at least one digit    
    if not re.search(r'\d', password):
        return False
    
    # Check for at least one symbol
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    
    return True


def authenticate_user(username, password):
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    query = f"SELECT * FROM newusers WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return user
    return None

# Function to insert new user with encrypted password
def insert_new_user(username, password):
    encrypted_password = encrypt_password(password)
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    insert_query = "INSERT INTO newusers (username, password) VALUES (%s, %s)"
    cursor.execute(insert_query, (username, encrypted_password))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id


def get_user_data(user_id):
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    query = f"""
        SELECT *
        FROM user_accounts
        WHERE user_id = %s
    """
    print("Executing SQL query:", query)  # Print the SQL query being executed
    cursor.execute(query, (user_id,))
    user_data = cursor.fetchone()
    print("User data retrieved from database:", user_data)  # Print the data retrieved from the database
    conn.close()
    return user_data






@app.route('/user_details')
def user_details():
    if 'user_id' in session:
        user_id = session['user_id']
        # Assuming you have a function to fetch user-specific data from the database
        user_data = get_user_data(user_id)
        return render_template('user_details.html', user_data=user_data)
    else:
        return redirect(url_for('login'))



@app.route('/mainpage')
def mainpage():
    if 'user_id' in session:
        user_id = session['user_id']
        user_data = get_user_data(user_id)
        if user_data:
            return render_template('mainpage.html', username=user_data[2], account_number=user_data[3], balance=user_data[4])
        else:
            # Redirect the user to the signup_account route if their data is not found
            return redirect(url_for('signup_account'))
    else:
        return redirect(url_for('login'))
    







def validate_pin(pin):
    # Check if PIN is 4 digits
    if len(pin) != 4 or not pin.isdigit():
        return False
    return True





@app.route('/charge', methods=['POST'])
def charge():
    if request.method == 'POST':
        
        recipient_account_number = request.form['recipient_account_number']
        amount = float(request.form['amount'])  # Convert amount to float
        comment = request.form.get('comment', 'No comment') 
        user_id = session.get('user_id')  # Get user ID from session

        # Check if user is logged in
        if not user_id:
            return redirect(url_for('login'))  # Redirect if user is not logged in

        pin = request.form.get('pin', '')
        if not validate_pin(pin):
            pin_error_message = 'Invalid PIN. Please enter the correct PIN.'
            return render_template('transfer.html', pin_error_message=pin_error_message)

        # Connect to the database
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        try:
            # Check if the user has sufficient balance
            select_balance_query = "SELECT balance FROM user_accounts WHERE user_id = %s"
            cursor.execute(select_balance_query, (user_id,))
            user_balance = cursor.fetchone()[0]

            if user_balance < amount:
                error_message = "Insufficient balance."
                return render_template('transfer.html', error_message=error_message,  recipient_account_number=recipient_account_number, amount=amount, comment=comment)

            # Check if the recipient account exists
            check_recipient_query = "SELECT COUNT(*) FROM user_accounts WHERE account_number = %s"
            cursor.execute(check_recipient_query, (recipient_account_number,))
            recipient_exists = cursor.fetchone()[0]

            if not recipient_exists:
                error_message = "Recipient account number does not exist."
                return render_template('transfer.html', error_message=error_message, recipient_account_number=recipient_account_number, amount=amount, comment=comment)

            # Store transaction data in the database
            # Modify the query to retrieve the recipient's name
            select_recipient_query = "SELECT username FROM user_accounts WHERE account_number = %s"
            cursor.execute(select_recipient_query, (recipient_account_number,))
            recipient = cursor.fetchone()[0]

            # Store transaction data in the database
            insert_query = "INSERT INTO transactions (user_id, recipient_account_number, recipient, amount, comment) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(insert_query, (user_id, recipient_account_number, recipient, amount, comment))
            conn.commit()

            # Deduct the transferred amount from the sender's balance
            update_sender_balance_query = "UPDATE user_accounts SET balance = balance - %s WHERE user_id = %s"
            cursor.execute(update_sender_balance_query, (amount, user_id))
            conn.commit()

            # Add the transferred amount to the recipient's balance
            update_recipient_balance_query = "UPDATE user_accounts SET balance = balance + %s WHERE account_number = %s"
            cursor.execute(update_recipient_balance_query, (amount, recipient_account_number))
            conn.commit()

            # Close database connection
            conn.close()

            # Redirect to transfer details page
            return redirect(url_for('transfer_details', recipient=recipient, recipient_account_number=recipient_account_number, amount=amount, comment=comment))

        except Exception as e:
            # Handle any exceptions
            conn.rollback()  # Rollback transaction in case of any exception
            print("Error:", e)  # Print the exception details for debugging
            error_message = "An error occurred while processing the transaction. Please try again later."
            return render_template('transfer.html', error_message=error_message, pin_error_message=pin_error_message, recipient_account_number=recipient_account_number, amount=amount, comment=comment)

    else:
        return redirect(url_for('login'))

@app.route('/transfer_details')
def transfer_details():
    recipient = request.args.get('recipient')
    amount = request.args.get('amount')
    comment = request.args.get('comment')
    if not comment:
        comment = "No comment"
    return render_template('transfer_details.html', recipient=recipient, amount=amount, comment=comment)




# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Authenticate user
        user = authenticate_user(username, password)
        
        if user:
            # Store user ID in session
            session['user_id'] = user[0]
            print("User logged in. User ID:", user[0])  # Debug statement
            
            # Record login activity in the login table
            try:
                conn = pymysql.connect(**db_config)
                cursor = conn.cursor()
                login_insert_query = "INSERT INTO login (username, login_time) VALUES (%s, NOW())"
                cursor.execute(login_insert_query, (username,))
                conn.commit()
            except Exception as e:
                # Handle database errors
                print("Error inserting login record:", e)
            finally:
                conn.close()
            
            return redirect(url_for('mainpage'))
        else:
            error = "Invalid username or password. Please try again."
            return render_template('login.html', error=error)
    else:
        # Render the login form for GET requests
         return render_template('login.html')




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']  # Get email address from the form

        # Store the entered username to preserve it in case of errors
        entered_username = username

        # Check if the username and password combination already exists
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        query = f"SELECT * FROM newusers WHERE username = '{username}'"
        cursor.execute(query)
        existing_user = cursor.fetchone()

        # Check if email address is already registered
        check_email_query = "SELECT * FROM newusers WHERE email = %s"
        cursor.execute(check_email_query, (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            # If the username and password combination or email already exist, display the same error message
            error = "Account already exists. Please login."
            return render_template('login.html', error=error)
        

        if existing_user:
            # If the username and password combination or email already exist, display the same error message
            error = "Username already exists. Please login."
            return render_template('login.html', error=error)



        # Check password complexity, passwords match, and validate email format
        if not is_password_complex(password):
            error = 'Password is too weak. Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'
            return render_template('signup2.html', error_message=error, entered_username=entered_username)

        if password != confirm_password:
            error = 'Passwords do not match'
            return render_template('signup2.html', error_message=error, entered_username=entered_username)

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            error = 'Invalid email address format'
            return render_template('signup2.html', error_message=error, entered_username=entered_username)
        
        encrypted_password = encrypt_password(password)

        # Attempt insert query execution
        insert_query = "INSERT INTO newusers (username, password, confirm_password, email)  VALUES (%s,%s,%s,%s)"
            
        try:
            cursor.execute(insert_query, (username,encrypted_password,encrypted_password,email))
            conn.commit()

            # Fetch the user_id after successful insertion
            user_id_query = "SELECT id FROM newusers WHERE username = %s"
            cursor.execute(user_id_query, (username,))
            user_id = cursor.fetchone()[0]

            # Store user_id in session
            session['user_id'] = user_id

            return redirect(url_for('signup_account'))  # Redirect to signup_account route after successful insertion
        except Exception as e:
            conn.rollback()
            error = f"ERROR: Could not able to execute {insert_query}. {str(e)}"
            return render_template('signup2.html', error_message=error, entered_username=entered_username)
        finally:
            # Close connection
            conn.close()
    return render_template('signup2.html')



@app.route('/signup_account', methods=['GET', 'POST'])
def signup_account():
    if 'user_id' not in session:
        return redirect(url_for('signup'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        account_number = request.form.get('account_number', '')
        balance = request.form.get('balance', '')
        pin = request.form.get('pin', '')  # New PIN field
        
        error_message = None

        # Basic validation
        if not username or not account_number or not balance or not pin:
            error_message = "Please fill in all fields."
        elif len(account_number) != 8 or not account_number.isdigit():
            error_message = "Please enter a valid 8-digit account number."
            account_number = ''
        elif len(pin) != 4 or not pin.isdigit():
            error_message = "Please enter a valid 4-digit PIN."
            pin = ''
        else:
            try:
                # Encrypt the PIN using AES encryption
                encrypted_pin = encrypt_password(pin)
                
                # Check if the account number already exists in the database
                conn = pymysql.connect(**db_config)
                cursor = conn.cursor()
                check_query = "SELECT COUNT(*) FROM user_accounts WHERE account_number = %s"
                cursor.execute(check_query, (account_number,))
                count = cursor.fetchone()[0]
                
                cursor.execute("SELECT username FROM newusers WHERE id = %s", (session['user_id'],))
                fetched_username = cursor.fetchone()[0]

                if count > 0:
                    error_message = "Account number already exists. Please enter a different one."
                    account_number = ''
                elif username != fetched_username:
                    error_message = "Username and account holder name must be the same."
            except Exception as e:
                error_message = "An error occurred while processing the request. Please try again later."
                print("Error:", e)
            finally:
                if conn:
                    conn.close()
        
        if error_message:
            return render_template('user_details.html', error=error_message, username=username, account_number=account_number, balance=balance)
        
        # Insert data into the database
        try:
            conn = pymysql.connect(**db_config)
            cursor = conn.cursor()
            insert_query = "INSERT INTO user_accounts (user_id, username, account_number, balance, pin) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(insert_query, (session['user_id'], username, account_number, balance, encrypted_pin))
            conn.commit()
        except Exception as e:
            error_message = "An error occurred while processing the request. Please try again later."
            print("Error:", e)
        finally:
            if conn:
                conn.close()
        
        if error_message:
            return render_template('user_details.html', error=error_message, username=username, account_number=account_number, balance=balance)
        else:
            
            return render_template('login.html', successs_message='Account created successfully. Please log in.', username=username, account_number=account_number, balance=balance)

    else:
        return render_template('user_details.html')


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    # Check if the payee's name and account number are stored in the session
    if 'payee_name' in session and 'account_number' in session:
        payee_name = session['payee_name']
        account_number = session['account_number']
        return render_template('transfer.html', payee_name=payee_name, account_number=account_number)
    else:
        # If the payee's name and account number are not stored in the session, render the transfer page without pre-filling
        return render_template('transfer.html')


@app.route('/balance')
def balance():
    if 'user_id' in session:
        user_id = session['user_id']
        user_data = get_user_data(user_id)
        if user_data:
            balance = user_data[4]  # Assuming balance is stored in the 5th column
            return render_template('balance.html', balance=balance)
        else:
            return "User data not found."
    else:
        return redirect(url_for('login'))
    
@app.route('/history')
def history():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        select_query = "SELECT * FROM transactions WHERE user_id = %s ORDER BY timestamp DESC"
        cursor.execute(select_query, (user_id,))
        transactions = cursor.fetchall()
        conn.close()

        print("Transactions:", transactions)  # Print transactions for debugging

        return render_template('history.html', transactions=transactions)
    else:
        return redirect(url_for('login'))
    
from flask import render_template, request, session, jsonify

@app.route('/check_account', methods=['POST'])
def check_account():
    payee_name = request.form['payee_name']
    account_number = request.form['account_number']

    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()

    # Query the database to check if the account exists
    cursor.execute("SELECT * FROM user_accounts WHERE account_number = %s", (account_number,))
    account_exists = cursor.fetchone() is not None

    cursor.close()
    conn.close()

    if account_exists:
        # Store the payee name and account number in the session
        session['payee_name'] = payee_name
        session['account_number'] = account_number

    return jsonify({'account_exists': account_exists})

@app.route('/payees', methods=['GET', 'POST'])
def payees():
    return render_template('payees.html')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        old_password = request.form['old-password']
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-new-password']  # Corrected key name
        
        user_id = session.get('user_id')
        
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        
        # Retrieve the current password from the database
        # Check if the user_id exists in the database
        select_user_query = "SELECT id FROM newusers WHERE id = %s"
        cursor.execute(select_user_query, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return render_template('settings.html', error_message="old passowrd is incorrect")
        
        if new_password != confirm_password:
            conn.close()
            return render_template('settings.html', error_message="New password and confirm password do not match.")
        
        if old_password == new_password:
            conn.close()
            return render_template('settings.html', error_message="New password must be different from old password.")
        
        # Update the password and confirm password in the database
        update_password_query = "UPDATE newusers SET password = %s, confirm_password = %s WHERE id = %s"
        cursor.execute(update_password_query, (new_password, confirm_password, user_id))
        conn.commit()
        
        conn.close()
        
        # Render the settings page with a success message
        return render_template('settings.html', success_message="Your password has been changed successfully.")
        
    else:
        return render_template('settings.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/front')
def front():
      # Clear session data
    session.clear()
    # Flash a message to indicate successful logout
    flash('You have been logged out', 'success')
    # Redirect to the login page
    
    return render_template('front.html')

@app.route('/signup2')
def signup2():
    return render_template('signup2.html')






if __name__ == '__main__':
    app.run(debug=True)