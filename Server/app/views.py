import secrets
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.http import HttpResponse
from django.contrib.auth.models import User
import hashlib
import hmac
import smtplib
from django.shortcuts import render
from django.contrib import messages
from .PasswordConfig import PasswordConfig
import random
from django.shortcuts import render
from django.core.mail import EmailMessage
from django.conf import settings
import smtplib
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from .models import Client, UserProfile
from django.contrib.auth import login as django_login

username_login = ""
user_otp = ""

def username(username):
    global username_login
    username_login = username

def getusername():
    return username_login

def userOTP(OTP):
    global user_otp
    user_otp = OTP

def getUserOTP():
    return user_otp


def system(request):
    return render(request, 'systemScreenPage.html')

def register(request):
    if request.method == 'POST':
        username = request.POST.get('UserName')
        email = request.POST.get('email')
        password = request.POST.get('Password')

        pc = PasswordConfig
        password_response = register_user(pc, password)

        # Create a new user
        if password_response == "":
            # Hash password with HMAC + Salt
            salt = hmac.new(b'secret_key', username.encode('utf-8'), hashlib.sha256).hexdigest().encode('utf-8')
            hashed_password = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).hexdigest()

            user = User.objects.create_user(username=username, email=email, password=hashed_password)

            if User.objects.get_by_natural_key(username) is not None:
                # Optionally, you can perform additional actions with the created user
                profile = UserProfile(user = username,numOfTry = 0)
                profile.save()
                return render(request, 'systemScreenPage.html')
            else:
                return HttpResponse("Invalid request method")
        else:
            messages.error(request, password_response)

        # Render the login page
    return render(request, 'newRegisterPage.html')

def login(request):
    if request.method == 'POST':
        username = request.POST.get('UserName')
        password = request.POST.get('Password')

        # Perform authentication
        user = authenticate(request, username=username, password=password)

        if user is not None:
            print(user)
            django_login(request, user)
            # User is authenticated, log them in
            user_profile, _ = UserProfile.objects.get_or_create(user=user)
            user_profile.zeroNumOfTry()  # Reset the number of login attempts using the instance method
            return render(request, 'systemScreenPage.html')
        else:
            try:
                user_profile = UserProfile.objects.get(user=username)
                user_profile.incNumOfTry()  # Increase the number of login attempts using the instance method

                if user_profile.getNumOfTry() > PasswordConfig.HISTORY:
                    # Maximum login attempts exceeded
                    messages.error(request, 'Maximum login attempts exceeded. Please try again later.')
                    return render(request, 'loginPage.html')  # Redirect back to the login page

                else:
                    # Authentication failed
                    messages.error(request, 'Invalid username or password,please try again.')
            except UserProfile.DoesNotExist:
              # Authentication failed
              messages.error(request, 'Invalid username or password - check out user or password.')

    # Render the login page
    return render(request, 'loginPage.html')

def change_pass(request):
    if request.method == 'POST':

        new_password = request.POST.get('newPassword')

        user = request.user

        user.set_password(new_password)
        user.save()
        messages.error(request, 'Password changed successfully.')

    return render(request, 'passwordChangePage.html')

def add_client(request):
    if request.method == 'POST':
        ClientName = request.POST.get('ClientName')
        email = request.POST.get('email')
        PhoneNumber = request.POST.get('PhoneNumber')
        client = None
        try:
            client = Client.objects.get(email=email)
            # Handle the case when a matching client is found
            # For example, you can update the existing client or display a message
        except Client.DoesNotExist:
            # Handle the case when no matching client is found
            client = Client.objects.create(name=ClientName, email=email, PhoneNumber=PhoneNumber)

        if client is not None:
            # Optionally, you can perform additional actions with the created user
            return render(request, 'systemScreenPage.html')
        else:
            return messages.error(request, 'Client allready exist !')

    return render(request, 'addNewClientPage.html')

def add_client_safe(request):
    if request.method == 'POST':
        ClientName = escape(request.POST.get('ClientName'))
        email = escape(request.POST.get('email'))
        PhoneNumber = escape(request.POST.get('PhoneNumber'))
        client = None
        try:
            client = Client.objects.get(email=email)
            # Handle the case when a matching client is found
            # For example, you can update the existing client or display a message
        except Client.DoesNotExist:
            # Handle the case when no matching client is found
            client = Client.objects.create(name=ClientName, email=email, PhoneNumber=PhoneNumber)

        if client is not None:
            # Optionally, you can perform additional actions with the created user
            return render(request, 'systemScreenPage.html')
        else:
            return messages.error(request, 'Client already exists!')

    return render(request, 'addNewClientPage.html')

def login_safe(request):
    if request.method == 'POST':
        username = request.POST.get('UserName')
        password = request.POST.get('Password')

        # Perform authentication
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # User is authenticated, log them in
            user_profile, _ = UserProfile.objects.get_or_create(user=user)
            user_profile.zeroNumOfTry()  # Reset the number of login attempts using the instance method
            return render(request, 'systemScreenPage.html')
        else:
            try:
                user_profile = UserProfile.objects.get(user__username=username)  # Using the correct field name
                user_profile.incNumOfTry()  # Increase the number of login attempts using the instance method

                if user_profile.getNumOfTry() > PasswordConfig.HISTORY:
                    # Maximum login attempts exceeded
                    messages.error(request, 'Maximum login attempts exceeded. Please try again later.')
                    return render(request, 'loginPage.html')  # Redirect back to the login page

                else:
                    # Authentication failed
                    messages.error(request, 'Invalid username or password,please try again.')
            except UserProfile.DoesNotExist:
                # Authentication failed
                messages.error(request, 'Invalid username or password - check out user or password.')

    # Render the login page
    return render(request, 'loginPage.html')


def client_list(request):
    clients = Client.objects.all()
    return render(request, 'listOfclientsPage.html', {'clients': clients})

def gen_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # User with the provided email does not exist
            return HttpResponse('DoesNotExist')  # Redirect to the forgot password page

        # Generate a random value
        random_value = secrets.token_hex(16)
        username(user.username)
        # Store the random value in the user's model
        user.reset_token = hashlib.sha1(random_value.encode('utf-8')).hexdigest()
        user.save()
        userOTP(random_value)
        # Provide your email credentials and details
        sender_email = "comunicationltd@outlook.co.il"
        sender_password = "Opal#Daniel#Liran2023"
        subject = "TOKEN"
        message = "The Token is " + random_value

        # Create a multipart message
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = email
        msg["Subject"] = subject

        # Add body to the email
        msg.attach(MIMEText(message, "plain"))

        # Setup the SMTP server
        smtp_server = "smtp-mail.outlook.com"
        smtp_port = 587

        try:
            # Create a secure SSL/TLS connection with the SMTP server
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)

            # Send the email
            server.sendmail(sender_email, email, msg.as_string())

            print("Email sent successfully!")
        except Exception as e:
            print("Error sending email:", str(e))
        finally:
            # Close the SMTP server connection
            server.quit()

        # Redirect to the password reset verification page
        return render(request, 'verOTPPage.html')
    else:
        return render(request, 'genOTPPage.html')

def ver_otp(request):
    if request.method == 'POST':
        OTP = request.POST.get('OTP')
        user_OTP = getUserOTP()

        # Perform authentication

        if OTP == user_OTP:
            # User is authenticated, log them in
            return render(request, 'passwordChangePage.html')
        else:
            # Authentication failed
            messages.error(request, 'Invalid OTP.')
        # Render the login page
    return render(request, 'verOTPPage.html')

def register_user(self, password):
    if len(password) < self.PASS_MIN_LENGTH:
        return "Password too short"

    if not any(char.isdigit() for char in password):
        return "Password must contain at least one digit"

    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter"

    if not any(char.islower() for char in password):
        return "Password must contain at least one lowercase letter"

    if not any(char in password for char in "!@#$%^&*()"):
        return "Password must contain at least one special character"

    return ""


