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

username_login = ""


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

            User.objects.create_user(username=username, email=email, password=hashed_password)

            if User.objects.get_by_natural_key(username) is not None:
                # Optionally, you can perform additional actions with the created user
                username_login = username.__str__()
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
            username_login = username.__str__()
            # User is authenticated, log them in
            return render(request, 'systemScreenPage.html')
        else:
            # Authentication failed
            messages.error(request, 'Invalid username or password.')
        # Render the login page
    return render(request, 'loginPage.html')


def change_pass(request):
    return render(request, 'passwordChangePage.html')


def add_client(request):
    if request.method == 'POST':
        form = 1  # ClientForm(request.POST)
        if form.is_valid():
            form.save()
            return render(request, 'systemScreenPage.html')

    return render(request, 'addNewClientPage.html')


def gen_otp(request):
    return HttpResponse("Generate one-time password")


# def forgot_password(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('Password')
#         try:
#             user = User.objects.get(username=username_login)
#         except User.DoesNotExist:
#             # User with the provided email does not exist
#             return HttpResponse('DoesNotExist')  # Redirect to the forgot password page
#
#         # Generate a random value
#         random_value = secrets.token_hex(16)
#
#         # Store the random value in the user's model
#         user.reset_token = hashlib.sha1(random_value.encode('utf-8')).hexdigest()
#         user.save()
#
#         # Send email to the user
#         subject = 'Password Reset'
#         message = f'Your password reset code: {random_value}'
#         from_email = 'opalhasson@gmail.com'  # Replace with your email address
#         to_email = 'opalhasson@gmail.com' #user.email
#
#         send_mail(subject, message, from_email, [to_email])
#
#         # Redirect to the password reset verification page
#         return render(request, 'passwordChangePage.html')
#     else:
#         return render(request, 'passwordForgetPage.html')


# Function to generate OTP
def generate_otp():
    digits = "0123456789"
    OTP = ""

    for _ in range(6):
        OTP += random.choice(digits)

    return OTP


import smtplib
import random

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# Function to generate OTP
def generate_otp():
    digits = "0123456789"
    OTP = ""

    for _ in range(6):
        OTP += random.choice(digits)

    return OTP


def forgot_password(request):
    SMTP_HOST = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USERNAME = 'opalhasson'
    SMTP_PASSWORD = '18opal18'

    # Sender and Receiver details
    SENDER_EMAIL = 'your_email@gmail.com'
    RECEIVER_EMAIL = 'recipient_email@gmail.com'

    # Generate OTP
    otp = generate_otp()

    # Email content
    message = MIMEMultipart()
    message['From'] = SENDER_EMAIL
    message['To'] = RECEIVER_EMAIL
    message['Subject'] = 'Your OTP'

    message.attach(MIMEText(f'Your OTP is: {otp}', 'plain'))

    # Create SMTP session
    session = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    session.starttls()
    session.login(SMTP_USERNAME, SMTP_PASSWORD)

    # Send email
    session.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, message.as_string())
    session.quit()

    print('OTP sent successfully!')


# View for generating OTP and sending email
def forgot_password12(request):
    print(request.method)
    print(request)
    if request.method == 'POST':
        email = request.POST.get('email')
        print("opal")
        print(email)

        # Generate OTP
        otp = generate_otp()

        # Email content
        message = f'Your OTP is: {otp}'
        email_subject = 'Your OTP'
        email_sender = settings.EMAIL_HOST_USER
        email_receiver = email

        # Send email
        Email = EmailMessage(email_subject, message, email_sender, [email_receiver])
        print(Email)
        Email.send()

        # Render the template with OTP input form
        return render(request, 'passwordChangePage.html', {'email': email})

    # Render the template with the email input form
    return render(request, 'passwordForgetPage.html')


def new_register(request):
    return render(request, 'newRegisterPage.html')


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
