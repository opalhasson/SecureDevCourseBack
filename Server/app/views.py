import secrets
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.http import HttpResponse
from django.contrib.auth.models import User
import hashlib
import hmac
from django.shortcuts import render
from django.contrib import messages
from .ClientForm import ClientForm
from .PasswordConfig import PasswordConfig

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
                username_login =  username._str__()
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
            username_login = username._str__()
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
        form = ClientForm(request.POST)
        if form.is_valid():
            form.save()
            return render(request, 'systemScreenPage.html')

    return render(request, 'addNewClientPage.html')


def gen_otp(request):
    return HttpResponse("Generate one-time password")


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('Password')
        try:
            user = User.objects.get(username=username_login)
        except User.DoesNotExist:
            # User with the provided email does not exist
            return HttpResponse('DoesNotExist')  # Redirect to the forgot password page

        # Generate a random value
        random_value = secrets.token_hex(16)

        # Store the random value in the user's model
        user.reset_token = hashlib.sha1(random_value.encode('utf-8')).hexdigest()
        user.save()

        # Send email to the user
        subject = 'Password Reset'
        message = f'Your password reset code: {random_value}'
        from_email = 'opalhasson@gmail.com'  # Replace with your email address
        to_email = 'opalhasson@gmail.com' #user.email

        send_mail(subject, message, from_email, [to_email])

        # Redirect to the password reset verification page
        return render(request, 'passwordChangePage.html')
    else:
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
