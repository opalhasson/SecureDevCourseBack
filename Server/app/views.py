import os

from django.contrib.auth import authenticate
from django.core.checks import database
from django.http import HttpResponse
from django.contrib.auth.models import User
import hashlib
import hmac
from django.shortcuts import render

from .PasswordConfig import PasswordConfig


def register(request):
    if request.method == 'POST':
        username = request.POST.get('UserName')
        email = request.POST.get('email')
        password = request.POST.get('Password')

        pc = PasswordConfig
        #import Password Config == self
        hashed_password = register_user(pc, username, password)
        print(username)
        print(email)
        print(hashed_password)

        # Create a new user
        User.objects.create_user(username=username, email=email, password=hashed_password)
        if User.objects.get_by_natural_key(username) is not None:
            # Optionally, you can perform additional actions with the created user
            return HttpResponse("User registered successfully")
        else:
            return HttpResponse("Invalid request method -opal")

        # Render the login page
    return render(request, 'newRegisterPage.html')

def login(request):
    # return HttpResponse("Login")
    if request.method == 'POST':
        username = request.POST.get('UserName')
        password = request.POST.get('Password')
        print(username + " " + password)
        # Perform authentication
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # User is authenticated, log them in
            login(request, user)
            return HttpResponse("User logged in successfully")
        else:
            # Authentication failed
            return HttpResponse("Invalid username or password")

        # Render the login page
    return render(request, 'loginPage.html')

def change_pass(request):
    return render(request, 'passwordChangePage.html')
    #return HttpResponse("Change pass")

def add_client(request):
    return HttpResponse("Add new client")


def gen_otp(request):
    return HttpResponse("Generate one-time password")


def verify_otp(request):
    return render(request, 'passwordForgetPage.html')
    #return HttpResponse("Verify one-time password")


def register_user(self, username, password):
    if len(password) < self.PASS_MIN_LENGTH:
        return "Password too short"  # I want to throw exption

    if not any(char.isdigit() for char in password):
        return "Password must contain at least one digit"

    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter"

    if not any(char.islower() for char in password):
        return "Password must contain at least one lowercase letter"

    if not all(char.isalnum() for char in password):
        return "Password must only contain alphanumeric characters"

    if self.password_requirement == 'strict':
        if not any(char in password for char in "!@#$%^&*()"):
            return "Password must contain at least one special character"

    # Hash password with HMAC + Salt
    salt = hmac.new(b'secret_key', username.encode('utf-8'), hashlib.sha256).hexdigest().encode('utf-8')
    hashed_password = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).hexdigest()
    return hashed_password
