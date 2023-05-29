from django.urls import path

from . import views

urlpatterns = [
    path("login/register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("change_pass/", views.change_pass, name="change_pass"),
    path("login/new_register/", views.new_register, name="new_register"),
    path("login/add_client/", views.add_client, name="add_client"),
    path("gen_otp/", views.gen_otp, name="gen_otp"),
    path("login/forgot_password/", views.forgot_password, name="forgot_password")
]
