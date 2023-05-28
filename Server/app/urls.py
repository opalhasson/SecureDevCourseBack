from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("change_pass/", views.change_pass, name="change_pass"),
    path("add_client/", views.add_client, name="add_client"),
    path("gen_otp/", views.gen_otp, name="gen_otp"),
    path("verify_otp/", views.verify_otp, name="verify_otp"),
]
