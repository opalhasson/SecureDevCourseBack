from django.urls import path

from . import views

urlpatterns = [
    path("login/register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("change_pass/", views.change_pass, name="change_pass"),
    path("add_client/", views.add_client, name="add_client"),
    path("login/gen_otp/", views.gen_otp, name="gen_otp"),
    path("login/ver_otp/", views.ver_otp, name="ver_otp"),
    path("system/",views.system, name = "system"),
    path("client_list/", views.client_list, name="client_list")

]
