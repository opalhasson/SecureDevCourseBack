from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import Client

# class ClientInline(admin.StackedInline):
#     model = Client
#     can_delete = False
#     verbose_name_plural = 'Client'

# class CustomUserAdmin(UserAdmin):
#     inlines = (ClientInline,)

#admin.site.unregister(User)
admin.site.register(Client)
