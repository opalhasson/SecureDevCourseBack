from django.contrib import admin
from .models import Client, UserProfile


class ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'PhoneNumber')

admin.site.register(Client, ClientAdmin)
admin.site.register(UserProfile)
