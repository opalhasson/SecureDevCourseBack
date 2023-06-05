from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save

class ClientManager(models.Manager):
    def create_client(self, name, email, PhoneNumber):
        client = self.create(name=name, email=email, PhoneNumber=PhoneNumber)
        # Additional custom logic if needed
        return client


# Create your models here.
class PageView(models.Model):
    hostname = models.CharField(max_length=32)
    timestamp = models.DateTimeField(auto_now_add=True)

class Client(models.Model):
    name = models.CharField(max_length=30, null=True)
    email = models.EmailField(max_length=30, default="")
    PhoneNumber = models.CharField(max_length=10,default="")

    def __str__(self):
        return self.email



class UserProfile(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    numOfTry = models.IntegerField(default=0)

    def incNumOfTry(self):
        self.numOfTry += 1
        self.save()

    def zeroNumOfTry(self):
        self.numOfTry = 0
        self.save()
    #other fields here

    def _str_(self):
          return "%s's profile" % self.user





