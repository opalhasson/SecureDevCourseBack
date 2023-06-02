from django.db import models

# Create your models here.
class PageView(models.Model):
    hostname = models.CharField(max_length=32)
    timestamp = models.DateTimeField(auto_now_add=True)

class Client(models.Model):
    name = models.CharField(max_length=30)

    def __str__(self):
        return self.name
# user = models.OneToOneField(User, on_delete=models.CASCADE)
    # name = models.CharField(max_length=100)
    # email = models.EmailField()
    # phone_number = models.CharField(max_length=20)