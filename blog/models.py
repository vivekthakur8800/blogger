from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class post(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    title=models.CharField(max_length=200)
    disc=models.TextField()
    # def get_queryset(self):
    #         user=self.request.user
    #         return post.objects.filter(passby=user)

class contact(models.Model):
    name=models.CharField(max_length=50)
    email=models.EmailField()
    subject=models.CharField(max_length=100)
    message=models.TextField()