from django.db import models
from django.contrib.auth.models import User
from django.utils.html import mark_safe
from markdown import markdown



class Document(models.Model):
    docfile = models.FileField(upload_to='threat/media')


class Requete(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.TextField()
    type = models.TextField()
    date = models.DateField()


class Apis(models.Model):
    name = models.TextField()
    url = models.TextField()
    key = models.TextField(null=True)
    url_test = models.TextField()
    status = models.BooleanField()


class Notification(models.Model):
    titre = models.TextField()
    message = models.TextField()
    status = models.BooleanField()

    def get_message_as_markdown(self):
        return mark_safe(markdown(self.message, safe_mode='escape'))
