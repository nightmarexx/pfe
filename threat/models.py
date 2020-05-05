from django.db import models
from django.contrib.auth.models import User


class Document(models.Model):
    docfile = models.FileField(upload_to='threat/media')


class Requete(models.Model):
    type = models.TextField()
    date = models.DateField()


class Apis(models.Model):
    name = models.TextField()
    url = models.TextField()
    key = models.TextField(null=True)
    url_test = models.TextField()
    status = models.BooleanField()
