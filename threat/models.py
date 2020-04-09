from django.db import models
from django.contrib.auth.models import User


class Document(models.Model):
    docfile = models.FileField(upload_to='threat/media')


class Requete(models.Model):
    type = models.TextField()
    date = models.DateField()
