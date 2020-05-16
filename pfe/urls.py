"""pfe URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from threat import views
from django.contrib.auth.decorators import login_required,permission_required
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login_user', views.utilisateur.login_user),
    path('reset_password', views.utilisateur.reset_password),
    path('index', views.dashbord.index),
    path('add_user', views.utilisateur.add_user),
    path('delete_user/<int:id>', views.utilisateur.delete_user),
    path('edit_user/<int:id>', views.utilisateur.edit_user),
    path('update_user/<int:id>', views.utilisateur.update_user),
    path('logout_user', views.utilisateur.logout_user),
    path('display_user', views.utilisateur.display_user),
    path('listmalware', views.threat.listemalware),
    path('listdomain', views.threat.listedomain),
    path('listip', views.threat.listeip),
    path('listhash', views.threat.listehash),
    path('checkfile', views.threat.checkfile),
    path('checkdomain', views.threat.checkdomain),
    path('checkip', views.threat.checkip),
    path('checkhash', views.threat.checkhash),
    path('checkmail', views.threat.checkmail),
    path('display_api', views.api_service.listeapi),
    path('add_api', views.api_service.add_api),
    path('delete_api/<int:id>', views.api_service.delete_api),
    path('delete_api/<int:id>', views.api_service.delete_api),
    path('edit_api/<int:id>', views.api_service.edit_api),
    path('update_api/<int:id>', views.api_service.update_api),
    path('add_notif', views.notifications.add_notif),
    path('display_notif', views.notifications.display_notif),
    path('delete_notif/<int:id>', views.notifications.delete_notif),
    path('envoye_notif/<int:id>', views.notifications.envoye_notif),


]

urlpatterns += staticfiles_urlpatterns()
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

