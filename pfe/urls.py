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
from django.urls import path , re_path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from threat import views
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path('login_user',views.utilisateur.login_user),
    path('index',login_required(views.utilisateur.index)),
    path('add_user',login_required(views.utilisateur.add_user)),
    path('delete_user/<int:id>', login_required(views.utilisateur.delete_user)),
    path('edit_user/<int:id>', login_required(views.utilisateur.edit_user)),
    path('update_user/<int:id>', login_required(views.utilisateur.update_user)),
    path('logout_user',login_required(views.utilisateur.logout_user)),
    path('display_user',login_required(views.utilisateur.display_user)),
    path('listmalware',login_required(views.threat.listemalware)),
    path('listdomain',login_required(views.threat.listedomain)),
    path('listip',login_required(views.threat.listeip)),
    path('listhash',login_required(views.threat.listehash)),
    path('checkfile',login_required(views.threat.checkfile)),
    path('checkdomain',login_required(views.threat.checkdomain)),
    path('checkip',login_required(views.threat.checkip)),
    path('checkhash',login_required(views.threat.checkhash)),

]
urlpatterns += staticfiles_urlpatterns()
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

