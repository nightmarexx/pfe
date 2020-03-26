import json
import pulsedive
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.views import View
from honeydb import api



import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException


# Create your views here.



class utilisateur(View):

    def login_user(request):
        if request.method == "POST":
            username = request.POST.get('username', False)
            password = request.POST.get('password', False)
            user = authenticate(username=username, password=password)
            if user is not None and user.is_active:
                request.session["username"] = username;
                request.session["password"] = password;
                login(request, user)

                return redirect('/display_user')
            else:
                return render(request, 'user/login_user.html')

        return render(request, 'user/login_user.html')

    def index(request):
        return render(request, 'index.html')

    def display_user(request):
        liste = User.objects.all()
        return render(request, 'user/user_display.html', {'utilisateurs': liste})

    def add_user(request):
        if request.method == "POST":
            nom = request.POST.get('firstName', False)
            prenom = request.POST.get('lastName', False)
            email = request.POST.get('emailAddress', False)
            pseudo = request.POST.get('pseudo', False)
            password = request.POST.get('password', False)
            type = request.POST.get('type', False)
            User.first_name = nom
            User.last_name = prenom
            User.is_active = False

            if type == "SuperUser":
                User.objects.create_superuser(pseudo, email, password)
                user = User.objects.get(username=pseudo)
                user.first_name = nom
                user.last_name = prenom
                user.save()
                return redirect('/display_user')
            else:
                User.objects.create_user(pseudo, email, password)
                user = User.objects.get(username=pseudo)
                user.first_name = nom
                user.last_name = prenom
                user.save()
                return redirect('/display_user')
        return render(request, 'user/add_user.html')

    def delete_user(request, id):
        user = User.objects.get(id=id)
        user.delete()
        return redirect('/display_user')

    def edit_user(request, id):
        user2 = User.objects.get(id=id)
        return render(request, 'user/edit_user.html', {'user2': user2})

    def update_user(request, id):

        if request.method == "POST":
            user = User.objects.get(id=id)
            nom = request.POST.get('firstname', False)
            prenom = request.POST.get('lastname', False)
            email = request.POST.get('email', False)
            pseudo = request.POST.get('username', False)
            password = request.POST.get('password', False)
            type = request.POST.get('type', False)
            status = request.POST.get('status', False)

            user.first_name = nom
            user.last_name = prenom
            user.email = email
            user.username = pseudo
            if status == 'Active':
                user.is_active = True
            elif status == 'Bloqué':
                user.is_active = False

            if password != '':
                user.password = make_password(password, None, hasher='default')

            if user.is_superuser == 1:
                type2 = 'Superuser'
            else:
                type2 = 'Staff'
            if type != type2:
                if type == 'SuperUser':
                    user.is_superuser = True
                    user.is_staff = True
                    user.save()
                    return redirect('/display_user')
                else:
                    user.is_superuser = False
                    user.is_staff = False
                    user.save()
                    return redirect('/display_user')
            user.save()
            return redirect('/display_user')

    def logout_user(request):
        logout(request)
        return redirect('/login_user')

class threat(View):
    def listefeed(request):
        with open('/home/hedi/Téléchargements/pfe/pfe/threat/static/feed.json') as json_data:
            data_dict = json.load(json_data)

        return render(request, 'api/listfeed.html', {'ind': data_dict})
    def listeattack(request):
        honeydb = api.Client('3db6f7b66c3d69f881d51f99c7447a335c0183caded44ae799d6e56ce85d934b','c95af819d97737589a754bf9f6d76c0a68f9514bd052a58493d62944e75a6788')
        print(honeydb.bad_hosts())
        honeydb.netinfo_lookup()
        return render(request, 'api/listattack.html')
    def listethreat(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.threat(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],category=['general', 'abuse', 'apt', 'attack', 'botnet', 'crime', 'exploitkit', 'fraud', 'group', 'malware', 'proxy', 'pup', 'reconnaissance', 'spam', 'terrorism', 'phishing', 'vulnerability'], properties=None, attribute=None, splitrisk=False)
        return render(request, 'api/listthreat.html', {'ind': ind['results']})


    def uploadfile(request):
        # Handle file upload
        if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            configuration = cloudmersive_virus_api_client.Configuration()
            configuration.api_key['Apikey'] = 'd2af0df3-5d75-41b0-bb4c-1d75851dbbd1'

            # create an instance of the API class
            api_instance = cloudmersive_virus_api_client.ScanApi(cloudmersive_virus_api_client.ApiClient(configuration))
            input_file = '/home/hedi/Téléchargements/pfe/pfe/media/'+filename

            api_response = api_instance.scan_file(input_file)
            return render(request, 'api/resultatfile.html', {
                'rep': api_response
            })
        return render(request, 'api/scanfile.html')














