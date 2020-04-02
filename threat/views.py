import json
import pulsedive
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
import requests
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render, redirect
from django.views import View
from honeydb import api
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes


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
    def listehash(request):
        url = "https://api.metadefender.com/v4/feed/infected/latest"
        headers = {
            'apikey': "4cfb6fa3cc775fafd692478b9b7cd11f"
        }
        response = requests.request("GET", url, headers=headers)
        re=response.json()
        return render(request, 'api/listhash.html', {'ind': re['hashes']})

    def listemalware(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.threat(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],category=['malware'], properties=None, attribute=None, splitrisk=False)
        return render(request, 'api/listmalware.html', {'ind': ind['results']})
    def listedomain(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.indicator(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],indicator_type=['url', 'domain'], lastseen=None, latest=None, limit=None, export=False, properties=None, attribute=None, feed=None, threat=None)
        return render(request, 'api/listdomain.html', {'ind': ind['results']})
    def listeip(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.indicator(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],indicator_type=['ip', 'ipv6'], lastseen=None, latest=None, limit=None, export=False, properties=None, attribute=None, feed=None, threat=None)
        return render(request, 'api/listip.html', {'ind': ind['results']})


    def checkfile(request):
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
    def checkdomain(request):
        if request.method == "POST":
            domain = request.POST.get('domain', False)
        otx = OTXv2("cee9c5f59ddad6f61aead25b961fb1ca6060bee6157137f95a868d5bb0c842e7")
        response = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain+'/http_scans')
        http_scan = response.json()
        if len(http_scan) == 1 :
            http_scan=None
        response2 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain+'/general')
        general = response2.json()
        response3 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain+'/url_list')
        url_list = response3.json()
        response4 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain+'/passive_dns')
        passive_dns = response4.json()
        response5 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain)
        infos = response5.json()
        return render(request, 'api/checkhostname.html', {'general': general, 'url_list': url_list['url_list'], 'passive_dns': passive_dns['passive_dns'], 'http_scan': http_scan, 'infos': infos['validation'], 'count': infos['pulse_info']})

    def checkip(request):
        if request.method == "POST":
            ip = request.POST.get('ip', False)
        otx = OTXv2("cee9c5f59ddad6f61aead25b961fb1ca6060bee6157137f95a868d5bb0c842e7")
        re = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        response = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/http_scans')
        http_scan = response.json()
        response2 = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/passive_dns')
        passive_dns = response2.json()
        response3 = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/malware')
        malware = response3.json()
        if len(http_scan) == 1 :
            http_scan=None
        return render(request, 'api/checkip.html', {'general': re['general'], 'url_list': re['url_list']['url_list'], 'passive_dns': passive_dns['passive_dns'], 'http_scan': http_scan['data'], 'malware': malware['data']})


    def checkhash(request):
        if request.method == "POST":
            hash = request.POST.get('hash', False)
        url = "https://api.metadefender.com/v4/hash/"+hash
        headers = {
            'apikey': "4cfb6fa3cc775fafd692478b9b7cd11f"
        }
        response = requests.request("GET", url, headers=headers)
        re=response.json()
        return render(request, 'api/checkhash.html', {'general': re, 'scan': re['scan_results']['scan_details']})















