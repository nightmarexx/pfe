import json
import string
import random
import pulsedive
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import permission_required, login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
import requests
from django.core.files.storage import FileSystemStorage
from django.core.mail import EmailMessage
from django.shortcuts import render, redirect
from django.template.loader import get_template
from django.views import View
from .models import Requete, Apis, Notification
from honeydb import api
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import time
from datetime import date
from bs4 import BeautifulSoup
from virus_total_apis import PublicApi as VirusTotalPublicApi
import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException
import shutil

# Create your views here.


class utilisateur(View):
    @staticmethod
    def notification_mail():
        utilisateurs = User.objects.all()
    @staticmethod
    def get_random_alphaNumeric_string(stringLength=8):
        lettersAndDigits = string.ascii_letters + string.digits
        return ''.join((random.choice(lettersAndDigits) for i in range(stringLength)))
    def reset_password(request):
        utilisateurs = User.objects.all()
        if request.method == "POST":
            username = request.POST.get('reset', False)
            verif = 0
            for i in utilisateurs:
                if i == username:
                    verif = 1
            if verif == 1:
                user = User.objects.get(username=username)
                password = utilisateur.get_random_alphaNumeric_string(8)
                user.password = make_password(password, None, hasher='default')
                ctx = {
                'user': username, 'password': password
                }
                message = get_template('user/email-templete-password-reset.html').render(ctx)
                msg = EmailMessage(
                'Réinitialiser le mot de passe',
                message,
                'hedi.hamza@esprit.tn',
                [user.email],
                )
                msg.content_subtype = "html"  # Main content is now text/html
                msg.send()
                user.save()
            else:
                return redirect('/login_user')
            return render(request, 'user/login_user.html')

    def login_user(request):
        if request.method == "POST":
            username = request.POST.get('username', False)
            password = request.POST.get('password', False)
            user = authenticate(username=username, password=password)
            if user is not None and user.is_active:
                request.session["username"] = username;
                request.session["password"] = password;
                login(request, user)

                return redirect('/index')
            else:
                return render(request, 'user/login_user.html')

        return render(request, 'user/login_user.html')

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def display_user(request):
        liste = User.objects.all()
        return render(request, 'user/user_display.html', {'utilisateurs': liste})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def add_user(request):
        utilisateurs = User.objects.all()
        if request.method == "POST":
            nom = request.POST.get('firstName', False)
            prenom = request.POST.get('lastName', False)
            email = request.POST.get('emailAddress', False)
            pseudo = request.POST.get('pseudo', False)
            password = request.POST.get('pwd', False)
            type = request.POST.get('type', False)
            User.first_name = nom
            User.last_name = prenom
            User.is_active = False
            if ' ' in nom or ' ' in email or ' ' in pseudo or ' ' in password:
                return render(request, 'user/add_user.html', {'users': utilisateurs})
            else:
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
        return render(request, 'user/add_user.html', {'users': utilisateurs})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def delete_user(request, id):
        user = User.objects.get(id=id)
        user.delete()
        return redirect('/display_user')

    @login_required(login_url="/login_user")
    def edit_user(request, id):
        user2 = User.objects.get(id=id)
        utilisateurs = User.objects.all()
        return render(request, 'user/edit_user.html', {'user2': user2, 'users': utilisateurs})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def update_user(request, id):

        if request.method == "POST":
            user = User.objects.get(id=id)
            nom = request.POST.get('firstname', False)
            prenom = request.POST.get('lastname', False)
            email = request.POST.get('email', False)
            password = request.POST.get('password', False)
            type = request.POST.get('type', False)
            status = request.POST.get('status', False)

            user.first_name = nom
            user.last_name = prenom
            user.email = email
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
    @login_required(login_url="/login_user")
    def listehash(request):
        url = "https://api.metadefender.com/v4/feed/infected/latest"
        headers = {
            'apikey': "4cfb6fa3cc775fafd692478b9b7cd11f"
        }
        response = requests.request("GET", url, headers=headers)
        re = response.json()
        return render(request, 'services/listhash.html', {'ind': re['hashes']})

    @login_required(login_url="/login_user")
    def listemalware(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.threat(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],
                                category=['malware'], properties=None, attribute=None, splitrisk=False)
        return render(request, 'services/listmalware.html', {'ind': ind['results']})

    @login_required(login_url="/login_user")
    def listedomain(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.indicator(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],
                                   indicator_type=['url', 'domain'], lastseen=None, latest=None, limit=None,
                                   export=False, properties=None, attribute=None, feed=None, threat=None)
        return render(request, 'services/listdomain.html', {'ind': ind['results']})

    @login_required(login_url="/login_user")
    def listeip(request):
        pud = pulsedive.Pulsedive('1b0d0dcb40d124d4d91a40cb00f281527a84139d23d685e32fd18b28bb3e7013')
        ind = pud.search.indicator(risk=['unknown', 'none', 'low', 'medium', 'high', 'critical', 'retired'],
                                   indicator_type=['ip', 'ipv6'], lastseen=None, latest=None, limit='hundred',
                                   export=False, properties=None, attribute=None, feed=None, threat=None)
        return render(request, 'services/listip.html', {'ind': ind['results']})

    @login_required(login_url="/login_user")
    def checkfile(request):
        # Handle file upload
        if request.method == 'POST' and request.FILES['myfile']:
            user = User.objects.get(username=request.session["username"])
            myfile = request.FILES['myfile']
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            input_file = '/home/hedi/PycharmProjects/pfe/media/' + filename
            url1 = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params1 = {'apikey': 'c6c0f01017b99df69fc4062421dfe7ab8079adbdc6a3fcf5741aee9b060dec25'}
            files1 = {'file': (input_file, open(input_file, 'rb'))}
            response = requests.post(url1, files=files1, params=params1)
            ree1 = response.json()
            url2 = 'https://www.virustotal.com/vtapi/v2/file/report'
            params2 = {'apikey': 'dc1cfb1c11233bff41fd313b933889721b563f615e73cd3bd2f050df0d902fb5',
                       'resource': ree1['sha1']}
            response2 = requests.get(url2, params=params2)
            ree2 = response2.json()
            ree = response2.json()
            while ree2['response_code'] == -2 or ree['response_code'] == -2 or ree1['response_code'] == -2:
                ree2['response_code'] = 1
                response = requests.post(url1, files=files1, params=params1)
                ree1 = response.json()
                time.sleep(15)
                response3 = requests.get(url2, params=params2)
                ree = response3.json()
            req = Requete(type='file', date=date.today(), name=filename, user=user)
            req.save()
            return render(request, 'services/checkfile.html', {'ree': ree})
        return redirect('/display_user')

    @login_required(login_url="/login_user")
    def checkdomain(request):
        if request.method == "POST":
            domain = request.POST.get('domain', False)
            user = User.objects.get(username=request.session["username"])
        otx = OTXv2("cee9c5f59ddad6f61aead25b961fb1ca6060bee6157137f95a868d5bb0c842e7")
        response = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/' + domain + '/http_scans')
        http_scan = response.json()
        if len(http_scan) == 1:
            http_scan = None
        response2 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/' + domain + '/general')
        general = response2.json()
        response3 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/' + domain + '/url_list')
        url_list = response3.json()
        response4 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/' + domain + '/passive_dns')
        passive_dns = response4.json()
        response5 = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/' + domain)
        infos = response5.json()
        req = Requete(type='domain', date=date.today(), name=domain , user=user)
        req.save()
        return render(request, 'services/checkhostname.html',
                      {'general': general, 'url_list': url_list['url_list'], 'passive_dns': passive_dns['passive_dns'],
                       'http_scan': http_scan, 'infos': infos['validation'], 'count': infos['pulse_info']})

    @login_required(login_url="/login_user")
    def checkip(request):
        if request.method == "POST":
            ip = request.POST.get('ip', False)
            user = User.objects.get(username=request.session["username"])
        otx = OTXv2("cee9c5f59ddad6f61aead25b961fb1ca6060bee6157137f95a868d5bb0c842e7")
        re = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        response = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/http_scans')
        http_scan = response.json()
        response2 = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/passive_dns')
        passive_dns = response2.json()
        response3 = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/malware')
        malware = response3.json()
        if len(http_scan) == 1:
            http_scan = None
        req = Requete(type='ip', date=date.today(), name=ip, user=user)
        req.save()
        return render(request, 'services/checkip.html', {'general': re['general'], 'url_list': re['url_list']['url_list'],
                                                    'passive_dns': passive_dns['passive_dns'], 'http_scan': http_scan,
                                                    'malware': malware['data']})

    @login_required(login_url="/login_user")
    def checkhash(request):
        if request.method == "POST":
            hash = request.POST.get('hash', False)
            user = User.objects.get(username=request.session["username"])
        url = "https://api.metadefender.com/v4/hash/" + hash
        headers = {'apikey': "4cfb6fa3cc775fafd692478b9b7cd11f"}
        response = requests.request("GET", url, headers=headers)
        re = response.json()
        req = Requete(type='hash', date=date.today(), name=hash, user=user)
        req.save()
        return render(request, 'services/checkhash.html', {'general': re, 'scan': re['scan_results']['scan_details']})

    @login_required(login_url="/login_user")
    def checkmail(request):
        if request.method == "POST":
            mail = request.POST.get('mail', False)
            user = User.objects.get(username=request.session["username"])
        url = "https://api.apility.net/bademail/" + mail
        headers = {
            'accept': "application/json",
            'x-auth-token': "f7c0683d-2acc-48b1-a1ff-7260d3c8eb25"
        }
        response = requests.request("GET", url, headers=headers)
        re = response.json()
        req = Requete(type='mail', date=date.today(), name=mail, user=user)
        req.save()
        return render(request, 'services/checkmail.html', {'general': re['response']})


class dashbord(View):
    @login_required(login_url="/login_user")
    def index(request):
        url2 = 'https://igotphished.abuse.ch/'
        response2 = requests.get(url2)
        soup2 = BeautifulSoup(response2.text, "html.parser")
        ree = soup2.find(class_='card-deck')
        ree2 = ree.find_all('h5')
        mal1 = ree2[1].contents[0]
        url6 = 'https://sslbl.abuse.ch/statistics/'
        response6 = requests.get(url6)
        soup6 = BeautifulSoup(response6.text, "html.parser")
        ree6 = soup6.find(class_='row')
        ree7 = ree6.find_all('p')
        mal2 = ree7[1].contents[0]
        url3 = 'https://urlhaus.abuse.ch/statistics/'
        response3 = requests.get(url3)
        soup3 = BeautifulSoup(response3.text, "html.parser")
        ree2 = soup3.find(class_='row')
        ree3 = ree2.find_all('p')
        mal3 = ree3[0].contents[0]
        url4 = 'https://feodotracker.abuse.ch/statistics/'
        response4 = requests.get(url4)
        soup4 = BeautifulSoup(response4.text, "html.parser")
        ree4 = soup4.find(class_='row')
        ree5 = ree4.find_all('p')
        mal4 = ree5[0].contents[0]
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        response = requests.request("GET", url)
        re = response.json()

        if re['query_status'] == 'no_results':
            malware = None
        else:
            malware = re['urls'][0:12]
        honeydb = api.Client('3db6f7b66c3d69f881d51f99c7447a335c0183caded44ae799d6e56ce85d934b',
                             'c95af819d97737589a754bf9f6d76c0a68f9514bd052a58493d62944e75a6788')
        services = honeydb.services()
        ree = honeydb.bad_hosts()
        service = services[0:8]
        host = ree[0:8]
        req = Requete.objects.all()
        domain = Requete.objects.all().filter(type='domain')
        ip = Requete.objects.all().filter(type='ip')
        hash = Requete.objects.all().filter(type='hash')
        file = Requete.objects.all().filter(type='file')
        mail = Requete.objects.all().filter(type='mail')
        total = len(req)
        moyd = len(domain)
        moyi = len(ip)
        moyh = len(hash)
        moyf = len(file)
        moym = len(mail)
        history = Requete.objects.all()

        return render(request, 'api/index.html',
                      {'mal1': mal1, 'mal2': mal2, 'mal3': mal3, 'mal4': mal4, 'malware': malware, 'services': services,
                       'service': service, 'host': host, 'total': total, 'domain': moyd, 'ip': moyi, 'hash': moyh,
                       'file': moyf, 'mail': moym, 'history': history[len(history)-5:len(history)]})


class api_service(View):
    @staticmethod
    def tests():
        list = Apis.objects.all()
        for i in list:
            if i.url_test[0:4] == 'http':
                response = requests.request("GET", i.url_test)
                if response is None:
                    i.status = 0
                    i.save()
                else:
                    i.status = 1
                    i.save()
            else:
                i.status = 0
                i.save()


    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def listeapi(request):
        api_service.tests()
        list = Apis.objects.all()
        return render(request, 'api/liste_api.html', {'list': list})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def add_api(request):
        if request.method == "POST":
            nom = request.POST.get('nom', False)
            url = request.POST.get('url', False)
            key = request.POST.get('key', False)
            url_test = request.POST.get('url_test', False)
            api1 = Apis(name=nom, url=url, key=key, url_test=url_test, status=True)
            api1.save()
            return redirect('/display_api')
        return render(request, 'api/add_api.html')

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def delete_api(request,id):
        api2 = Apis.objects.get(id=id)
        api2.delete()
        return redirect('/display_api')

    @login_required(login_url="/login_user")
    def edit_api(request, id):
        api2 = Apis.objects.get(id=id)
        return render(request, 'api/edit_api.html', {'api2': api2})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def update_api(request, id):
        if request.method == "POST":
            api2 = Apis.objects.get(id=id)
            nom = request.POST.get('nom', False)
            url = request.POST.get('url', False)
            key = request.POST.get('key', False)
            url_test = request.POST.get('url_test', False)
            api2.name = nom
            api2.url = url
            api2.url_test = url_test
            api2.key = key
            api2.save()
        return redirect('/display_api')

class notifications(View):
    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def add_notif(request):
        if request.method == "POST":
            message = request.POST.get('demo1', False)
            titre = request.POST.get('titre', False)
            notif = Notification(titre=titre, message=message, status=False)
            notif.save()
            return redirect('/display_notif')
        return render(request, 'notifications/add_notif.html')

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def display_notif(request):
        list = Notification.objects.all()
        return render(request, 'notifications/liste_notif.html', {'list': list})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def envoye_notif(request,id):
        notif = Notification.objects.get(id=id)
        list = User.objects.all().filter(is_staff=False)
        for i in list:
            ctx = {
                'titre': notif.titre, 'message': notif.message, 'user': i.username
            }
            message = get_template('notifications/notifications.html').render(ctx)
            msg = EmailMessage(
                'EY Threat Intelligence',
                message,
                'hedi.hamza@esprit.tn',
                [i.email],
            )
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()
        notif.status = True
        notif.save()
        return redirect('/display_notif')

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def delete_notif(request,id):
        notif = Notification.objects.get(id=id)
        notif.delete()
        return redirect('/display_notif')

    @login_required(login_url="/login_user")
    def edit_notif(request, id):
        notif = Notification.objects.get(id=id)
        return render(request, 'notifications/edit_notif.html', {'notif': notif})

    @login_required(login_url="/login_user")
    @permission_required('is_superuser', login_url="/index")
    def update_notif(request, id):
        if request.method == "POST":
            notif = Notification.objects.get(id=id)
            message = request.POST.get('demo1', False)
            titre = request.POST.get('titre', False)
            notif.titre = titre
            notif.message = message
            notif.save()
        return redirect('/display_notif')







