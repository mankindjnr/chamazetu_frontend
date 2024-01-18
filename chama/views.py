from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import requests
from decouple import config

# Create your views here.
def index(request):
    return render(request, 'chama/index.html')

def validate_token(request):
    try:
        jwt.decode(request.COOKIES.get('access_token').split(' ')[1], config('JWT_SECRET') , algorithms=['HS256'])
    except InvalidTokenError as e:
        return HttpResponseRedirect(reverse('membersignin'))


def memberdashboard(request):
    access_token = request.COOKIES.get('access_token')

    # local validation of token
    current_user = requests.get('https://sj76vr3h-9000.euw.devtunnels.ms/users/me', headers={'Authorization': access_token})

    if current_user.status_code == 200:
        return render(request, 'chama/dashboard.html', {'current_user': current_user.json()})
    else:
        return HttpResponseRedirect(reverse('membersignin'))

def profile(request):
    response = validate_token(request)
    if isinstance(response, HttpResponseRedirect):
        return response

    return render(request, 'chama/profile.html')

def membersignin(request):
    if request.method == "POST":
        data = {
            'username': request.POST['email'],
            'password': request.POST['password'],
        }

        response = requests.post('https://sj76vr3h-9000.euw.devtunnels.ms/users/login', data=data)

        if response.status_code == 200:
            access_token = response.json()['access_token']
            # successful login - store token - redirect to dashboard
            response = HttpResponseRedirect(reverse('memberdashboard'))
            response.set_cookie('access_token', f'Bearer {access_token}', secure=True, httponly=True, samesite='Strict')
            return response
        else:
            # unsuccessful login - redirect to login page
            return render(request, 'chama/memberLogin.html')

    return render(request, 'chama/memberLogin.html')

def managersignin(request):
    if request.method == "POST":
        data = {
            'username': request.POST['email'],
            'password': request.POST['password'],
        }

        response = requests.post('https://sj76vr3h-9000.euw.devtunnels.ms/users/login', data=data)

        if response.status_code == 200:
            access_token = response.json()['access_token']
            # successful login - store token - redirect to dashboard
            return render(request, 'chama/dashboard.html', {'access_token': access_token})
        else:
            # unsuccessful login - redirect to login page
            return render(request, 'chama/managerLogin.html')
    return render(request, 'chama/managerLogin.html')

def membersignup(request):
    return render(request, 'chama/membersignup.html')

def managersignup(request):
    return render(request, 'chama/managersignup.html')

def dashboard(request):
    return render(request, 'chama/dashboard.html')