from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
import jwt
import json
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

def refresh_token(request):
    try:
        refresh_token = request.COOKIES.get('refresh_token').split(' ')[1]
        decoded_token = jwt.decode(refresh_token, config('JWT_SECRET'), algorithms=['HS256'])
        # If the refresh token is valid, generate a new access token
        email_claim = decoded_token.get('sub')
        data = {
            'username': email_claim,
        }

        headers = {'Content-type': 'application/json'}
        refresh_access = requests.post('https://sj76vr3h-9400.euw.devtunnels.ms/users/refresh', data=json.dumps(data), headers=headers)
        refresh_data = refresh_access.json()
        new_access_token = refresh_data['new_access_token']
        response = HttpResponse("Access token refreshed")
        response.set_cookie('access_token', new_access_token)
        return response
    except (InvalidTokenError, ExpiredSignatureError) as e:
        return HttpResponseRedirect(reverse('membersignin'))


def memberdashboard(request):
    access_token = request.COOKIES.get('access_token')

    # backend validation of token
    current_user = request.COOKIES.get('current_user')
    response = validate_token(request)
    if isinstance(response, HttpResponseRedirect):
        refreshed_response = refresh_token(request)
        if isinstance(refreshed_response, HttpResponseRedirect):
            return refreshed_response

    return render(request, 'chama/dashboard.html', {'current_user': current_user})

def profile(request):
    response = validate_token(request)
    if isinstance(response, HttpResponseRedirect):
        refreshed_response = refresh_token(request)
        if isinstance(refreshed_response, HttpResponseRedirect):
            return refreshed_response

    return render(request, 'chama/profile.html')

def membersignin(request):
    if request.method == "POST":
        data = {
            'username': request.POST['email'],
            'password': request.POST['password'],
        }

        response = requests.post('https://sj76vr3h-9400.euw.devtunnels.ms/users/login', data=data)

        if response.status_code == 200:
            access_token = response.json()['access_token']
            refresh_token = response.json()['refresh_token']
            current_user = request.POST['email']
            print("-------------initial token-----------------")
            print(access_token)

            # successful login - store token - redirect to dashboard
            response = HttpResponseRedirect(reverse('memberdashboard'))
            response.set_cookie('current_user', current_user, secure=True, httponly=True, samesite='Strict')
            response.set_cookie('access_token', f'Bearer {access_token}', secure=True, httponly=True, samesite='Strict')
            response.set_cookie('refresh_token', f'Bearer {refresh_token}', secure=True, httponly=True, samesite='Strict')
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

        response = requests.post('https://sj76vr3h-9400.euw.devtunnels.ms/users/login', data=data)

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