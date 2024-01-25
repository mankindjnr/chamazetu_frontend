from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('signin', views.signin, name='signin'),
    path('managersignin', views.managersignin, name='managersignin'),
    path('membersignup', views.membersignup, name='membersignup'),
    path('managersignup', views.managersignup, name='managersignup'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('memberdashboard', views.memberdashboard, name='memberdashboard'),
    path('managerdashboard', views.managerdashboard, name='managerdashboard'),
    path('profile', views.profile, name='profile'),
]