from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('membersignin', views.membersignin, name='membersignin'),
    path('managersignin', views.managersignin, name='managersignin'),
    path('membersignup', views.membersignup, name='membersignup'),
    path('managersignup', views.managersignup, name='managersignup'),
    path('memberdashboard', views.memberdashboard, name='memberdashboard'),
    path('profile', views.profile, name='profile'),
    #path('memberdashboard', views.memberdashboard, name='memberdashboard'),
]