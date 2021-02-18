from django.urls import path
from django.conf.urls import url
from . import views

app_name = 'dashboard'

urlpatterns = [
        # post views
        path('', views.home_page, name='home_page'),
        path('external/', views.external, name='external'),
        path('nmap_visu/', views.nmap_visu, name='nmap_visu'),
        path('apropos/', views.apropos, name='apropos'),
        path('metasploit/', views.metasploit_visu, name='metasploit_visu')
        ]