from django.urls import path
from django.conf.urls import url
from . import views
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

app_name = 'dashboard'

urlpatterns = [
        # dashboard views url
        path('', views.home_page, name='home_page'),
        path('external/', views.external, name='external'),
        path('nmap_visu/', views.nmap_visu, name='nmap_visu'),
        path('apropos/', views.apropos, name='apropos'),
        path('metasploit/', views.metasploit_visu, name='metasploit_visu'),
        path('crafter_exploit_port_based/', views.crafter_port_visu, name='crafter_port_visu'),
        path('crafter_exploit_dbdatabase_based/', views.crafter_version_visu, name='crafter_version_visu'),
        path('syn_flood_attack/', views.syn_flood_attack_visu, name='syn_flood_attack_visu'),
        path('blackhat_script_attack/', views.blackhat_attack_visu, name='blackhat_attack_visu')
        ]


