from django.urls import path
from . import views

app_name = 'scans'

urlpatterns = [
    path('search_domain_ip/', views.search, name='search'),
    path('search_file/', views.search_file, name='search_file'),
    path('', views.home, name='home'),
]