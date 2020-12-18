from django.shortcuts import render
from itertools import chain
from .models import DomainIpScan, CommunicatingFile, ReferringFile, FileScan, ExecutionParent
import psycopg2
from psycopg2.extras import execute_values
import re
import json, urllib.request, requests

# Create your views here.

def home(request):
    return render(request, 'home.html')

def search(request):
    query = request.GET.get('q')

    url = "http://127.0.0.1:8000/scan/domain_ip/" + query

    domain_ip_dict = json.loads(requests.get(url).text)

    id = domain_ip_dict["id"]
    type = domain_ip_dict["type"]
    score = domain_ip_dict["score"]
    severity = domain_ip_dict["severity"]
    date = domain_ip_dict["date"]
    domainipinfo = (id, type, score, severity, date)

    communicating_files = domain_ip_dict["communicating_files"]
    referring_files = domain_ip_dict["referring_files"]
    
    return render(request, 'search_domain_ip.html', {'domainipinfo': domainipinfo, 'communicating_files': communicating_files, 'referring_files': referring_files})

    

def search_file(request):
    query = request.GET.get('file')

    url = "http://127.0.0.1:8000/scan/files/" + query 

    file_dict = json.loads(requests.get(url).text)

    file_id = file_dict["file_id"]
    type = file_dict["type"]
    score = file_dict["score"]
    severity = file_dict["severity"]
    tags = file_dict["tags"]
    date = file_dict["date"]
    fileinfo = (file_id, type, score, severity, tags, date)

    exec_parents = file_dict["exec_parents"]
    
    return render(request, 'search_file.html', {'fileinfo': fileinfo, 'execution_parents': exec_parents})


# file with execution_parents: 43239bce0a3200c5d61d968f8e130dbaa3bf987e02417d49191c72bbf1636d4e, b0f476d3f63bf6c0294baa40e1e1a18933a0ee787b6077675b6073c1c1a7b7a4, 92ba324f390c6a09feaf42d88591c7481fe432ed9a58822efebda0a7bca170db
# cd56643dc3a657ad83b8edbe9f607a572643db0d7ea7376bb86b569c38f82cee