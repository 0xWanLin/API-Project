from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from itertools import chain
from .models import DomainIpScan, CommunicatingFile, ReferringFile, FileScan, ExecutionParent
import psycopg2
from psycopg2.extras import execute_values
import re
import json
import requests

# Create your views here.

def home(request):
    return render(request, 'scans/home.html')

def domain_ip(request):
    domainip_query = DomainIpScan.objects.all()
    return render(request, 'scans/domain_ip.html', {'domainip_query': domainip_query})

def files(request):
    file_query = FileScan.objects.all()
    return render(request, 'scans/file.html', {'file_query': file_query})

def search(request):
    query = request.GET.get('q')

    url = "http://127.0.0.1:8000/scan/domain_ip/" + query
    response = requests.get(url)
    domain_ip_dict = json.loads(response.text)

    id = domain_ip_dict["id"]
    type = domain_ip_dict["type"]
    score = domain_ip_dict["score"]
    severity = domain_ip_dict["severity"]
    date = domain_ip_dict["date"]
    domainipinfo = (id, type, score, severity, date)

    communicating_files = domain_ip_dict["communicating_files"]
    referring_files = domain_ip_dict["referring_files"]
    
    return render(request, 'scans/search_domain_ip.html', {'domainipinfo': domainipinfo, 'communicating_files': communicating_files, 'referring_files': referring_files})

def search_file(request):
    query = request.GET.get('file')

    url = "http://127.0.0.1:8000/scan/files/" + query 
    response_file = requests.get(url)
    file_dict = json.loads(response_file.text)

    file_id = file_dict["file_id"]
    type = file_dict["type"]
    score = file_dict["score"]
    severity = file_dict["severity"]
    date = file_dict["date"]
    tags = file_dict["tags"]
    fileinfo = (file_id, type, score, severity, date, tags)

    exec_parents = file_dict["exec_parents"]
    
    return render(request, 'scans/search_file.html', {'fileinfo': fileinfo, 'execution_parents': exec_parents})


# file with execution_parents: 6210d10145358e05ea5e2852277a393c51a8dde8308f003e101a6efe7df84479, 43239bce0a3200c5d61d968f8e130dbaa3bf987e02417d49191c72bbf1636d4e (already in the db), b0f476d3f63bf6c0294baa40e1e1a18933a0ee787b6077675b6073c1c1a7b7a4, 92ba324f390c6a09feaf42d88591c7481fe432ed9a58822efebda0a7bca170db
# cd56643dc3a657ad83b8edbe9f607a572643db0d7ea7376bb86b569c38f82cee