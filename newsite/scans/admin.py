from django.contrib import admin
from .models import DomainIpScan, CommunicatingFile, ReferringFile, FileScan, ExecutionParent

# Register your models here.

class DomainIP(admin.ModelAdmin):
    list_display = ("id", "type", "score", "severity", "date")

admin.site.register(DomainIpScan, DomainIP)

class CommunicatingAdmin(admin.ModelAdmin):
    list_display = ("communicating_id", "id", "date_scanned", "detection_score", "severity", "type", "name")

admin.site.register(CommunicatingFile, CommunicatingAdmin)

class ReferringAdmin(admin.ModelAdmin):
    list_display = ("referring_id", "id", "date_scanned", "detection_score", "severity", "type", "name")

admin.site.register(ReferringFile,ReferringAdmin)

class FileAdmin(admin.ModelAdmin):
    list_display = ("file_id", "type", "score", "severity", "tags", "date")

admin.site.register(FileScan, FileAdmin)

class ExecutionAdmin(admin.ModelAdmin):
    list_display = ("execution_id", "file_id", "date_scanned", "detection_score", "severity", "type", "name")

admin.site.register(ExecutionParent, ExecutionAdmin)