from django.contrib import admin
from .models import DomainIpScan, CommunicatingFile, ReferringFile, FileScan, ExecutionParent
from django.contrib.admin import DateFieldListFilter
from rangefilter.filter import DateRangeFilter, DateTimeRangeFilter

# file with execution_parents: 6210d10145358e05ea5e2852277a393c51a8dde8308f003e101a6efe7df84479, 43239bce0a3200c5d61d968f8e130dbaa3bf987e02417d49191c72bbf1636d4e (already in the db), b0f476d3f63bf6c0294baa40e1e1a18933a0ee787b6077675b6073c1c1a7b7a4, 92ba324f390c6a09feaf42d88591c7481fe432ed9a58822efebda0a7bca170db
# cd56643dc3a657ad83b8edbe9f607a572643db0d7ea7376bb86b569c38f82cee

class DomainIP(admin.ModelAdmin):
    list_display = ("id", "type", "score", "severity", "date")
    readonly_fields = ("id", "type", "score", "severity", "date")
    search_fields = ('id',)
    list_filter = ('date',)
    
    def has_add_permission(self, request):  # remove add option
        return False

admin.site.register(DomainIpScan, DomainIP)

class CommunicatingAdmin(admin.ModelAdmin):
    list_display = ("communicating_id", "id", "date_scanned", "detection_score", "severity", "type")
    readonly_fields = ("communicating_id", "id", "date_scanned", "detection_score", "severity", "type", "name")
    search_fields = ['id__id']
    list_filter = ('date_scanned',)

    def has_add_permission(self, request):  # remove add option
        return False

admin.site.register(CommunicatingFile, CommunicatingAdmin)

class ReferringAdmin(admin.ModelAdmin):
    list_display = ("referring_id", "id", "date_scanned", "detection_score", "severity", "type")
    readonly_fields = ("referring_id", "id", "date_scanned", "detection_score", "severity", "type", "name")
    search_fields = ['id__id']
    list_filter = ('date_scanned',)

    def has_add_permission(self, request):  # remove add option
        return False

admin.site.register(ReferringFile,ReferringAdmin)

class FileAdmin(admin.ModelAdmin):
    list_display = ("file_id", "type", "score", "severity", "date")
    list_filter = ('date',)
    readonly_fields = ("file_id", "type", "score", "severity", "date", "tags")
    search_fields = ('file_id',)
    list_filter = ('date',)

    def has_add_permission(self, request):  # remove add option
        return False

admin.site.register(FileScan, FileAdmin)

class ExecutionAdmin(admin.ModelAdmin):
    list_display = ("execution_id", "file_id", "date_scanned", "detection_score", "severity", "type")
    readonly_fields = ("execution_id", "file_id", "date_scanned", "detection_score", "severity", "type", "name")
    search_fields = ['file_id__file_id']
    list_filter = ('date_scanned',)

    def has_add_permission(self, request):  # remove add option
        return False

admin.site.register(ExecutionParent, ExecutionAdmin)


        