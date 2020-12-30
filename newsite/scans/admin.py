from django.contrib import admin
from .models import DomainIpScan, CommunicatingFile, ReferringFile, FileScan, ExecutionParent

class DomainIP(admin.ModelAdmin):
    list_display = ("id", "type", "score", "severity", "date")
    readonly_fields = ("id", "type", "score", "severity", "date")
    search_fields = ('id',)
    list_filter = ('date', 'severity')
    
    def has_add_permission(self, request):  # remove add option
        return False
    
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': False,
            'show_save_and_continue': False,
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

admin.site.register(DomainIpScan, DomainIP)

class CommunicatingAdmin(admin.ModelAdmin):
    list_display = ("communicating_id", "id", "date_scanned", "detection_score", "severity", "type")
    readonly_fields = ("communicating_id", "id", "date_scanned", "detection_score", "severity", "type", "name")
    search_fields = ['id__id']
    list_filter = ('date_scanned', 'severity')

    def has_add_permission(self, request):  # remove add option
        return False
    
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': False,
            'show_save_and_continue': False,
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

admin.site.register(CommunicatingFile, CommunicatingAdmin)

class ReferringAdmin(admin.ModelAdmin):
    list_display = ("referring_id", "id", "date_scanned", "detection_score", "severity", "type")
    readonly_fields = ("referring_id", "id", "date_scanned", "detection_score", "severity", "type", "name")
    search_fields = ['id__id']
    list_filter = ('date_scanned', 'severity')

    def has_add_permission(self, request):  # remove add option
        return False
    
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': False,
            'show_save_and_continue': False,
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

admin.site.register(ReferringFile,ReferringAdmin)

class FileAdmin(admin.ModelAdmin):
    list_display = ("file_id", "type", "score", "severity", "date")
    list_filter = ('date',)
    readonly_fields = ("file_id", "type", "score", "severity", "date", "tags")
    search_fields = ('file_id',)
    list_filter = ('date', 'severity')

    def has_add_permission(self, request):  # remove add option
        return False
    
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': False,
            'show_save_and_continue': False,
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

admin.site.register(FileScan, FileAdmin)

class ExecutionAdmin(admin.ModelAdmin):
    list_display = ("execution_id", "file_id", "date_scanned", "detection_score", "severity", "type")
    readonly_fields = ("execution_id", "file_id", "date_scanned", "detection_score", "severity", "type", "name")
    search_fields = ['file_id__file_id']
    list_filter = ('date_scanned', 'severity')

    def has_add_permission(self, request):  # remove add option
        return False
    
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': False,
            'show_save_and_continue': False,
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

admin.site.register(ExecutionParent, ExecutionAdmin)


        