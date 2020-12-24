from django.db import models

# Create your models here.

class CommunicatingFile(models.Model):
    communicating_id = models.CharField(primary_key=True, max_length=255)
    id = models.ForeignKey('DomainIpScan', on_delete=models.CASCADE, db_column='id', related_name='comms')
    date_scanned = models.DateTimeField(auto_now_add = True)
    detection_score = models.CharField(max_length=10)
    severity = models.CharField(max_length=10)
    type = models.CharField(max_length=10)
    name = models.TextField()

    class Meta:
        managed = False
        verbose_name_plural = "communicating_files"
        db_table = 'communicating_files'
    
    def __str__(self):
        return self.communicating_id

class ReferringFile(models.Model):
    referring_id = models.CharField(primary_key=True, max_length=255)
    id = models.ForeignKey('DomainIpScan', on_delete=models.CASCADE, db_column='id', related_name='referr')
    date_scanned = models.DateTimeField(auto_now_add = True)
    detection_score = models.CharField(max_length=10)
    severity = models.CharField(max_length=10)
    type = models.CharField(max_length=10)
    name = models.TextField()

    class Meta:
        managed = False
        verbose_name_plural = "referring_files"
        db_table = 'referring_files'

    def __str__(self):
        return self.referring_id

class DomainIpScan(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=10)
    score = models.CharField(max_length=10)
    severity = models.CharField(max_length=10)
    date = models.DateTimeField(auto_now_add = True)

    class Meta:
        managed = False
        verbose_name_plural = "domain_ip_scans"
        db_table = 'domain_ip_scans'

    def __str__(self):
        return self.id

class ExecutionParent(models.Model):
    execution_id = models.CharField(primary_key=True, max_length=255)
    file_id = models.ForeignKey('FileScan', on_delete=models.CASCADE, db_column='file_id')
    date_scanned = models.DateTimeField()
    detection_score = models.CharField(max_length=10)
    severity = models.CharField(max_length=10)
    type = models.CharField(max_length=10)
    name = models.TextField()

    class Meta:
        managed = False
        verbose_name_plural = "execution_parents"
        db_table = 'execution_parents'

    def __str__(self):
        return self.execution_id

class FileScan(models.Model):
    file_id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=10)
    score = models.CharField(max_length=10)
    severity = models.CharField(max_length=10)
    date = models.DateTimeField()
    tags = models.CharField(max_length=255)

    class Meta:
        managed = False
        verbose_name_plural = "file_scans"
        db_table = 'file_scans'

    def __str__(self):
        return self.file_id


