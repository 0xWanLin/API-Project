# Generated by Django 3.1.4 on 2020-12-16 11:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0002_delete_executionparent'),
    ]

    operations = [
        migrations.CreateModel(
            name='ExecutionParent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('execution_id', models.CharField(max_length=255)),
                ('date_scanned', models.DateTimeField()),
                ('detection_score', models.CharField(max_length=10)),
                ('severity', models.CharField(max_length=10)),
                ('type', models.CharField(max_length=10)),
                ('name', models.TextField()),
            ],
            options={
                'verbose_name_plural': 'execution_parents',
                'db_table': 'execution_parents',
                'managed': False,
            },
        ),
    ]