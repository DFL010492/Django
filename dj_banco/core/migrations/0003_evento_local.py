# Generated by Django 5.0.6 on 2024-07-04 19:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_evento_usuario_alter_evento_data_evento'),
    ]

    operations = [
        migrations.AddField(
            model_name='evento',
            name='local',
            field=models.CharField(default=1, max_length=255),
            preserve_default=False,
        ),
    ]
