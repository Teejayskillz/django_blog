# Generated by Django 4.2.13 on 2025-07-04 12:35

from django.db import migrations, models
import django.db.models.deletion
import django_resized.forms


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AdPlacement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text="A unique name for this ad placement (e.g., 'Sidebar Top', 'Below Post Content')", max_length=100, unique=True)),
                ('slug', models.SlugField(help_text='A unique slug for URL or template identification', max_length=100, unique=True)),
                ('description', models.TextField(blank=True, help_text='Brief description of where this placement appears.')),
                ('width', models.IntegerField(blank=True, help_text='Recommended width for ads in this placement (in pixels)', null=True)),
                ('height', models.IntegerField(blank=True, help_text='Recommended height for ads in this placement (in pixels)', null=True)),
                ('is_active', models.BooleanField(default=True, help_text='Whether this ad placement is currently active on the site.')),
            ],
            options={
                'verbose_name': 'Ad Placement',
                'verbose_name_plural': 'Ad Placements',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Ad',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Internal name for the ad creative.', max_length=200)),
                ('image', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format=None, help_text='Upload the ad image (e.g., banner, square ad).', keep_meta=True, null=True, quality=85, scale=None, size=[1200, 800], upload_to='ads/')),
                ('code', models.TextField(blank=True, help_text='HTML/JavaScript code for the ad (e.g., Google AdSense, direct HTML banner). If code is provided, image and target_url might be ignored.')),
                ('target_url', models.URLField(blank=True, help_text='The URL the user will be redirected to when clicking the ad image.')),
                ('alt_text', models.CharField(blank=True, help_text='Alt text for the ad image, important for accessibility and SEO.', max_length=255)),
                ('start_date', models.DateTimeField(blank=True, help_text='Date and time when the ad should start appearing.', null=True)),
                ('end_date', models.DateTimeField(blank=True, help_text='Date and time when the ad should stop appearing.', null=True)),
                ('is_active', models.BooleanField(default=True, help_text='Whether this ad is currently active and eligible for display.')),
                ('views', models.PositiveIntegerField(default=0, help_text='Number of times this ad has been displayed.')),
                ('clicks', models.PositiveIntegerField(default=0, help_text='Number of times this ad has been clicked.')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('placement', models.ForeignKey(blank=True, help_text='The location where this ad is intended to be displayed.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ads', to='ads.adplacement')),
            ],
            options={
                'verbose_name': 'Ad Creative',
                'verbose_name_plural': 'Ad Creatives',
                'ordering': ['-created_at'],
            },
        ),
    ]
