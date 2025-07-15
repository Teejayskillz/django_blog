# your_app/management/commands/import_media_thumbnails.py
import os
from django.core.management.base import BaseCommand
from django.core.files import File
from django.conf import settings
from core.models import Media # Replace your_app_name

class Command(BaseCommand):
    help = 'Imports existing images from MEDIA_ROOT/thumbnails/ into the Media model.'

    def handle(self, *args, **kwargs):
        thumbnail_dir = os.path.join(settings.MEDIA_ROOT, 'thumbnails')
        if not os.path.exists(thumbnail_dir):
            self.stdout.write(self.style.ERROR(f"Thumbnail directory not found: {thumbnail_dir}"))
            return

        self.stdout.write(self.style.SUCCESS(f"Scanning for images in: {thumbnail_dir}"))
        imported_count = 0

        for filename in os.listdir(thumbnail_dir):
            file_path = os.path.join(thumbnail_dir, filename)
            
            # Skip directories and non-image files (based on common extensions)
            if os.path.isdir(file_path) or not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                continue

            # Check if a Media object with this thumbnail already exists
            # We'll compare the full file path of the thumbnail field
            relative_path = os.path.join('thumbnails', filename) # This is how Django stores it
            
            if Media.objects.filter(thumbnail=relative_path).exists():
                self.stdout.write(self.style.WARNING(f"Skipping existing: {filename}"))
                continue

            # Create a new Media instance
            try:
                with open(file_path, 'rb') as f:
                    media_instance = Media(title=os.path.splitext(filename)[0]) # Use filename as title
                    # Assign the thumbnail file directly
                    media_instance.thumbnail.save(filename, File(f), save=False)
                    media_instance.save() # This will save the object and the thumbnail file reference
                    imported_count += 1
                    self.stdout.write(self.style.SUCCESS(f"Imported: {filename}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error importing {filename}: {e}"))

        self.stdout.write(self.style.SUCCESS(f"Successfully imported {imported_count} new media items."))