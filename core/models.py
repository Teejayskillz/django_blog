# your_app/models.py

from django.db import models
from django.contrib.auth.models import User
from taggit.managers import TaggableManager
from taggit.models import Tag as TaggitTag
from django_resized import ResizedImageField
from django_ckeditor_5.fields import CKEditor5Field
from django.urls import reverse
from django.utils.text import slugify
import os 
from django.conf import settings
from django.core.files.base import ContentFile
from PIL import Image
from io import BytesIO

class SiteSettings(models.Model):
    site_title = models.CharField(
        max_length=200, 
        default='Watch Latest Movies & TV Shows',
        help_text='Default title for pages without specific titles'
    )
    site_name = models.CharField(
        max_length=100, 
        default='Hypeblog9jaTV'
    )
    
    class Meta:
        verbose_name = "Site Settings"
        verbose_name_plural = "Site Settings"
    
    def __str__(self):
        return "Site Settings"
    
    # Ensure only one instance exists
    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)
    
    @classmethod
    def load(cls):
        obj, created = cls.objects.get_or_create(pk=1)
        return obj
    
class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        # Assumes you have a URL pattern named 'category_detail'
        # that takes the category's slug as an argument.
        return reverse('category', kwargs={'slug': self.slug})

class Post(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200, unique=True)
    seo_title = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="(e.g., 'Henry Danger S1 EP20 - Series Download'). If left blank, the main title will be used."
    )
    thumbnail = ResizedImageField(
        size=[300, 450],
        quality=85,
        upload_to='thumbnails/',
        blank=True,
        null=True,
        help_text="Upload featured image (recommended size: 300x450px)"
    )
    content = CKEditor5Field('Text', config_name='default')

    excerpt = models.TextField(
        blank=True,
        help_text="A brief summary of the post, used for previews (e.g., on index pages, social media, Telegram)."
    )

    # ADD THIS LINE FOR THE VIEWS COUNT
    views = models.IntegerField(default=0) # Added this line for tracking views
    # END ADDITION

    enable_downloads = models.BooleanField(
        default=True,
        help_text="Show download section for this post"
    )
    download_section_title = models.CharField(
        max_length=100,
        default="Download Links",
        blank=True
    )
    download_button_text = models.CharField(
        max_length=50,
        default="Download Now",
        blank=True
    )
    download_url = models.URLField(blank=True)
    subtitle_url = models.URLField(blank=True)
    subtitle_button_text = models.CharField(
        max_length=50,
        default="Download Subtitle",
        blank=True
    )

    author = models.ForeignKey(User, on_delete=models.CASCADE, default=2)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True)
    tags = TaggableManager(blank=True)  # Tags using django-taggit
    published_date = models.DateTimeField(auto_now_add=True)
    is_published = models.BooleanField(default=True)

    # source = models.ForeignKey(
    #     "core.FeedSource",
    #     on_delete=models.SET_NULL,
    #     null=True,
    #     blank=True
    # )
    # source_url = models.URLField(blank=True, null=True)
    is_external = models.BooleanField(default=False)


    def get_absolute_url(self):
        # This assumes your post detail URL pattern is named 'post_detail'
        # and expects 'category' and 'slug' kwargs.
        # Ensure your urls.py matches this.
        return reverse('post_detail', kwargs={
            'category': self.category.slug,
            'slug': self.slug
        })

    def __str__(self):
        return self.title
    @property
    def get_page_title(self):
        return self.seo_title if self.seo_title else self.title
    
class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    name = models.CharField(max_length=100)
    email = models.EmailField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Comment"
        verbose_name_plural = "Comments"

    def __str__(self):
        return f"Comment by {self.name} on {self.post.title}"
    
# from django.db import models # Already imported above

class HomepageSection(models.Model):
    """Admin-configurable sections for homepage"""
    title = models.CharField(max_length=100)
    categories = models.ManyToManyField('Category', blank=True)
    enabled = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['display_order']
    
    def __str__(self):
        return self.title

class DownloadQuality(models.Model):
    QUALITY_CHOICES = [
        ('360p', 'DOWNLOAD MOVIE [360p]'),
        ('mp3', 'DOWNLOAD MUSIC/MP3'),
        ('ZIP', 'DOWNLOAD FULL ALBUM [ZIP]'),
        ('480p', 'DOWNLOAD MOVIE [480p]'), 
        ('720p', 'DOWNLOAD MOVIE [720p (HD)]'),
        ('1080p', 'DOWNLOAD MOVIE 1080p (FHD)]'),
        ('4K', 'DOWNLOAD [4K (UHD)]'),
        ('EP1', 'DOWNLOAD EPISODE 1'),
        ('EP2', 'DOWNLOAD EPISODE 2'),
        ('EP3', 'DOWNLOAD EPISODE 3'),
        ('EP4', 'DOWNLOAD EPISODE 4'),
        ('EP5', 'DOWNLOAD EPISODE 5'),
        ('EP6', 'DOWNLOAD EPISODE 6'),
        ('EP7', 'DOWNLOAD EPISODE 7'),
        ('EP8', 'DOWNLOAD EPISODE 8'),
        ('EP9', 'DOWNLOAD EPISODE 9'),
        ('EP10', 'DOWNLOAD EPISODE 10'),
        ('EP11', 'DOWNLOAD EPISODE 11'),
        ('EP12', 'DOWNLOAD EPISODE 12'),
        ('EP13', 'DOWNLOAD EPISODE 13'),
        ('EP14', 'DOWNLOAD EPISODE 14'),
        ('EP15', 'DOWNLOAD EPISODE 15'),
        ('EP16', 'DOWNLOAD EPISODE 16'),
        ('EP17', 'DOWNLOAD EPISODE 17'),
        ('EP18', 'DOWNLOAD EPISODE 18'),
        ('EP19', 'DOWNLOAD EPISODE 19'),
        ('EP20', 'DOWNLOAD EPISODE 20'),
        ('EP21', 'DOWNLOAD EPISODE 21'),
        ('EP22', 'DOWNLOAD EPISODE 22'),
        ('EP23', 'DOWNLOAD EPISODE 23'),
        ('EP24', 'DOWNLOAD EPISODE 24'),
        ('EP25', 'DOWNLOAD EPISODE 25'),
        ('EP26', 'DOWNLOAD EPISODE 26'),
        ('EP27', 'DOWNLOAD EPISODE 27'),
        ('EP28', 'DOWNLOAD EPISODE 28'),
        ('EP29', 'DOWNLOAD EPISODE 29'),
        ('EP30', 'DOWNLOAD EPISODE 30'),
        ('EP31', 'DOWNLOAD EPISODE 31'),
        ('EP32', 'DOWNLOAD EPISODE 32'),
        ('EP33', 'DOWNLOAD EPISODE 33'),
        ('EP34', 'DOWNLOAD EPISODE 34'),
        ('EP35', 'DOWNLOAD EPISODE 35'),
        ('EP36', 'DOWNLOAD EPISODE 36'),
        ('EP37', 'DOWNLOAD EPISODE 37'),
        ('EP38', 'DOWNLOAD EPISODE 38'),
        ('EP39', 'DOWNLOAD EPISODE 39'),
        ('EP40', 'DOWNLOAD EPISODE 40'),
    ]
    
    post = models.ForeignKey('Post', on_delete=models.CASCADE, related_name='qualities')
    quality = models.CharField(max_length=10, choices=QUALITY_CHOICES)
    download_url = models.URLField()
    download_count = models.PositiveIntegerField(default=0)
    is_premium = models.BooleanField(default=False)

class Subtitle(models.Model):
    post = models.ForeignKey('Post', on_delete=models.CASCADE, related_name='subtitles')
    language = models.CharField(max_length=50)
    download_url = models.URLField()
    is_auto_generated = models.BooleanField(default=False)
    download_count = models.PositiveIntegerField(default=0)
class MyCustomTag(TaggitTag):
    class Meta:
        proxy = True # This is correct

    def get_absolute_url(self):
        # This is perfect. It will work once the URL pattern is fixed.
        return reverse('tag_detail', kwargs={'slug': self.slug})
class Page(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200, unique=True)
    content = CKEditor5Field('Content', config_name='default')
    published_date = models.DateTimeField(auto_now_add=True)
    is_published = models.BooleanField(default=True)

    def get_absolute_url(self):
        return reverse('page_detail', kwargs={'slug': self.slug})

    class Meta:
        ordering = ['-published_date']
        verbose_name = "Page"
        verbose_name_plural = "Pages"

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)


class Media(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='media/') # Original file (optional for thumbnails)
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True) # Field for the thumbnail
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        if self.file:
            return self.file.url
        # If no main file, but a thumbnail exists, you might link to the thumbnail
        elif self.thumbnail:
            return self.thumbnail.url
        return '#'


    def save(self, *args, **kwargs):
        # Retrieve the original instance to compare file changes before the current save modifies it.
        # This helps determine if the 'file' field has truly changed for an existing object.
        original_file_path = None
        original_thumbnail_path = None
        if self.pk: # If it's an existing instance
            try:
                original_instance = Media.objects.get(pk=self.pk)
                original_file_path = original_instance.file.name if original_instance.file else None
                original_thumbnail_path = original_instance.thumbnail.name if original_instance.thumbnail else None
            except Media.DoesNotExist:
                pass # New instance, no original to compare with

        # Perform the first save to ensure files are uploaded and we have a PK for new instances.
        super().save(*args, **kwargs)

        # Determine if the main 'file' has changed
        current_file_path = self.file.name if self.file else None
        file_changed = (original_file_path != current_file_path)

        # --- Thumbnail Generation/Management Logic ---

        # Case 1: An image is uploaded to the 'file' field.
        if self.file and self.file.name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            # Condition for auto-generating/regenerating thumbnail:
            # 1. The 'thumbnail' field is currently empty (or was cleared by the user).
            # OR 2. The main 'file' has changed, and the existing thumbnail was previously auto-generated.
            #    (We assume any thumbnail not in 'thumbnails/' or matching generated pattern is manual)
            
            # Check if the current thumbnail points to a path we'd generate.
            # This is a heuristic, adjust if your manual upload process uses very similar names.
            is_auto_generated_thumb = self.thumbnail and \
                                      self.thumbnail.name.startswith('thumbnails/') and \
                                      '_thumb' in self.thumbnail.name

            if not self.thumbnail or (file_changed and is_auto_generated_thumb):
                try:
                    img = Image.open(self.file.path)
                    img.thumbnail((128, 128))

                    thumb_io = BytesIO()
                    file_extension = os.path.splitext(self.file.name)[1].lower()
                    img_format = 'JPEG' # Default
                    if file_extension in ('.png',): img_format = 'PNG'
                    elif file_extension in ('.gif',): img_format = 'GIF'

                    img.save(thumb_io, format=img_format)

                    # Construct a unique thumbnail name for auto-generation
                    base_name = os.path.splitext(os.path.basename(self.file.name))[0]
                    from datetime import datetime
                    unique_suffix = datetime.now().strftime("_%Y%m%d%H%M%S")
                    thumbnail_name = f"{base_name}{unique_suffix}_auto_thumb{file_extension}" # Added '_auto' for clarity

                    # Delete old auto-generated thumbnail if it exists and a new one is being generated
                    if original_thumbnail_path and '_auto_thumb' in original_thumbnail_path: # Ensure it's an auto-gen one
                        if os.path.exists(os.path.join(settings.MEDIA_ROOT, original_thumbnail_path)):
                            os.remove(os.path.join(settings.MEDIA_ROOT, original_thumbnail_path))
                        # Note: We don't call self.thumbnail.delete() here, as we are about to set a new one.

                    # Assign the new generated thumbnail
                    self.thumbnail.save(thumbnail_name, ContentFile(thumb_io.getvalue()), save=False)
                    super().save(update_fields=['thumbnail']) # Save only the thumbnail field

                except Exception as e:
                    print(f"Error generating thumbnail for {self.file.name}: {e}")
                    # If generation fails, ensure the thumbnail field is cleared if it was trying to generate
                    # and was previously empty.
                    if not self.thumbnail and not original_thumbnail_path:
                        self.thumbnail = None
                        super().save(update_fields=['thumbnail'])


        # Case 2: The 'file' field is not an image, or it's empty.
        # If the 'file' is not an image (e.g., PDF, video), or no 'file' is uploaded,
        # ensure no auto-generated thumbnail persists.
        elif file_changed or (not self.file and original_file_path):
            # If the original file was an image and had an auto-generated thumbnail, remove it.
            if original_thumbnail_path and '_auto_thumb' in original_thumbnail_path:
                if os.path.exists(os.path.join(settings.MEDIA_ROOT, original_thumbnail_path)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, original_thumbnail_path))
                self.thumbnail.delete(save=False) # Clear the field value
                super().save(update_fields=['thumbnail']) # Persist change

        # No need for a final super().save(*args, **kwargs) outside, as we either call it with update_fields
        # or the initial super().save() was sufficient.

# class FeedSource(models.Model):
#     name = models.CharField(max_length=200)
#     feed_url = models.URLField(unique=True)
#     default_category = models.ForeignKey(
#         "core.Category",
#         on_delete=models.SET_NULL,
#         null=True,
#         blank=True
#     )
#     is_active = models.BooleanField(default=True)
#     last_fetched = models.DateTimeField(null=True, blank=True)

#     def __str__(self):
#         return self.name
