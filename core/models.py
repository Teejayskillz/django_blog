# your_app/models.py

from django.db import models
from django.contrib.auth.models import User
from taggit.managers import TaggableManager
from taggit.models import Tag as TaggitTag
from django_resized import ResizedImageField
from django_ckeditor_5.fields import CKEditor5Field
from django.urls import reverse
from django.utils.text import slugify

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)

    def __str__(self):
        return self.name

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
    tags = TaggableManager()  # Tags using django-taggit
    published_date = models.DateTimeField(auto_now_add=True)
    is_published = models.BooleanField(default=True)


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
        proxy = True # Use proxy=True if you just want to add methods/managers without a new table

    def save(self, *args, **kwargs):
        if not self.slug or self.slug == '-': # Check for empty or problematic slugs
            self.slug = slugify(self.name)
            # If slugify(self.name) also results in an empty or problematic slug,
            # you might want a default like 'untitled-tag' or raise a validation error.
            if not self.slug or self.slug == '-':
                self.slug = f"tag-{self.id}" # Fallback to a unique slug
        super().save(*args, **kwargs)    
        
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
    file = models.FileField(upload_to='media/') # Original file
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True) # New: Field for the thumbnail
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        # This can still return the original file URL or a specific admin URL
        if self.file:
            return self.file.url
        return '#'

    def save(self, *args, **kwargs):
        # Save the original file firstx to get its path
        super().save(*args, **kwargs)

        # Only generate a thumbnail if the file is an image
        if self.file and self.file.name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            try:
                # Open the original image
                img = Image.open(self.file)
                img.thumbnail((128, 128)) # Max dimensions for the thumbnail

                # Create a file-like object to save the thumbnail
                thumb_io = BytesIO()
                # Determine format based on original file extension
                file_extension = os.path.splitext(self.file.name)[1].lower()
                if file_extension == '.jpg':
                    format = 'JPEG'
                elif file_extension == '.jpeg':
                    format = 'JPEG'
                elif file_extension == '.png':
                    format = 'PNG'
                elif file_extension == '.gif':
                    format = 'GIF'
                else: # Fallback to JPEG for other cases if needed
                    format = 'JPEG'

                img.save(thumb_io, format=format)

                # Construct the thumbnail file name
                thumbnail_name = os.path.splitext(os.path.basename(self.file.name))[0] + '_thumb' + file_extension
                
                # Check if a thumbnail already exists for this instance
                if self.thumbnail:
                    # If it exists, delete the old file to prevent orphans
                    if os.path.exists(self.thumbnail.path):
                        os.remove(self.thumbnail.path)
                    self.thumbnail.delete(save=False) # Clear the field without saving yet

                # Save the thumbnail to the thumbnail field
                self.thumbnail.save(thumbnail_name, ContentFile(thumb_io.getvalue()), save=False)

            except Exception as e:
                print(f"Error generating thumbnail for {self.file.name}: {e}")
        elif self.file:
            # If not an image, but a file exists, ensure thumbnail field is cleared if it had one
            if self.thumbnail:
                if os.path.exists(self.thumbnail.path):
                    os.remove(self.thumbnail.path)
                self.thumbnail.delete(save=False)
        else:
            # If no file, ensure thumbnail is cleared
            if self.thumbnail:
                if os.path.exists(self.thumbnail.path):
                    os.remove(self.thumbnail.path)
                self.thumbnail.delete(save=False)

        # Call the original save method again to save the thumbnail path
        super().save(*args, **kwargs)
