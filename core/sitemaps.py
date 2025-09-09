# core/sitemaps.py
from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from django.db.models import Count, Q

# Import all your needed models
from core.models import Post, Category, MyCustomTag 

# --- PostSitemap ---
class PostSitemap(Sitemap):
    changefreq = "daily"
    priority = 0.9

    def items(self):
        return Post.objects.filter(is_published=True, category__isnull=False).order_by('-published_date')

    def lastmod(self, obj):
        return obj.updated_date if hasattr(obj, 'updated_date') and obj.updated_date else obj.published_date

    def location(self, obj):
        return obj.get_absolute_url()

# --- CategorySitemap ---
class CategorySitemap(Sitemap):
    changefreq = "weekly"
    priority = 0.8

    def items(self):
        return Category.objects.annotate(
            num_posts=Count('post', filter=Q(post__is_published=True))
        ).filter(num_posts__gt=0).order_by('name') # Added .order_by('name')

    def lastmod(self, obj):
        latest_post = obj.post_set.filter(is_published=True).latest('published_date')
        return latest_post.published_date

    def location(self, obj):
        return obj.get_absolute_url()

# --- NEW: TagSitemap ---
class TagSitemap(Sitemap):
    changefreq = "weekly"
    priority = 0.7

    def items(self):
        # Only include tags used on at least one published post
        used_tag_ids = Post.objects.filter(is_published=True).values_list('tags', flat=True).distinct()
        return MyCustomTag.objects.filter(id__in=used_tag_ids).order_by('name') # Added .order_by('name')

    def lastmod(self, obj):
        # Use the date of the newest post that has this tag
        return Post.objects.filter(is_published=True, tags__in=[obj]).latest('published_date').published_date

    def location(self, obj):
        # Uses the get_absolute_url() method from your MyCustomTag model
        return obj.get_absolute_url()

# --- StaticViewSitemap ---
class StaticViewSitemap(Sitemap):
    priority = 0.8
    changefreq = "monthly"

    def items(self):
        return ['home', 'search'] 

    def location(self, item):
        return reverse(item)