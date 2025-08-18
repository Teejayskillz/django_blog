# core/context_processors.py
from .models import Post, Category , SiteSettings # Import SiteSettings
from taggit.models import Tag, TaggedItem # Import TaggedItem
from django.db.models import Count, Q # Ensure Q is imported for filtering
from django.utils import timezone
from datetime import timedelta

def global_sidebar_context(request):
    """
    Context processor to add trending, recent, and popular tags to all templates.
    """
    trending_posts = []
    recent_posts = []
    popular_tags = []

    # Fetch Trending Posts
    try:
        trending_category = Category.objects.get(name='Trending')
        trending_posts = Post.objects.filter(
            is_published=True,
            category=trending_category
        ).order_by('-published_date')[:3]
    except Category.DoesNotExist:
        pass

    # Fetch Recent Posts
    recent_posts = Post.objects.filter(
        is_published=True
    ).order_by('-published_date')[:10]

    # Corrected way to Fetch Popular Tags
    # 1. Get the IDs of published posts.
    published_post_ids = Post.objects.filter(is_published=True).values_list('id', flat=True)

    # 2. Filter TaggedItem instances that relate to these published posts AND content type for Post.
    # We need to explicitly specify the content_type, which requires importing ContentType
    from django.contrib.contenttypes.models import ContentType
    post_content_type = ContentType.objects.get_for_model(Post)

    popular_tags = Tag.objects.filter(
        taggit_taggeditem_items__object_id__in=published_post_ids, # TaggedItem's object_id is in published post IDs
        taggit_taggeditem_items__content_type=post_content_type # And the content type matches Post
    ).annotate(
        num_times=Count('taggit_taggeditem_items')
    ).order_by(
        '-num_times'
    )[:10]

    return {
        'trending_posts': trending_posts,
        'recent_posts': recent_posts,
        'popular_tags': popular_tags,
    }
    
   

def trending_posts_processor(request):
    """
    Context processor to add trending posts to the context of every request.
    """
    time_frame = request.GET.get('time', '7days') # Get 'time' parameter from URL
    
    if time_frame == '24hrs':
        time_threshold = timezone.now() - timedelta(hours=24)
    else: # Default or '7days'
        time_threshold = timezone.now() - timedelta(days=7)

    trending_posts = Post.objects.filter(
        is_published=True,
        published_date__gte=time_threshold # Posts published within the timeframe
    ).order_by('-views')[:10] # Order by views, limit to 5 (adjust as needed)

    return {
        'trending_posts': trending_posts,
        'selected_time_frame': time_frame,
    }    

def site_settings(request):
    try:
        settings = SiteSettings.load()
    except:
        # If there's an error, create default settings
        settings = SiteSettings()
    return {
        'site_settings': settings
    }