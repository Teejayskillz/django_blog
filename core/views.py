from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, DetailView
from .models import Post, Category, Comment, HomepageSection, DownloadQuality, Subtitle, Media, Page
from .forms import CommentForm
from django.db.models import Q
from django.core.paginator import Paginator
from django.http import HttpResponseRedirect
from taggit.models import Tag 
from .sitemaps import PostSitemap, CategorySitemap, TagSitemap, StaticViewSitemap
from django.contrib.sitemaps.views import sitemap as sitemap_view, index as sitemap_index_view
from django.http import HttpResponse
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.conf import settings
from django.views.static import serve

def home(request):
    # Get all active homepage sections
    sections = HomepageSection.objects.filter(enabled=True)
    
    # Prepare section data
    section_data = []
    for section in sections:
        posts = Post.objects.filter(
            is_published=True,
            category__in=section.categories.all()
        ).order_by('-published_date')[:6]  # 6 posts per section
        
        section_data.append({
            'title': section.title,
            'posts': posts,
            'id': section.id
        })
    
    # Get all other recent posts not in sections for pagination
    section_categories = [cat for section in sections for cat in section.categories.all()]
    other_posts_queryset = Post.objects.filter(
        is_published=True
    ).exclude(
        category__in=section_categories
    ).order_by('-published_date')
    
    # Handle search functionality
    query = request.GET.get('q')
    if query:
        other_posts_queryset = other_posts_queryset.filter(
            Q(title__icontains=query) | 
            Q(content__icontains=query) |
            Q(category__name__icontains=query) |
            Q(tags__name__icontains=query)  # Add this if you have tags
        ).distinct()
    
    # Set up pagination
    posts_per_page = 12  # Adjust this number as needed
    paginator = Paginator(other_posts_queryset, posts_per_page)
    
    page_number = request.GET.get('page', 1)
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page
        page_obj = paginator.page(1)
    except EmptyPage:
        # If page is out of range, deliver last page
        page_obj = paginator.page(paginator.num_pages)
    
    context = {
        'sections': section_data,
        'page_obj': page_obj,  # Replace other_posts with page_obj
        'query': query,  # Pass search query to template
        'total_posts': paginator.count,  # Total number of posts
    }
    return render(request, 'core/home.html', context)

class CategoryView(ListView):
    model = Post
    template_name = 'core/category.html'
    paginate_by = 12
    context_object_name = 'posts'
    slug_url_kwarg = 'slug'  # Explicitly define the slug parameter name
    
    def get_queryset(self):
        # Optimized query with select_related and prefetch_related
        return Post.objects.filter(
            category__slug=self.kwargs[self.slug_url_kwarg],
            is_published=True
        ).select_related('category', 'author')\
         .prefetch_related('tags', 'qualities', 'subtitles')\
         .order_by('-published_date')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        category_slug = self.kwargs[self.slug_url_kwarg]
        
        # Get category with one query and add to context
        context['category'] = get_object_or_404(
            Category.objects.only('name', 'slug'),
            slug=category_slug
        )
        
        # Add additional context you might need
        context['page_title'] = f"Posts in {context['category'].name}"
        context['meta_description'] = f"Browse all posts in {context['category'].name} category"
        
        return context



class PostDetailView(DetailView):
    model = Post
    template_name = 'core/post_detail.html'
    context_object_name = 'post'
    
    def get_object(self, queryset=None):
        """
        Handles both URL patterns:
        1. WordPress-style: /category-slug/post-slug/
        2. Legacy: /posts/post-slug/
        """
        if 'category' in self.kwargs:  # WordPress-style URL
            post = get_object_or_404(Post, slug=self.kwargs['slug'])
            
            # SEO: Redirect if category doesn't match (301 permanent)
            if post.category.slug != self.kwargs['category']:
                return redirect('post_detail', # Use the name of your URL pattern for the post detail
                              category=post.category.slug,
                              slug=post.slug,
                              permanent=True)
            return post
        return get_object_or_404(Post, slug=self.kwargs['slug'])  # Legacy URL

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        post = self.object # 'self.object' is already set by DetailView's get_object()

        # --- START: ADDED OG/Twitter Absolute URL Logic ---
        # Calculate absolute URL for the post
        # post.get_absolute_url() returns a relative URL, e.g., /hollywood-movie/tornado-2025/
        post_absolute_url = self.request.build_absolute_uri(post.get_absolute_url())
        context['post_absolute_url'] = post_absolute_url

        # Calculate absolute URL for the thumbnail
        if post.thumbnail:
            # post.thumbnail.url returns a relative URL, e.g., /media/thumbnails/my_image.jpg
            thumbnail_absolute_url = self.request.build_absolute_uri(post.thumbnail.url)
            context['thumbnail_absolute_url'] = thumbnail_absolute_url
        else:
            # Construct the absolute URL for the default static image
            # Assumes your STATIC_URL leads to a publicly accessible directory
            default_image_relative_url = settings.STATIC_URL + 'images/default_poster.jpg'
            context['thumbnail_absolute_url'] = self.request.build_absolute_uri(default_image_relative_url)
        # --- END: ADDED OG/Twitter Absolute URL Logic ---


        # Download-related context
        download_data = {
            'related_posts': Post.objects.filter(
                category=post.category,
                is_published=True
            ).exclude(id=post.id)[:4],
            'has_downloads': post.enable_downloads,
            'download_section_title': post.download_section_title,
            'qualities': post.qualities.all() if post.enable_downloads else [],
            'subtitles': post.subtitles.all() if post.enable_downloads else [],
            'show_download_section': post.enable_downloads and (
                post.qualities.exists() or post.subtitles.exists()
            ),
            'current_category': post.category  # For breadcrumbs
        }

        # Comment-related context
        comment_data = {
            'comments': post.comments.filter(is_approved=True).order_by('-created_at'),
            'comment_form': CommentForm(),
            'comments_count': post.comments.filter(is_approved=True).count()
        }

        context.update({**download_data, **comment_data})
        return context

    def post(self, request, *args, **kwargs):
        """Handle comment submissions"""
        self.object = self.get_object()
        form = CommentForm(request.POST)
        
        if form.is_valid():
            comment = form.save(commit=False)
            comment.post = self.object
            comment.save()
            
            # Redirect back to the same URL pattern
            if 'category' in self.kwargs:
                return redirect('post_detail',
                              category=self.object.category.slug,
                              slug=self.object.slug)
            return redirect('post_detail', slug=self.object.slug)
        
        # Invalid form - re-render with errors
        context = self.get_context_data()
        context['comment_form'] = form
        return self.render_to_response(context)
def search(request):
    query = request.GET.get('q')
    results = Post.objects.filter(
        Q(title__icontains=query) | 
        Q(content__icontains=query),
        is_published=True
    ).order_by('-published_date')
    
    paginator = Paginator(results, 12)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'core/search.html', {
        'query': query,
        'page_obj': page_obj
    })
    
    

def search(request):  # Renamed to 'search' to match your original function name
    query = request.GET.get('q', '') # Changed 'query' to 'q' to match your original 'request.GET.get('q', '')'
    results = []
    page_obj = None
    is_paginated = False
    
    if query:
        # Search in title, content, and excerpt fields
        results = Post.objects.filter(
            Q(title__icontains=query) | 
            Q(content__icontains=query) | 
            Q(excerpt__icontains=query), # Added excerpt field
            is_published=True  # CHANGED THIS LINE: Used 'is_published' instead of 'status'
        ).order_by('-published_date')  # Order by newest first
        
        # Pagination
        paginator = Paginator(results, 12)  # Show 12 posts per page
        page_number = request.GET.get('page')
        
        try:
            page_obj = paginator.get_page(page_number)
            results = page_obj.object_list
            is_paginated = paginator.num_pages > 1
        except PageNotAnInteger:
            page_obj = paginator.get_page(1)
            results = page_obj.object_list
        except EmptyPage:
            page_obj = paginator.get_page(paginator.num_pages)
            results = page_obj.object_list
    
    context = {
        'query': query,
        'results': results,
        'page_obj': page_obj,
        'is_paginated': is_paginated,
    }
    
    return render(request, 'core/search.html', context) # Kept your original template name 'core/search.html'
def download_quality(request, pk):
    quality = get_object_or_404(DownloadQuality, pk=pk)
    quality.download_count += 1
    quality.save()
    return HttpResponseRedirect(quality.download_url)

def download_subtitle(request, pk):
    subtitle = get_object_or_404(Subtitle, pk=pk)
    subtitle.download_count += 1
    subtitle.save()
    return HttpResponseRedirect(subtitle.download_url)    
    
class TagDetailView(ListView):
    model = Post
    template_name = 'core/tag_detail.html'
    context_object_name = 'posts'
    paginate_by = 12

    def get_queryset(self):
        tag_slug = self.kwargs['slug']
        return Post.objects.filter(
            tags__slug=tag_slug,
            is_published=True
        ).order_by('-published_date')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
       
        context['tag'] = Tag.objects.get(slug=self.kwargs['slug']) # This is line 179
        return context
    
def robots_txt(request):
    return render(request, 'robots.txt', content_type='text/plain')

def PageView(request, slug):
    page = get_object_or_404(Page, slug=slug, is_published=True)
    context = {
        'page': page
    }
    return render(request, 'core/page.html', context)   

class MediaListView(ListView):
    model = Media
    template_name = 'media/media_list.html' # Path to your template
    context_object_name = 'medias' # The name of the variable that will contain the list of media objects in your template
    ordering = ['-uploaded_at'] # Order by most recent upload

class MediaDetailView(DetailView):
    model = Media
    template_name = 'media/media_detail.html' # Path to your template
    context_object_name = 'media_item' # The name of the variable that will contain the single media object

def styled_sitemap(request):
    """
    Custom view to serve a styled sitemap index for human users.
    """
    sitemaps = {
        'blog': PostSitemap,
        'categories': CategorySitemap,
        'tags': TagSitemap,
        'static': StaticViewSitemap,
    }
    
    response = sitemap_index_view(request, sitemaps=sitemaps)
    response.render() 
    
    xml_content = response.content.decode('utf-8')
    
    # ⭐ FIX: The stylesheet link must be on a new line after the xml declaration.
    # The XML declaration must be the very first line of the document with no preceding characters.
    stylesheet_link = f'<?xml-stylesheet type="text/xsl" href="{ reverse("styled_sitemap_stylesheet") }"?>\n'
    
    # Find the position of the XML declaration and insert the stylesheet after it.
    # This is a more robust way to handle the insertion.
    insert_pos = xml_content.find('?>') + 2  # Find the end of the XML declaration
    
    styled_xml = xml_content[:insert_pos] + '\n' + stylesheet_link + xml_content[insert_pos:]
    
    return HttpResponse(styled_xml, content_type='application/xml')



from django.http import Http404
def sitemap_stylesheet(request):
    """
    View to serve the sitemap.xsl static file, with a check for the directory.
    """
    if not settings.STATICFILES_DIRS:
        # If STATICFILES_DIRS is empty, return a 404 or a clear message.
        raise Http404("STATICFILES_DIRS is not configured to serve sitemap.xsl.")
    
    # Safely access the first element of the list
    document_root = settings.STATICFILES_DIRS[0]
    
    return serve(request, 'sitemap.xsl', document_root=document_root, show_indexes=False)