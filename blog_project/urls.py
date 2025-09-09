# your_project/urls.py
from django.contrib import admin
from django.urls import path, include, reverse
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.http import HttpResponse

from core.sitemaps import PostSitemap, CategorySitemap, TagSitemap, StaticViewSitemap

from django.contrib.sitemaps.views import sitemap as sitemap_view, index as sitemap_index_view

from core.views import robots_txt, styled_sitemap, sitemap_stylesheet

sitemaps = {
    'blog': PostSitemap, 
    'categories': CategorySitemap,
    'tags': TagSitemap,
    'static': StaticViewSitemap,
}

urlpatterns = [
    path('admin/', admin.site.urls),
    path('media/<path:path>', serve, {'document_root': settings.MEDIA_ROOT}),
    path('ckeditor5/', include('django_ckeditor_5.urls')),
    path('robots.txt', robots_txt),
   
    # Use the custom styled sitemap view for the main sitemap.xml
    path('sitemap.xml', styled_sitemap, name='styled_sitemap'),
    
    # Add a URL for the sitemap.xsl file
    path('sitemap.xsl', sitemap_stylesheet, name='styled_sitemap_stylesheet'),

    # This path remains for search engines to crawl individual sitemaps
    path('sitemap-<section>.xml', sitemap_view, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.sitemap'),
    
    path('', include('core.urls')), 
    path('ads/', include('ads.urls')),
    
] 
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT, show_indexes=settings.DEBUG)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)