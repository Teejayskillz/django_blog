# your_project/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from core.sitemaps import PostSitemap, CategorySitemap, TagSitemap, StaticViewSitemap
from django.contrib.sitemaps.views import sitemap, index  # Import 'index'
from core.views import robots_txt

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
   
    path('sitemap.xml', index, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.index'),
    
    path('sitemap-<section>.xml', sitemap, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.sitemap'),
    path('', include('core.urls')), 
    path('ads/', include('ads.urls')),
    
] 
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT, show_indexes=settings.DEBUG)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)