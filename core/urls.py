from django.urls import path
from django.views.generic.base import RedirectView
from .views import home, CategoryView, PostDetailView, search, download_quality, download_subtitle, TagDetailView, PageView, MediaListView, MediaDetailView

urlpatterns = [
    path('', home, name='home'),
    path('search/', search, name='search'),

    # Static paths first (most specific to least specific)
    path('category/<slug:slug>/', CategoryView.as_view(), name='category'),
    path('tag/<slug:slug>/', TagDetailView.as_view(), name='tag_detail'),
    path('download/quality/<int:pk>/', download_quality, name='download_quality'),
    path('download/subtitle/<int:pk>/', download_subtitle, name='download_subtitle'),

    # Legacy URL support with redirect (must come before WordPress pattern)
    path('posts/<slug:slug>/', RedirectView.as_view(
        pattern_name='post_detail',
        permanent=True,
        query_string=True
    )),
    path('<slug:slug>/', PageView, name='page_view'),

    # WordPress-style URLs (catch-all pattern - must come LAST)
    path('<str:category>/<slug:slug>/', PostDetailView.as_view(), name='post_detail'),
    path('media/', MediaListView.as_view(), name='media_list'),
    path('media/<int:pk>/', MediaDetailView.as_view(), name='media_detail'),
]