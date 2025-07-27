from django.urls import path
from django.views.generic.base import RedirectView
from .views import home, CategoryView, PostDetailView, search, download_quality, download_subtitle, TagDetailView, PageView, MediaListView, MediaDetailView

urlpatterns = [
    path('', home, name='home'),
    path('search/', search, name='search'),

    # ✅ CORRECTED: Use <str:slug> for flexibility
    path('category/<str:slug>/', CategoryView.as_view(), name='category'),
    path('tag/<str:slug>/', TagDetailView.as_view(), name='tag_detail'),
    
    path('download/quality/<int:pk>/', download_quality, name='download_quality'),
    path('download/subtitle/<int:pk>/', download_subtitle, name='download_subtitle'),

    path('posts/<slug:slug>/', RedirectView.as_view(
        pattern_name='post_detail',
        permanent=True,
        query_string=True
    )),

    # ✅ CORRECTED: Use <str:slug> for pages too
    path('<str:slug>/', PageView, name='page_view'),

    # ✅ This pattern is good, but let's make the post slug flexible too
    path('<str:category>/<str:slug>/', PostDetailView.as_view(), name='post_detail'),

    path('media/', MediaListView.as_view(), name='media_list'),
    path('media/<int:pk>/', MediaDetailView.as_view(), name='media_detail'),
]