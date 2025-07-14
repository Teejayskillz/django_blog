# core/admin.py

from django.contrib import admin
from django.utils.html import format_html
from django import forms
from django.urls import path
from django.shortcuts import render, redirect
from django.contrib import messages
import os
from django_ckeditor_5.widgets import CKEditor5Widget
from .models import Post, Category, Comment, HomepageSection, DownloadQuality, Subtitle, Page

# WordPress Import Form and Functionality
class ImportForm(forms.Form):
    xml_file = forms.FileField(label="WordPress Export XML")
    default_category = forms.ModelChoiceField(
        queryset=Category.objects.all(),
        required=True,
        label="Default Category for Posts"
    )
    skip_existing = forms.BooleanField(
        required=False,
        initial=False,
        label="Skip existing posts",
        help_text="Check this to skip posts that already exist (uncheck to update them)"
    )

class PostAdminForm(forms.ModelForm):
    content = forms.CharField(widget=CKEditor5Widget())
    
    class Meta:
        model = Post
        fields = '__all__'
        
class QualityInline(admin.TabularInline):
    model = DownloadQuality
    extra = 1
    fields = ('quality', 'download_url', 'is_premium')

class SubtitleInline(admin.TabularInline):
    model = Subtitle
    extra = 1
    fields = ('language', 'download_url', 'is_auto_generated')

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    form = PostAdminForm
    list_display = (
        'title',
        'author',
        'category',
        'is_published',
        'enable_downloads',
        'get_has_downloads',
        'get_thumbnail_preview',
        'get_total_downloads'
    )
    list_filter = (
        'category',
        'tags',
        'is_published',
        'enable_downloads'
    )
    list_editable = ('is_published', 'enable_downloads')
    prepopulated_fields = {'slug': ('title',)}
    
    # MODIFIED: Added 'seo_title' to search_fields
    search_fields = ('title', 'content', 'excerpt', 'seo_title') 
    
    readonly_fields = (
        'get_thumbnail_preview',
        'get_total_downloads',
        'get_downloads_preview'
    )
    inlines = [QualityInline, SubtitleInline]
    change_list_template = 'admin/blog/post/change_list.html'

    fieldsets = (
        ('Content', {
            'fields': (
                'title',
                'slug',
                'seo_title', # MODIFIED: Added 'seo_title' here
                'content',
                'excerpt',
                'thumbnail',
                'author',
                'category',
                'tags',
                'is_published'
            )
        }),
        ('Download Settings', {
            'fields': (
                'enable_downloads',
                'download_section_title',
                'get_downloads_preview'
            ),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': ('get_total_downloads',),
            'classes': ('collapse',)
        }),
    )

    # WordPress Import Methods
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('import-wordpress/', self.admin_site.admin_view(self.import_wordpress), name='import_wordpress'),
        ]
        return custom_urls + urls
    
    def import_wordpress(self, request):
        if request.method == 'POST':
            form = ImportForm(request.POST, request.FILES)
            if form.is_valid():
                try:
                    # Save the uploaded file temporarily
                    xml_file = request.FILES['xml_file']
                    temp_path = os.path.join('/tmp', xml_file.name)
                    with open(temp_path, 'wb+') as destination:
                        for chunk in xml_file.chunks():
                            destination.write(chunk)
                    
                    # Run the import command with correct arguments
                    from django.core.management import call_command
                    call_command(
                        'import_wordpress', 
                        temp_path,
                        default_category=form.cleaned_data['default_category'].slug,
                        skip_existing=form.cleaned_data['skip_existing']
                    )
                    
                    messages.success(request, 'WordPress content imported successfully!')
                    return redirect('..')
                except Exception as e:
                    messages.error(request, f'Error during import: {str(e)}')
        else:
            form = ImportForm()
        
        context = {
            'form': form,
            'opts': self.model._meta,
            **self.admin_site.each_context(request),
        }
        return render(request, 'admin/wordpress_import.html', context)

    # Existing Admin Methods
    def get_thumbnail_preview(self, obj):
        if obj.thumbnail:
            return format_html(
                '<img src="{}" style="max-height: 100px; max-width: 100px; object-fit: cover;" />',
                obj.thumbnail.url
            )
        return "No thumbnail"
    get_thumbnail_preview.short_description = 'Thumbnail Preview'

    def get_total_downloads(self, obj):
        qualities = sum(q.download_count for q in obj.qualities.all())
        subtitles = sum(s.download_count for s in obj.subtitles.all())
        return format_html(
            "▶️ <b>Video:</b> {}<br>"
            "📝 <b>Subtitles:</b> {}",
            qualities,
            subtitles
        )
    get_total_downloads.short_description = '📊 Downloads'

    def get_downloads_preview(self, obj):
        if obj.enable_downloads:
            qualities = obj.qualities.count()
            subtitles = obj.subtitles.count()
            return format_html(
                "<div style='background:#f8f9fa;padding:10px;border-radius:5px;'>"
                "<b>Will display:</b> {}<br>"
                "<b>Qualities:</b> {}<br>"
                "<b>Subtitles:</b> {}"
                "</div>",
                obj.download_section_title,
                qualities or "None added",
                subtitles or "None added"
            )
        return "❌ Download section will be hidden"
    get_downloads_preview.short_description = 'Live Preview'

    def get_has_downloads(self, obj):
        return obj.enable_downloads
    get_has_downloads.boolean = True
    get_has_downloads.short_description = 'Downloads'

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('name', 'post', 'created_at', 'is_approved')
    list_filter = ('is_approved', 'created_at')
    list_editable = ('is_approved',)
    search_fields = ('name', 'email', 'comment')
    actions = ['approve_comments']

    def approve_comments(self, request, queryset):
        queryset.update(is_approved=True)
    approve_comments.short_description = "Approve selected comments"

@admin.register(HomepageSection)
class HomepageSectionAdmin(admin.ModelAdmin):
    filter_horizontal = ('categories',)
    list_display = ('title', 'enabled', 'display_order')
    list_editable = ('enabled', 'display_order')
    
@admin.register(Page)
class PageAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'is_published')
    prepopulated_fields = {'slug': ('title',)}
    search_fields = ('title', 'content')
    list_filter = ('is_published',)
    fieldsets = (
        (None, {
            'fields': ('title', 'slug', 'content', 'is_published')
        }),
    )