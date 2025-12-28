import feedparser
from django.utils import timezone
from django.utils.text import slugify
from core.models import Post
from .models import FeedSource

def fetch_feeds():
    sources = FeedSource.objects.filter(is_active=True)

    for source in sources:
        feed = feedparser.parse(source.feed_url)

        for entry in feed.entries:
            link = entry.get("link")
            title = entry.get("title", "").strip()

            if not link or not title:
                continue

            # Prevent duplicates
            if Post.objects.filter(source_url=link).exists():
                continue

            slug = slugify(title)[:190]

            if Post.objects.filter(slug=slug).exists():
                slug = f"{slug}-{int(timezone.now().timestamp())}"

            Post.objects.create(
                title=title,
                slug=slug,
                content=entry.get("summary", ""),
                excerpt=entry.get("summary", "")[:300],
                category=source.default_category,
                is_external=True,
                source=source,
                source_url=link,
                is_published=True,
            )

        source.last_fetched = timezone.now()
        source.save()
