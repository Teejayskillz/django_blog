import feedparser
from django.utils import timezone
from django.utils.text import slugify
from core.models import Post
from core.models import FeedSource

import requests
from django.core.files.base import ContentFile
from bs4 import BeautifulSoup
import os

def get_image_from_entry(entry):
    # 1. media:content
    if hasattr(entry, "media_content"):
        media = entry.media_content
        if media and "url" in media[0]:
            return media[0]["url"]

    # 2. media:thumbnail
    if hasattr(entry, "media_thumbnail"):
        thumb = entry.media_thumbnail
        if thumb and "url" in thumb[0]:
            return thumb[0]["url"]

    # 3. enclosures
    if hasattr(entry, "enclosures") and entry.enclosures:
        if "url" in entry.enclosures[0]:
            return entry.enclosures[0]["url"]

    # 4. image inside summary HTML
    summary = entry.get("summary", "")
    if summary:
        soup = BeautifulSoup(summary, "html.parser")
        img = soup.find("img")
        if img and img.get("src"):
            return img["src"]

    return None

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

            # 🔥 SCRAPE FULL CONTENT
            full_content = scrape_full_article(link)
            content_to_save = full_content if full_content else entry.get("summary", "")

            post = Post.objects.create(
                title=title,
                slug=slug,
                content=content_to_save,
                excerpt=entry.get("summary", "")[:300],
                category=source.default_category,
                is_external=True,
                source=source,
                source_url=link,
                is_published=True,
            )

            # 🔥 FETCH FEATURED IMAGE
            image_url = get_image_from_entry(entry)
            if image_url:
                download_image(post, image_url)

        source.last_fetched = timezone.now()
        source.save()


def download_image(post, image_url):
    try:
        response = requests.get(image_url, timeout=10)
        if response.status_code == 200:
            filename = os.path.basename(image_url.split("?")[0])
            post.thumbnail.save(
                filename,
                ContentFile(response.content),
                save=True
            )
    except Exception as e:
        print("Image download failed:", e)


def scrape_full_article(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; FeedBot/1.0)"
        }
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            return None

        soup = BeautifulSoup(response.text, "html.parser")

        selectors = [
            "div.entry-content",
            "div.post-content",
            "div.td-post-content",
            "article"
        ]

        content_div = None
        for selector in selectors:
            content_div = soup.select_one(selector)
            if content_div:
                break

        if not content_div:
            return None

        # ❌ REMOVE UNWANTED TAGS COMPLETELY
        for tag in content_div.find_all([
            "script", "style", "iframe", "form",
            "aside", "nav", "footer", "header", "ins"
        ]):
            tag.decompose()

        # ❌ REMOVE COMMON AD / AUTHOR / SHARE CLASSES
        junk_classes = [
            "ads", "advert", "advertisement",
            "author", "author-box", "post-author",
            "share", "social", "related", "tags",
            "navigation", "breadcrumb", "comments"
        ]

        for div in content_div.find_all(True):
            class_list = " ".join(div.get("class", []))
            if any(junk in class_list.lower() for junk in junk_classes):
                div.decompose()

        # ✅ KEEP ONLY REAL CONTENT TAGS
        allowed_tags = ["p", "h1", "h2", "h3", "h4", "img", "ul", "ol", "li", "blockquote"]

        clean_html = ""
        for tag in content_div.find_all(allowed_tags, recursive=True):
            text = tag.get_text(strip=True)
            if text:
                clean_html += str(tag)

        # ❌ FINAL TEXT CLEANUP
        blacklist_phrases = [
            "The post",
            "first appeared on",
            "Related Posts",
            "Read more:",
            "Source:"
        ]

        for phrase in blacklist_phrases:
            if phrase.lower() in clean_html.lower():
                clean_html = clean_html.split(phrase)[0]

        return clean_html.strip()

    except Exception as e:
        print("Article scrape failed:", e)
        return None
