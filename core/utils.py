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

def paragraph_score(text):
    score = 0
    length = len(text)

    if length > 120:
        score += 3
    elif length > 60:
        score += 1

    if re.match(r"^[a-z]+ \d{1,2}, \d{4}$", text.lower()):
        score -= 5

    if text.lower().startswith("by ") and len(text.split()) <= 4:
        score -= 5

    junk_phrases = [
        "don't miss",
        "you may like",
        "related posts",
        "breaking:",
        "read also",
        "advertisement",
        "source:"
    ]

    if any(j in text.lower() for j in junk_phrases):
        score -= 5

    return score

def extract_article_body(container):
    collecting = False
    article_parts = []
    confidence = 0
    negative_hits = 0

    for tag in container.find_all(["p", "h2", "h3", "blockquote"], recursive=True):
        text = tag.get_text(strip=True)
        if not text:
            continue

        score = paragraph_score(text)

        # START detection
        if not collecting and score >= 2:
            collecting = True

        if collecting:
            # Count junk only if repeated
            if score <= -4:
                negative_hits += 1
                if negative_hits >= 2:
                    break
                continue

            article_parts.append(str(tag))

    html = "".join(article_parts)
    return html if len(html) > 600 else None



def rewrite_content(html, max_sentences=6):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)

    sentences = re.split(r'(?<=[.!?])\s+', text)
    if len(sentences) <= max_sentences:
        return html

    selected = sentences[:max_sentences]
    rewritten = " ".join(selected)

    return f"<p>{rewritten}</p>"


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

        container = None
        for selector in selectors:
            container = soup.select_one(selector)
            if container:
                break

        if not container:
            return None

        # REMOVE obvious junk containers
        for tag in container.find_all([
            "time", "header", "footer", "nav",
            "aside", "script", "style", "iframe"
        ]):
            tag.decompose()

        raw_html = extract_article_body(container)
        if not raw_html:
            return None

        # SAFE REWRITE
        return rewrite_content(raw_html)

    except Exception as e:
        print("Article scrape failed:", e)
        return None
