"""Local test-only shim: feedparser is not installable in this sandbox.

The real dependency is declared in requirements.txt and is installed on the
production host.  Tests never call the feed import code path.
"""

__version__ = "0.0.0-local-shim"


class FeedParserDict(dict):
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)


def parse(url=None, *args, **kwargs):
    return FeedParserDict(entries=[], feed=FeedParserDict(), bozo=False)
