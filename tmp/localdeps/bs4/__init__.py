"""Local test-only shim for BeautifulSoup (not installable in this sandbox)."""


class _Tag:
    def get(self, name, default=None):
        return default

    def find(self, *args, **kwargs):
        return None

    def find_all(self, *args, **kwargs):
        return []


class BeautifulSoup(_Tag):
    def __init__(self, markup="", features=None, **kwargs):
        self.markup = markup

    def __str__(self):
        return self.markup
