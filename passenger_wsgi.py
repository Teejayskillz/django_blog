import os
import sys

# --- VERIFY THIS SECTION CAREFULLY ---

# 1. Add your application root to the Python path.
# This should be the directory that contains 'manage.py' and your main Django project folder (e.g., 'blog_project').
# Based on your venv path, it appears to be: /home/hypeblog/hypeblog9jatv.com.ng
PROJECT_ROOT = '/home/hypeblog/hypeblog9jatv.com.ng' # <--- CONFIRM THIS IS YOUR ACTUAL PROJECT ROOT
sys.path.insert(0, PROJECT_ROOT)

# 2. Point to your virtual environment's Python interpreter.
# This path is usually found in cPanel's "Setup Python App" under your app details.
# Based on your venv path: /home/hypeblog/virtualenv/hypeblog9jatv.com.ng/3.9/bin/python
INTERP = "/home/hypeblog/virtualenv/hypeblog9jatv.com.ng/3.9/bin/python" # <--- CONFIRM THIS EXACT PATH
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

# 3. Set the DJANGO_SETTINGS_MODULE environment variable.
# 'your_django_project_name' should be the name of your Django project's main folder
# (the one that contains settings.py, urls.py, wsgi.py).
# From previous context, it was 'blog_project'. If you renamed it, update this.
os.environ['DJANGO_SETTINGS_MODULE'] = 'blog_project.settings' # <--- CONFIRM YOUR DJANGO PROJECT FOLDER NAME

# --- END VERIFICATION SECTION ---


from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()