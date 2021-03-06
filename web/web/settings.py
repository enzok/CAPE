# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import os

try:
    import re2 as re
except ImportError:
    import re

# Cuckoo path.
CUCKOO_PATH = os.path.join(os.getcwd(), "..")
sys.path.append(CUCKOO_PATH)
from lib.cuckoo.common.config import Config


cuckoo_cfg = Config()
rep_cfg = Config("reporting")
aux_cfg = Config("auxiliary")
vtdl_cfg = aux_cfg.virustotaldl
zip_cfg = aux_cfg.zipped_download
moloch_cfg = rep_cfg.moloch

# Error handling for database backends
if not rep_cfg.mongodb.get("enabled") and not rep_cfg.elasticsearchdb.get("enabled"):
    raise Exception("No database backend reporting module is enabled! Please enable either ElasticSearch or MongoDB.")

if rep_cfg.mongodb.get("enabled") and rep_cfg.elasticsearchdb.get("enabled") and \
    not rep_cfg.elasticsearchdb.get("searchonly"):
    raise Exception("Both database backend reporting modules are enabled. Please only enable ElasticSearch or MongoDB.")

# Enable Django authentication for website
WEB_AUTHENTICATION = False

# Get connection options from reporting.conf.
MONGO_HOST = rep_cfg.mongodb.get("host", "127.0.0.1")
MONGO_PORT = rep_cfg.mongodb.get("port", 27017)
MONGO_DB = rep_cfg.mongodb.get("db", "cuckoo")
MONGO_USER = rep_cfg.mongodb.get("username", None)
MONGO_PASS = rep_cfg.mongodb.get("password", None)

ELASTIC_HOST = rep_cfg.elasticsearchdb.get("host", "127.0.0.1")
ELASTIC_PORT = rep_cfg.elasticsearchdb.get("port", 9200)
ELASTIC_INDEX = rep_cfg.elasticsearchdb.get("index", "cuckoo")

MOLOCH_BASE = moloch_cfg.get("base", None)
MOLOCH_NODE = moloch_cfg.get("node", None)
MOLOCH_ENABLED = moloch_cfg.get("enabled", False)

GATEWAYS = aux_cfg.get("gateways")
VTDL_ENABLED = vtdl_cfg.get("enabled", False)
VTDL_PRIV_KEY = vtdl_cfg.get("dlprivkey", None)
VTDL_INTEL_KEY = vtdl_cfg.get("dlintelkey", None)
VTDL_PATH = vtdl_cfg.get("dlpath", None)

ZIP_PWD = zip_cfg.get("zip_pwd", "inf3ct3d")

CUCKOO_HOST = "cuckoo01"
CUCKOO_PORT = "8090"

TEMP_PATH = cuckoo_cfg.cuckoo.get("tmppath", "/tmp")

DLNEXEC = aux_cfg.dlnexec.get("enabled", False)

ipaddy_re = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

if GATEWAYS:
    GATEWAYS_IP_MAP = {}
    for e in GATEWAYS:
        if "," in e:
            continue
        elif ipaddy_re.match(GATEWAYS[e]):
            GATEWAYS_IP_MAP[GATEWAYS[e]]=e  
 

# Enabled/Disable Zer0m0n tickbox on the submission page
OPT_ZER0M0N = False


# To disable comment support, change the below to False
COMMENTS = True

DEBUG = False

# Database settings. We don't need it.
DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': 'siteauth.sqlite'
            }
        }

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# Disabling time zone support and using local time for web interface and storage.
# See: https://docs.djangoproject.com/en/1.5/ref/settings/#time-zone
USE_TZ = False
TIME_ZONE = None

# Unique secret key generator.
# Secret key will be placed in secret_key.py file.
try:
    from secret_key import *
except ImportError:
    SETTINGS_DIR=os.path.abspath(os.path.dirname(__file__))
    # Using the same generation schema of Django startproject.
    from django.utils.crypto import get_random_string
    key = get_random_string(50, "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)")

    # Write secret_key.py
    with open(os.path.join(SETTINGS_DIR, "secret_key.py"), "w") as key_file:
        key_file.write("SECRET_KEY = \"{0}\"".format(key))

    # Reload key.
    from secret_key import *

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    os.path.join(os.getcwd(), 'static'),
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Template class for starting w. django 1.10
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            "templates",
        ],
        "OPTIONS": {
            "debug": True,
            "context_processors": [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
            "loaders": [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
            ]
        },
    },
]


MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # Cuckoo headers.
    'web.headers.CuckooHeaders',
    'ratelimit.middleware.RatelimitMiddleware',
)

ROOT_URLCONF = 'web.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'web.wsgi.application'

RATELIMIT_VIEW = 'api.views.limit_exceeded'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    #'django.contrib.sites',
    #'django.contrib.messages',
    'django.contrib.staticfiles',
    # Uncomment the next line to enable the admin:
    'django.contrib.admin',
    # Uncomment the next line to enable admin documentation:
    # 'django.contrib.admindocs',
    'analysis',
    'compare',
    'api',
    'ratelimit',
)

LOGIN_REDIRECT_URL = "/"

# Fix to avoid migration warning in django 1.7 about test runner (1_6.W001).
# In future it could be removed: https://code.djangoproject.com/ticket/23469
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s %(levelname)s [%(name)s:%(lineno)s] %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        }
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'cuckoo_web': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'verbose',
            'filename': '/opt/cuckoo/log/cuckoo_web.log',
            'maxBytes': 1024 * 1024 * 16,  # 16 mb
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
        'django': {
            'level': 'INFO',
            'handlers': ['cuckoo_web'],
            'propagate': False,
        },
        'gunicorn': {
            'level': 'DEBUG',
            'handlers': ['cuckoo_web'],
            'propagate': False,
        },
    }
}

# Hack to import local settings.
try:
    LOCAL_SETTINGS
except NameError:
    try:
        from local_settings import *
    except ImportError:
        pass
