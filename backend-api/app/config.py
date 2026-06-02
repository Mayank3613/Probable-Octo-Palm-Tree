"""Probable-Octo-Palm-Tree Backend API Configuration"""

import os
_HOME_DIR = os.path.expanduser("~")
_APP_DIR = os.path.join(_HOME_DIR, ".octoplamtree")
os.makedirs(_APP_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(_APP_DIR, "probable_octo_threats.db")
APP_NAME = "Probable-Octo-Palm-Tree Threat Intelligence API"
VERSION = "1.0.0"
CORS_ORIGINS = ["*"]
MAX_EVENTS_PER_UPLOAD = 100
DEFAULT_PAGE_SIZE = 50
