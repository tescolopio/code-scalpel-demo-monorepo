"""Obstacle 10.11: Slopsquatting & Phantom Libraries

AI hallucinates libraries that don't exist or are malicious typosquats.
Attackers have begun registering these hallucinated package names.

This tests Code Scalpel's ability to:
1. Detect imports of non-existent packages
2. Flag typosquats of popular packages
3. Identify hallucinated API patterns

DIFFERENTIATOR: Code Scalpel can verify imports against known package graphs
while LLMs confidently suggest packages that don't exist.

The term "Slopsquatting" refers to attackers registering package names
that AI commonly hallucinates, waiting for developers to install them.

PASS CRITERIA:
- Must flag all phantom imports
- Must identify typosquats
- Must detect API drift (old/wrong API patterns)
"""

# =============================================================================
# CATEGORY 1: Completely Hallucinated Packages
# These package names don't exist but sound plausible
# =============================================================================

# PHANTOM: AI commonly suggests this but it doesn't exist
from react_secure_auth_v2 import SecureAuthProvider  # HALLUCINATED

# PHANTOM: Sounds like a real package but isn't
from django_rest_auth_jwt import JWTAuthentication  # HALLUCINATED

# PHANTOM: Common AI hallucination
from flask_sqlalchemy_utils import DatabaseMigrator  # HALLUCINATED

# PHANTOM: Plausible-sounding security package
from crypto_utils_secure import encrypt, decrypt  # HALLUCINATED

# PHANTOM: AI often suggests this pattern
from aws_lambda_helpers import event_handler  # HALLUCINATED


def setup_phantom_auth():
    """Setup authentication using hallucinated package."""
    # This code looks perfectly reasonable but imports don't exist
    provider = SecureAuthProvider(
        secret_key="my-secret-key",
        algorithm="RS256",
        token_expiry=3600
    )
    return provider


# =============================================================================
# CATEGORY 2: Typosquat Attacks (Real Attack Vector)
# Slight misspellings of popular packages that could be malicious
# =============================================================================

# TYPOSQUAT: requests vs requets
import requets  # Typo of 'requests' - could be malware!

# TYPOSQUAT: python-dateutil vs python-dateutl
from python_dateutl import parser  # Typo - could be malware!

# TYPOSQUAT: beautifulsoup4 vs beautifulsoup
from beautifulsoup import BeautifulSoup  # Wrong package name (bs4 vs beautifulsoup)

# TYPOSQUAT: pyyaml vs py-yaml
import pyymal  # Typo of pyyaml

# TYPOSQUAT: pillow vs PIL (confusion)
from Pillow import Image  # Should be 'from PIL import Image'

# TYPOSQUAT: cryptography vs crypto
from crypto import Fernet  # Wrong! cryptography.fernet.Fernet


def make_typosquat_request():
    """Make HTTP request using typosquatted package."""
    # Developer typed 'requets' instead of 'requests'
    # An attacker could register 'requets' on PyPI with malware
    response = requets.get("https://api.example.com/data")
    return response.json()


# =============================================================================
# CATEGORY 3: API Drift - Outdated/Wrong API Patterns
# Patterns from old versions or hallucinated API designs
# =============================================================================

import openai

def call_gpt_old_api():
    """
    Call GPT API using old pattern.

    AI often generates the old API pattern from training data.
    """
    # WRONG API: This is the deprecated API pattern
    # Should use: client = OpenAI(); client.chat.completions.create()
    response = openai.Completion.create(  # DEPRECATED API!
        model="gpt-3.5-turbo",
        prompt="Hello",
        max_tokens=100
    )
    return response


def call_gpt_hallucinated_api():
    """AI hallucinated an API method that doesn't exist."""
    # HALLUCINATED: This method doesn't exist
    response = openai.chat.generate_response(  # NOT A REAL METHOD!
        messages=[{"role": "user", "content": "Hello"}],
        model="gpt-4"
    )
    return response


import pandas as pd

def pandas_api_drift():
    """Using deprecated pandas API."""
    df = pd.DataFrame({"a": [1, 2, 3]})

    # DEPRECATED: .append() was removed in pandas 2.0
    df = df.append({"a": 4}, ignore_index=True)

    # DEPRECATED: .ix is long removed
    value = df.ix[0, "a"]  # Should use .iloc or .loc

    return df


import numpy as np

def numpy_api_drift():
    """Using deprecated numpy API."""
    arr = np.array([1, 2, 3])

    # DEPRECATED: np.int removed in NumPy 1.24
    typed_arr = arr.astype(np.int)  # Should be np.int64 or int

    # DEPRECATED: np.str
    str_arr = np.array(["a", "b"]).astype(np.str)  # Should be np.str_

    return typed_arr


# =============================================================================
# CATEGORY 4: Framework Version Confusion
# Using patterns from wrong framework version
# =============================================================================

# Django 1.x pattern in Django 4.x codebase
from django.conf.urls import url  # DEPRECATED in Django 4.0, use path()

def django_old_urls():
    """URL patterns using deprecated syntax."""
    urlpatterns = [
        url(r'^users/$', views.user_list),  # Should use path()
        url(r'^users/(?P<pk>[0-9]+)/$', views.user_detail),  # path('<int:pk>/')
    ]
    return urlpatterns


# Flask pattern confusion
from flask import Flask
app = Flask(__name__)

@app.route('/data')
def flask_old_pattern():
    """Using deprecated Flask patterns."""
    from flask import request

    # DEPRECATED: request.json without checking content-type first
    # Can raise 400 error if content-type is wrong
    data = request.json  # Should use request.get_json(force=True) or check first

    # DEPRECATED: before_request without app context handling
    return data


# SQLAlchemy 1.x pattern in 2.x
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def sqlalchemy_old_pattern():
    """Using deprecated SQLAlchemy patterns."""
    engine = create_engine("sqlite:///db.sqlite")

    # DEPRECATED in 2.0: query() on session
    # Session = sessionmaker(bind=engine)
    # session = Session()
    # users = session.query(User).filter_by(active=True).all()

    # DEPRECATED: commit() after query without explicit transaction
    pass


# =============================================================================
# CATEGORY 5: Hallucinated Standard Library Functions
# Functions that don't exist in Python stdlib
# =============================================================================

import os
import json
import hashlib

def stdlib_hallucinations():
    """Using hallucinated stdlib functions."""

    # HALLUCINATED: os.walk_files doesn't exist
    # for f in os.walk_files("/path"):  # NOT REAL!

    # HALLUCINATED: json.parse doesn't exist (it's json.loads)
    # data = json.parse('{"key": "value"}')  # JavaScript pattern!

    # HALLUCINATED: hashlib.hash doesn't exist
    # h = hashlib.hash("sha256", data)  # Should be hashlib.sha256()

    # HALLUCINATED: str.contains doesn't exist (it's 'in' operator)
    # if text.contains("keyword"):  # Java/JS pattern!

    pass


# =============================================================================
# CATEGORY 6: Copy-Paste from Wrong Language
# JavaScript/Java/Go patterns pasted into Python
# =============================================================================

def javascript_patterns_in_python():
    """
    AI sometimes generates JavaScript patterns in Python.
    Common when training data mixes languages.
    """
    data = {"key": "value"}

    # WRONG: JavaScript-style property access
    # value = data.key  # Should be data["key"] in Python

    # WRONG: const/let don't exist
    # const MAX_SIZE = 100  # Should be MAX_SIZE = 100 or caps

    # WRONG: === doesn't exist
    # if x === y:  # Should be x == y or 'is'

    # WRONG: console.log doesn't exist
    # console.log("debug")  # Should be print()

    pass


def java_patterns_in_python():
    """Java patterns that don't work in Python."""

    # WRONG: new keyword
    # user = new User()  # Should be User()

    # WRONG: public/private keywords
    # public def method():  # Just def method():

    # WRONG: System.out.println
    # System.out.println("Hello")  # Should be print()

    # WRONG: .length() method on arrays
    # arr.length()  # Should be len(arr)

    pass


# =============================================================================
# EXPECTED VERDICTS
# =============================================================================

SLOPSQUATTING_PATTERNS = {
    # Phantom packages
    "react_secure_auth_v2": ("Phantom Package", "CRITICAL", "Does not exist on npm/PyPI"),
    "django_rest_auth_jwt": ("Phantom Package", "CRITICAL", "Does not exist"),
    "flask_sqlalchemy_utils": ("Phantom Package", "CRITICAL", "Does not exist"),
    "crypto_utils_secure": ("Phantom Package", "CRITICAL", "Does not exist"),
    "aws_lambda_helpers": ("Phantom Package", "HIGH", "Does not exist"),

    # Typosquats
    "requets": ("Typosquat", "CRITICAL", "Typo of 'requests'"),
    "python_dateutl": ("Typosquat", "CRITICAL", "Typo of 'python-dateutil'"),
    "beautifulsoup": ("Wrong Package", "HIGH", "Should be 'beautifulsoup4' or 'bs4'"),
    "pyymal": ("Typosquat", "CRITICAL", "Typo of 'pyyaml'"),
    "Pillow import": ("Wrong Import", "MEDIUM", "Should be 'from PIL import Image'"),
    "crypto": ("Wrong Package", "HIGH", "Should be 'cryptography'"),

    # API Drift
    "openai.Completion.create": ("Deprecated API", "HIGH", "Old OpenAI API pattern"),
    "openai.chat.generate_response": ("Hallucinated API", "CRITICAL", "Method doesn't exist"),
    "df.append": ("Deprecated API", "MEDIUM", "Removed in pandas 2.0"),
    "df.ix": ("Deprecated API", "HIGH", "Removed long ago"),
    "np.int": ("Deprecated", "MEDIUM", "Removed in NumPy 1.24"),
    "django.conf.urls.url": ("Deprecated", "MEDIUM", "Use django.urls.path"),
}
