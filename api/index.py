# api/index.py

import os
from flask import Flask

# Assume your main application logic is in app.py
# If your app instance is defined here, you can skip the import
from app import app  
# Vercel needs a handler function called 'handler'
# that serves your Flask application
def handler(environ, start_response):
    return app(environ, start_response)