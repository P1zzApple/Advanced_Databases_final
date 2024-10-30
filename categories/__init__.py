from flask import Blueprint

# Create the Blueprint for categories
categories_bp = Blueprint('categories', __name__)

# Import the routes
from . import routes
