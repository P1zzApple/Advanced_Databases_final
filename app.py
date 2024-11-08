import os
from flask import Flask, request, jsonify
import redis
import jwt
import datetime
from functools import wraps
from auth.routes import auth_bp
from categories import categories_bp
from dotenv import load_dotenv
from flask_cors import CORS


load_dotenv()   

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:5173", "https://your-frontend-domain.com",'*']}})

redis_client = redis.Redis(host='redis-17786.c232.us-east-1-2.ec2.redns.redis-cloud.com', port=17786, password='qaA9XpXI5NdIuHWrcluse37dzG0Ose7F')
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(categories_bp, url_prefix='/api/categories')
# Secret key to encode and decode JWT
app.config['JWT_SECRET'] =  os.getenv('JWT_SECRET')
app.config['JWT_TOKEN_LOCATION'] = ['headers']




if __name__ == '__main__':
    app.run(debug=True)
