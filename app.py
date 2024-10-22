import os
from flask import Flask, request, jsonify
import redis
import jwt
import datetime
from functools import wraps
from auth.routes import auth_bp
from dotenv import load_dotenv
from flask_cors import CORS


load_dotenv()   

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:5173", "https://your-frontend-domain.com",'*']}})

redis_client = redis.Redis(host='localhost', port=6379, db=0)
app.register_blueprint(auth_bp, url_prefix='/api/auth')
# Secret key to encode and decode JWT
app.config['JWT_SECRET'] =  os.getenv('JWT_SECRET')
app.config['JWT_TOKEN_LOCATION'] = ['headers']




if __name__ == '__main__':
    app.run(debug=True)
