from flask import Flask, request, jsonify
import redis
import jwt
import datetime
from functools import wraps
from auth.routes import auth_bp


app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0)
app.register_blueprint(auth_bp, url_prefix='/auth')
# Secret key to encode and decode JWT
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET'] =  'key'
app.config['JWT_TOKEN_LOCATION'] = ['headers']




if __name__ == '__main__':
    app.run(debug=True)
