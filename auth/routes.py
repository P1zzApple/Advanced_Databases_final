from flask import Blueprint, request, jsonify, current_app
import jwt
import bcrypt
from functools import wraps
from .token import sign_access_token, sign_refresh_token, decode_token
import redis
import json
import traceback

auth_bp = Blueprint('auth', __name__)
redis_client = redis.Redis(host='localhost',port=6379, db=0)

# Decorator to protect routes with JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403

        try:
            token = token.split(" ")[1]  # Extract the token part from "Bearer <token>"
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 403

        return f(current_user, *args, **kwargs)

    return decorated


# Route to register a new user
@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user and return a pair of access and refresh tokens.
    """
    try:
        data = request.json
        email = data.get('email')    
        username = data.get('username')
        password = data.get('password')
        region = data.get('region')

        salt = bcrypt.gensalt(rounds=12)
        encrypted_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    
        if redis_client.exists(f"user:{username}"):
            return jsonify({'message': 'User already exists!'}), 400
    
        new_user = {
            "username": str(username),
            "password": str(encrypted_password.decode('utf-8')),
            "email": str(email),
            "region": str(region)
        }
    
        access_token = sign_access_token(username)
        refresh_token = sign_refresh_token(username)

        # Generate both access and refresh tokens
        access_token = sign_access_token(username)
        refresh_token = sign_refresh_token(username)

        redis_client.set(f"user:{username}", json.dumps(new_user))
        redis_client.set(f"refresh_token:{username}", refresh_token, ex=60 * 60 * 24 * 7)

        return jsonify({
            'user': new_user,
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
    except Exception as e:
        traceback.print_exc()
        
        return jsonify({
            'message': str(e),
        }), 500



@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login user and return access and refresh tokens.
    """
    try:
        # Get user credentials from the request
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Check if the user exists in Redis
        user_data = redis_client.get(f"user:{username}")
        if not user_data:
            return jsonify({'message': 'User does not exist!'}), 404

        # Deserialize the user data from Redis
        user = json.loads(user_data)
        bcrypt.gensalt(rounds=12)
        hashed_password = user['password'].encode('utf-8')

        if not bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return jsonify({'message': 'Invalid credentials!'}), 401

        # Generate access and refresh tokens
        access_token = sign_access_token(username)
        refresh_token = sign_refresh_token(username)

        # Store refresh token in Redis with a 7-day expiration
        redis_client.set(f"refresh_token:{username}", refresh_token, ex=60 * 60 * 24 * 7)

        # Return tokens and user info
        return jsonify({
            'user': {
                'username': user['username'],
                'email': user['email'],
                'region': user['region']
            },
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200

    except Exception as e:
        print(e)
        traceback.print_exc()
        return jsonify({
            'message': str(e)
        }), 500


# Route to refresh the access token
@auth_bp.route('/token/refresh', methods=['POST'])
def refresh_token():
    """
    Refresh the access token using the refresh token.
    """
    try:
        # Extract the refresh token from the request
        data = request.json
        refresh_token = data.get('refresh_token')

        if not refresh_token:
            return jsonify({'message': 'Refresh token is missing!'}), 400

        # Decode the refresh token to get the username
        decoded_refresh_token = jwt.decode(refresh_token, current_app.config['REFRESH_SECRET_KEY'], algorithms=["HS256"])
        username = decoded_refresh_token['user']

        # Check if the stored refresh token in Redis matches the provided token
        stored_refresh_token = redis_client.get(f"refresh_token:{username}")
        if not stored_refresh_token or stored_refresh_token.decode() != refresh_token:
            return jsonify({'message': 'Invalid refresh token!'}), 403

        # Generate a new access token
        new_access_token = sign_access_token(username)

        return jsonify({
            'access_token': new_access_token
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired!'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token!'}), 403
    except Exception as e:
        return jsonify({
            'message': str(e)
        }), 500





# Example protected route
@auth_bp.route('/protected', methods=['GET'])
@token_required
def protected_route(user):
    """
    A protected route that requires a valid access token.
    """
    return jsonify({'message': f'Welcome, {user}! This is a protected route.'})
