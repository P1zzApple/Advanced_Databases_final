import jwt
import datetime
from flask import current_app



def sign_access_token(user):
    return jwt.encode({
        'user': user,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15) 
    }, current_app.config['SECRET_KEY'], algorithm="HS256")



def sign_refresh_token(user):
    return jwt.encode({
        'user': user,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    })


def decode_token(token):
    """
    Decodes a JWT token and returns the user if the token is valid.
    """
    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
        return data['user']
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token