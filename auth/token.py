import jwt
import datetime
from flask import current_app



def sign_access_token(user):
    return jwt.encode(
        key=current_app.config['JWT_SECRET'],
        algorithm="HS256",
        payload=
        {
            'user': user,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }
    )



def sign_refresh_token(user):
    return jwt.encode(
        key=current_app.config['JWT_SECRET'],
        algorithm="HS256",
        payload=
        {
            'user': user,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
    )


def decode_token(token):
    """
    Decodes a JWT token and returns the user if the token is valid.
    """
    try:
        data = jwt.decode(token, current_app.config['JWT_SECRET'], algorithms=["HS256"])
        return data['user']
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token