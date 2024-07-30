from flask import Flask, redirect, request, session, url_for
import requests
import jwt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Keycloak Configuration
KEYCLOAK_SERVER_URL = 'https://keycloak.jakehomelab.com'
REALM_NAME = 'jakehomelab'
CLIENT_ID = 'test'
CLIENT_SECRET = '<secret_key>'
REDIRECT_URI = 'http://localhost:5000/callback'

# Decorator to protect routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return 'Welcome to the Flask App'

@app.route('/login')
def login():
    keycloak_auth_url = f"{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth"
    return redirect(f"{keycloak_auth_url}?client_id={CLIENT_ID}&response_type=code&scope=openid&redirect_uri={REDIRECT_URI}")

@app.route('/callback')
def callback():
    code = request.args.get('code')
    token_url = f"{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(token_url, data=data)
    token_response = response.json()

    # Decode the JWT token
    access_token = token_response.get('access_token')
    session['access_token'] = access_token
    decoded_token = jwt.decode(access_token, options={"verify_signature": False})
    session['user'] = decoded_token

    return redirect(url_for('protected'))

@app.route('/protected')
@login_required
def protected():
    return f"Hello, {session['user']['preferred_username']}!"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
