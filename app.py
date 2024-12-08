from flask import Flask, redirect, session, url_for, request, render_template, jsonify
import google_auth_oauthlib.flow
import json
import os
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from flask_frozen import Freezer

# Simulación de preguntas con alternativas
QUESTIONS = [
    {
        "question": "¿Cuál es el lenguaje de programación más utilizado en el mundo?",
        "options": ["Python", "JavaScript", "C++", "Java"],
        "answer": "Python"
    },
    {
        "question": "¿Qué planeta es conocido como el planeta rojo?",
        "options": ["Venus", "Saturno", "Marte", "Mercurio"],
        "answer": "Marte"
    },
    {
        "question": "¿Quién pintó la Mona Lisa?",
        "options": ["Leonardo da Vinci", "Van Gogh", "Pablo Picasso", "Miguel Ángel"],
        "answer": "Leonardo da Vinci"
    },
    {
        "question": "¿En qué año llegó el hombre a la luna?",
        "options": ["1969", "1955", "1973", "1980"],
        "answer": "1969"
    },
]

app = Flask(__name__)
freezer = Freezer(app)
# `FLASK_SECRET_KEY` is used by sessions. You should create a random string
# and store it as secret.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)

# `GOOGLE_APIS_OAUTH_SECRET` contains the contents of a JSON file to be downloaded
# from the Google Cloud Credentials panel. See next section.
# Obtener la ruta del archivo desde la variable de entorno
file_path = os.environ.get('GOOGLE_OAUTH_SECRETS')
with open(file_path, 'r') as file:
    oauth_config = json.load(file)

# This sets up a configuration for the OAuth flow
oauth_flow = google_auth_oauthlib.flow.Flow.from_client_config(
    oauth_config,
    # scopes define what APIs you want to access on behave of the user once authenticated
    scopes=[
        "https://www.googleapis.com/auth/userinfo.email",
        "openid", 
        "https://www.googleapis.com/auth/userinfo.profile",
    ]
)

# This is entrypoint of the login page. It will redirect to the Google login service located at the
# `authorization_url`. The `redirect_uri` is actually the URI which the Google login service will use to
# redirect back to this app.
@app.route('/signin')
def signin():
    # We rewrite the URL from http to https because inside the Repl http is used, 
    # but externally it's accessed via https, and the redirect_uri has to match that
    oauth_flow.redirect_uri ="https://jubilant-palm-tree-pjqg56rrr6x27vpq-5000.app.github.dev/oauth2callback"
    authorization_url, state = oauth_flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

# This is the endpoint that Google login service redirects back to. It must be added to the "Authorized redirect URIs"
# in the API credentials panel within Google Cloud. It will call a Google endpoint to request
# an access token and store it in the user session. After this, the access token can be used to access
# APIs on behalf of the user.
@app.route('/oauth2callback')
def oauth2callback():
    if not session['state'] == request.args['state']:
        return 'Invalid state parameter', 400
    oauth_flow.fetch_token(authorization_response=request.url.replace('http:', 'https:'))
    session['access_token'] = oauth_flow.credentials.token
    return redirect("/")

# This is the home page of the app. It directs the user to log in if they are not already.
# It shows the user info's information if they already are.
@app.route('/')
def welcome():
    if "access_token" in session:
        user_info = get_user_info(session["access_token"])
        if user_info:
            return render_template("index.html", user_info=user_info)
    return redirect(url_for('register'))

@app.route('/register')
def register():
    return render_template("signin.html")

# Call the userinfo API to get the user's information with a valid access token.
# This is the first example of using the access token to access an API on the user's behalf.
def get_user_info(access_token):
    response = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={
       "Authorization": f"Bearer {access_token}"
   })
    if response.status_code == 200:
        user_info = response.json()
        return user_info
    else:
        print(f"Failed to fetch user info: {response.status_code} {response.text}")
        return None

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

def validate_google_token(token):
    """
    Valida un token de Google.
    Puede ser un access token o un ID token.
    Args:
        token (str): El token de acceso o ID token.
    Returns:
        dict: Información del token si es válido, o un mensaje de error.
    """
    try:
        # Intentar validar como ID token (JWT)
        client_id = os.environ.get("GOOGLE_CLIENT_ID")
        if not client_id:
            return {"valid": False, "error": "Missing GOOGLE_CLIENT_ID in environment variables"}

        # Intentar validación como ID token (JWT)
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            client_id
        )
        return {"valid": True, "type": "id_token", "user_info": idinfo}

    except ValueError:
        # Si no es un ID token, intentamos validarlo como Access Token
        response = requests.get(f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}")
        if response.status_code == 200:
            token_info = response.json()
            return {"valid": True, "type": "access_token", "token_info": token_info, "Preguntas": QUESTIONS}
        else:
            return {"valid": False, "error": response.json().get("error_description", "Invalid token")}

@app.route('/validate-token', methods=['POST'])
def validate_token():
    # Obtener el token de la sesión
    access_token = session.get('access_token')
    if not access_token:
        return jsonify({"error": "No token found in session"}), 401

    # Validar el token
    result = validate_google_token(access_token)
    return jsonify(result), (200 if result["valid"] else 400)


# Congelar la aplicación
if __name__ == '__main__':
    freezer.freeze()  # Congela la aplicación en archivos estáticos
    #app.run(debug=True)