# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import jwt
from jwt import PyJWKClient
from flask import Flask, request, abort, Response

app = Flask(__name__)


@app.route('/', methods=['POST', 'GET'])
def hello_app():
    return Response(f"Hello, app #{app.config['APP_ID']}", mimetype='text/plain')


@app.before_request
def run_checks():
    app_id = verify_app_check(request.headers.get('X-Firebase-AppCheck'))
    if app_id is None:
        abort(401)
    app.config['APP_ID'] = app_id


def verify_app_check(token):
    if token is None:
        return None

    # Obtain the Firebase App Check Public Keys
    # Note: It is not recommended to hard code these keys as they rotate,
    # but you should cache them for up to 6 hours.
    url = "https://firebaseappcheck.googleapis.com/v1beta/jwks"

    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    header = jwt.get_unverified_header(token)
    # Ensure the token's header uses the algorithm RS256
    if header.get('alg') != 'RS256':
        return None
    # Ensure the token's header has type JWT
    if header.get('typ') != 'JWT':
        return None

    payload = {}
    try:
        # Verify the signature on the App Check token
        # Ensure the token is not expired
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            # Ensure the token's audience matches your project
            audience="projects/" + app.config["PROJECT_NUMBER"],
            # Ensure the token is issued by App Check
            issuer="https://firebaseappcheck.googleapis.com/" + \
            app.config["PROJECT_NUMBER"],
        )
    except:
        print(f'Unable to verify the token')

    # The token's subject will be the app ID, you may optionally filter against
    # an allow list
    return payload.get('sub')
