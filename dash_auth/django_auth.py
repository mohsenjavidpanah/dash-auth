import base64

import requests
import flask

from .auth import Auth


class DjangoAuth(Auth):
    def __init__(self, app, login_endpoint_url):
        Auth.__init__(self, app)
        self._endpoint_url = login_endpoint_url

    def is_authorized(self):
        auth_header = flask.request.headers.get('Authorization', None)
        if not auth_header:
            return False

        response = requests.post(
            self._endpoint_url,
            HTTP_AUTHORIZATION=auth_header,
            timeout=10
        )
        return response.status_code == 200

    def login_request(self):
        return flask.Response(
            'Login Required',
            headers={'WWW-Authenticate': 'Basic realm="User Visible Realm"'},
            status=401)

    def auth_wrapper(self, f):
        def wrap(*args, **kwargs):
            if not self.is_authorized():
                return flask.Response(status=403)

            response = f(*args, **kwargs)
            return response
        return wrap

    def index_auth_wrapper(self, original_index):
        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return self.login_request()
        return wrap
