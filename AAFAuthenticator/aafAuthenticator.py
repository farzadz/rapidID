"""
Base classes for Rapid Authenticator

"""

import os
import jwt
from tornado import gen, web
import base64
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Unicode, Bool, List



class AAFLoginHandler(BaseHandler):
    """Base class for login handler
    """
    def get(self):
        external_login_url = self.authenticator.get_external_login_url(self)
        self.log.info('AAF redirect: %r', external_login_url)
        # self.authorize_redirect(
        #     redirect_uri=redirect_uri
        # )
        self.redirect(external_login_url)


class AAFCallbackHandler(BaseHandler):
    """Basic handler for AAF Rapid Connect callback. Calls authenticator to verify username."""

    @gen.coroutine
    def post(self):
        self.log.info("Post body is: " + str(type(self.get_argument("assertion"))))
        user = yield self.login_user(data=self.get_argument("assertion"))
        if user is None:
            raise web.HTTPError(403)
        self.redirect(self.get_next_url(user))


class AAFAuthenticator(Authenticator):
    """Class for AAFAuthenticator

    login_service
    login_handler
    authenticate (method takes one arg - the request handler handling the oauth callback)
    """

    external_login_url = Unicode(
        os.getenv('AAF_LOGIN_LINK', ''),
        config=True,
        help="""Redirect login page.
             Typically `https://rapid.test.aaf.edu.au/jwt/authnrequest/research/{...}`"""
    )
    jwt_secret = Unicode(
        os.getenv('JWT_CALLBACK_SECRET', ''),
        config=True,
        help="""jwt secret used by AAF"""
    )

    login_service = 'AAF'
    # callback_url = Unicode(
    #     "https://juno-dev.aurin.org.au/hub/callback"
    # )

    def login_url(self, base_url):
        return url_path_join(base_url, 'login')

    login_handler = AAFLoginHandler
    callback_handler = AAFCallbackHandler
    
    def get_external_login_url(self, handler=None):
        """Get my AAF redirect URL
        Should be specified in configs
        """
        if self.external_login_url:
            return self.external_login_url
        else:
            raise ValueError("Specify a login url")

    def get_handlers(self, app):
        return [
            (r'/login', self.login_handler),
            (r'/callback', self.callback_handler),
        ]

    @gen.coroutine
    def authenticate(self, handler, data=None):

        self.log.info("Inside authenticate ***** {} data is: {}".format(type(data),str(data)))

        assertion = jwt.decode(data , self.jwt_secret, options={'verify_aud': False})
        self.log.info(str(assertion))
        assertion = assertion["https://aaf.edu.au/attributes"]
        return {'name': base64.b32encode(assertion['mail'].encode()).decode('utf-8')}

