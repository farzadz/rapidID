This is a Jupyterhub Authenticator for authenticating users via Australian Access Federation (AAF) 
using [RapidIdP](https://aaf.edu.au/rapid/).
To use it:

```pip install git+https://github.com/farzadz/rapidID.git```

Change the jupyterhub config file:

```
from AAFAuthenticator import aafAuthenticator
c.JupyterHub.authenticator_class = aafAuthenticator.AAFAuthenticator
c.AAFAuthenticator.external_login_url = "login url provided by AAF"
c.AAFAuthenticator.jwt_secret = "secret with which AAF jwt tokens signed"
```
The callback url in AAF admin panel should be set to "https://example.com/hub/callback".
Since AAF only redirects users to HTTPS enabled urls, you are required to obtain certificates prior to using this mechanism.
It uses base32 to encode email address of users as of their username with some alterations: Changes the encoded string to lowercase and removes succeeding `=` signs. 
