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

### Rapid Connect Return Format

The response from Rapid Connect has the following format:
#### header:
```json
{
 "typ": "JWT",
 "alg": "HS256"
}
```
#### payload:
```json
{
 "iat": 1544591261,
 "nbf": 1544591201,
 "exp": 1544591381,
 "jti": "7qJF7lNJSa_jYESzw773ohTnFfqheEUN",
 "typ": "authnresponse",
 "https://aaf.edu.au/attributes": {
   "cn": "Sample User's fullname",
   "displayname": "Sample user's full name",
   "surname": "SURNAME",
   "givenname": "sampleuser",
   "mail": "sampleuser@student.university.edu.au",
   "edupersonorcid": "",
   "edupersonscopedaffiliation": "student@university.edu.au;member@university.edu.au",
   "edupersonprincipalname": "sampleuser@university.edu.au",
   "edupersontargetedid": "https://rapid.test.aaf.edu.au!https://example.com/RapidConnectPath"
 },
 "iss": "https://rapid.test.aaf.edu.au",
 "aud": "https://example.com",
 "sub": "https://rapid.test.aaf.edu.au!https://example.com/RapidConnectPath"
}
```
#### signature:
A signature as per jwt specifications.


Here is the [full documentation](https://rapid.aaf.edu.au/developers) of Rapid Connect
