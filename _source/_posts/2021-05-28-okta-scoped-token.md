---
layout: blog_post
title: Creating and using a scoped API token with Okta
author: phill-edwards
by: contractor
communities: [python]
description: ""
tags: [python]
tweets:
- ""
- ""
image: blog/
type: conversion
...

APIs such as Oktas are usually accessed using an API token. These pose several security risks. The API tokens give access to all APIs and don't allow fine-grained access control. The tokens don't expire, so changing them requires updating all applications that use them. This is particularly a problem if the token is compromised.

Okta can provide *OAuth for Okta* tokens. These do allow for finely scoped access to APIs. They also have expiry dates.

Today, we will create and use a scoped access token that can only use the Okta API to read logs. Let's get started.

**PS**: The code for this project can be found on [GitHub](https://github.com/Dr-Phill-Edwards/okta-scoped-token-example.git).

## Prerequisistes for developing an application

{% include setup/cli.md type="web" loginRedirectUri="http://localhost:8080/callback" %}

In the Okta console select `Applications` and your application. In the `Okta API Scopes` tab, grant access to `okta.logs.read`.

If you don't already have Python installed on your computer, you will need to [install a recent version of Python 3](https://www.python.org/downloads/).

Next, create a directory where all of our future code will live.

```bash
mkdir okta-scoped-token-example
cd okta-scoped-token-example
```

Finally, install the Tornado package.

```bash
pip install tornado
```

## How to set up the environment

We need to provide some credentials to authenticate users. As these are secrets a good way of providing them is using environment variables. Create the following environment variables using values obtained from the Okta Developer Console:

```bash
export OKTA_DOMAIN=https://dev-123456.okta.com
export OKTA_OAUTH2_ISSUER=https://dev-123456.okta.com/oauth2/default
export OKTA_OAUTH2_CLIENT_ID=0...6
export OKTA_OAUTH2_CLIENT_SECRET=w...b
export OKTA_REDIRECT_URL=http://localhost:8080/callback
```

## How to authenticate a user in Python

We need to authenticate users using Okta's OAuth 2.0 protocols. We are going to start by creating a helper class that communicates with the Okta APIs. Create a file called `OktaAPI.py` with the following Python code:

```python
import base64
import os
import requests
import secrets
import sys
from urllib.parse import urlencode

class OktaAPI:
    def __init__(self):
        self.state = secrets.token_hex(5)
        self.domain = self.getenv('OKTA_DOMAIN')
        self.issuer = self.getenv('OKTA_OAUTH2_ISSUER')
        self.client_id = self.getenv('OKTA_OAUTH2_CLIENT_ID')
        self.client_secret = self.getenv('OKTA_OAUTH2_CLIENT_SECRET')
        self.redirect_uri = self.getenv('OKTA_OAUTH2_REDIRECT_URI')
        credentials = self.client_id + ':' + self.client_secret
        credentials_b64 = base64.b64encode(credentials.encode('utf-8'))
        self.auth_header = 'Basic: ' + credentials_b64.decode('utf-8')
        self.getEndpoints()
        
    def getenv(self, envvar):
        value = os.environ.get(envvar)
        if value is None:
            print('Environment variable %s must be defined' % envvar)
            sys.exit(1)
        return value

    def getEndpoints(self):
        response = requests.get(self.domain + '/.well-known/oauth-authorization-server')
        self.endpoints = response.json()

    def generateLoginURL(self):
        params = { 'response_type': 'code',
                   'client_id': self.client_id,
                   'redirect_uri': self.redirect_uri,
                   'state': self.state,
                   'scope': 'openid offline_access okta.logs.read'
                 }
        query = urlencode(params)
        url = self.endpoints['authorization_endpoint'] + '?' + query
        return url

if __name__ == '__main__':
    api = OktaAPI()
    print(api.generateLoginURL())
```

So, what is happening here? A class called `OktaAPI` is created. The constructor `__init__()` first creates a random hexadecimal string that will be used to improve authentication security. It then reads the environment variables we created earlier. It then creates an authentication header from the client ID and the client secret. It then obtains the dictionary of endpoints from the Okta application.

The `getenv()` method reads environment variables and exits with an error if the environment variable doesn't exist.

The `getendpoints()` method requests a dictionary of API endpoints from a well known URL for the Okta organization. This is imporant as only the organization authorization server can create tokens with the correct scopes.

The `generateLoginURL()` method creates a GET URL from the authorization endpoint, the client ID, the redirect URI, and the random state string. It requests a code on successful login that will be exchanged for an access token.

**PS:** It is important that all of the API scopes that the access token needs to use are spcified in the `scope` parameter of the URL.

The final three lines are for test purposes. If the file is run as a Python program, it will construct an `OktaAPI` object and print out the login URL. We can test this by running it:

```bash
python3 OktaAPI.py
```

The URL should be printed out.

## How to set API scopes for the application

On the Okta Developer Console, select `Applications` and your application. Select the `Okta API Scopes` tab and hit `Grant` for `okta.logs.read`.