# Learn OAuth2.0 

## How to use it

1. Clone repo and `npm install`
2. Set environment variables in `.env` with all the API keys of respective oAuth2 providers
3. Run `npm start`
4. Open the link in browser to start exploring oAuth2.0 workflows of Twitter, Github, Google, etc.


# References

## Overview

OAuth2.0 is an authorization framework to enable third-party application obtain limited access to HTTP service

[The OAuth 2.0 Authorization Framework - RFC 6749](https://tools.ietf.org/html/rfc6749)

## Types of authorization grants

### Client Credentials Flow

#### Twitter example : Search recent tweets

**1. Get Bearer token from twitter auth server using client credentials**

```
curl -u 'gfdsfdsuTpZgc:GBddYKB2Eqjsdf8fdK6kidlj' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

**2. Making request using bearer token | Get recent search**

```
curl -X GET -H "Authorization: Bearer AAsdaVIFNgxQ2eSuiOpEnlQt" "https://api.twitter.com/labs/2/tweets/search?tweet.fields=created_at,author_id,lang&query=from%3Atwitterdev%20has%3Amedia"
```

**References**


### Authorization Code Grant Flow

#### Github example : Star a repository

Assuming, you have received your client id and client secret from github by registering your application

**1. Request a user's GitHub identity by redirecting to the url**

```
GET https://github.com/login/oauth/authorize?client_id=cliend_id&redirect_uri=registered_redirect_uri&scope=public_repo user&state=csrf_token
```

**2. Users are redirected back to your redirect_uri with authorization code in param, get the access token using this code**

```
POST https://github.com/login/oauth/access_token

//body
client_id=consumer_key,
client_secret=consumer_secret,
code=authorization_code,
state=csrf_token

//Response
access_token=e72edsfdsfb4a&token_type=bearer
```

**3. Use the access token to access the API**

```
curl -H "Authorization: token OAUTH-TOKEN" https://api.github.com/user
```

**References**

[Authorizing github oauth apps](https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps)

[Scope for github oauth apps](https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/)

### Implicit Grant Flow

#### Google Calendar API example: Getting calendar settings

**1. Redirect user to Google's OAuth 2.0 server**

```
https://accounts.google.com/o/oauth2/v2/auth?
 scope=https://www.googleapis.com/auth/calendar.settings.readonly&
 include_granted_scopes=true&
 response_type=token&
 state=state_parameter_passthrough_value&
 redirect_uri=https%3A//oauth2.example.com/code&
 client_id=client_id
```

**2. Google auth server redirects to client redirect uri with token in uri frgment**

```
http:/localhost:3000/callback#state=satefsad&access_token=4/P7q7W91&token_type=Bearer&expires_in=3600
```

**3. Call Google Calendar API for data from browser**

```
GET https://www.googleapis.com/calendar/v3/users/me/settings?access_token=access_token
```

**References**

[Google OAuth2.0 for Client-Side Web Applications - Implicit Flow](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow)

[Google Calendar API - Settings](https://developers.google.com/calendar/v3/reference/settings/list)

# Learn OpenID Connect - Authentication layer on top of OAuth2.0 protocol

## Overview

[OpenID Connect core spec](https://openid.net/specs/openid-connect-core-1_0.html)

[OpenID Connect home - contains more specs on logout, sessions management, etc.](https://openid.net/connect/)


## Types of flow

### Authentication using the Authorization Code Flow

#### Google OpenIDConnect example : Sign-in with Google

**1. Send an authentication request to Google**

```
https://accounts.google.com/o/oauth2/v2/auth?
 response_type=code&
 client_id=424911365001.apps.googleusercontent.com&
 scope=openid%20email&
 redirect_uri=https%3A//oauth2.example.com/code&
 state=security_token%3D138r5719ru3e1%26url%3Dhttps%3A%2F%2Foauth2-login-demo.example.com%2FmyHome&
 login_hint=jsmith@example.com&
 nonce=0394852-3190485-2490358&
 access_type=offline&
 hd=example.com
```

**2. Google sends code to redirect_uri**

```
https://oauth2.example.com/code?state=security_token%3D1du3e1%26url%3Dhttps%3A%2F%2Foa2cb.example.com%2FmyHome&code=4/P7sem6bTrgtp7&scope=openid%20email%20https://www.googleapis.com/auth/userinfo.email
```


**3. Exchange code for access token and ID token**

```
POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-Type: application/x-www-form-urlencoded

code=4/P7q7W91a-oMsCeLvIaQm6bTrgtp7&
client_id=your-client-id&
client_secret=your-client-secret&
redirect_uri=https%3A//oauth2.example.com/code&
grant_type=authorization_code   

// RESPONSE
access_token	A token that can be sent to a Google API.
expires_in	The remaining lifetime of the access token in seconds.
id_token	A JWT that contains identity information about the user that is digitally signed by Google.
scope	The scopes of access granted by the access_token expressed as a list of space-delimited, case-sensitive strings.
token_type	Identifies the type of token returned. At this time, this field always has the value Bearer.
refresh_token	This field is only present if the access_type parameter was set to offline in the authentication request. For details, see Refresh tokens.


```



**4. Client validates the ID token and obtains user info**

* Verify ID token is signed by the issuer
* Verify that the value of the iss claim in the ID token is equal to https://accounts.google.com or accounts.google.com.
* Verify that the value of the aud claim in the ID token is equal to your app's client ID.
* Verify that the expiry time (exp claim) of the ID token has not passed.


```
{
  "iss": "https://accounts.google.com",
  "azp": "123s19200.apps.googleusercontent.com",
  "aud": "123s7819200.apps.googleusercontent.com",
  "sub": "10769150350006150715113082367",
  "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
  "hd": "example.com",
  "email": "jsmith@example.com",
  "email_verified": "true",
  "iat": 1353601026,
  "exp": 1353604926,
  "nonce": "0394852-3190485-2490358"
}
```

**5. Client authenticates user**

* Query your app's user database. If the user already exists in your database, start an application session for that user
* If the user does not exist in your user database, redirect the user to sign-up flow or auto-register or at the very least pre-populate many of the fields that you require on your registration form
* In addition to the information in the ID token, you can get additional user profile information by accessing `userinfo` endpoint with `access_token` or you could have included scope `openid profile email` in authentication request to get profile


**References**

* [Google OpenID Connect API](https://developers.google.com/identity/protocols/oauth2/openid-connect)


### Authentication using the Implicit Flow

## Choosing the right authorization grant flow

There is no single best answer. For different situations, we should find the right balance between the security and user experience. Recommended setup is as follows

* Web app with server backend -> Authorization code grant flow
* Web app without server backend (e.g. Single page applications) -> Implicit grant flow
* Native mobile app -> Authorization code grant flow with PKCE
* APIs and microservices -> Client credentials grant flow

## Interesting examples to be covered in future

[List of OAuth providers : reddit, twitch, discord and more...](https://en.wikipedia.org/wiki/List_of_OAuth_providers)


## More resources

[Authorization code flow with PKCE](https://auth0.com/docs/flows/guides/auth-code-pkce/call-api-auth-code-pkce#create-a-code-challenge)

[OAuth2.0 various grant flows explained in image](https://github.com/athiththan11/OAuth-2-Grant-Types#implicit-grant-type-flow)

[Image: Refresh token grant flow](https://github.com/athiththan11/OAuth-2-Grant-Types/raw/master/img/Refresh%20Token%20Grant%20Flow.png)

[Image: Resource owner client credentials](https://github.com/athiththan11/OAuth-2-Grant-Types/raw/master/img/Resource%20Owner%20Credentials%20Grant%20Type%20Flow.png)

[OAuth2.0 Device Flow for devices that don't have easy data entry method e.g. gaming console, smart watch](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-03)

[OAuth2.0 Device Token Flow example - Login with amazon](https://developer.amazon.com/docs/login-with-amazon/retrieve-token-other-platforms-cbl-docs.html)