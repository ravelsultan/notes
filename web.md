# Tokens
Tokens can be of two type:
1. Tokens by reference
2. Tokens by value

## Tokens by reference
These tokens are **opaque** strings (often random strings) that refer to a database
index where the values associated to the tokens are stored.

## Tokens by value
This type contains the values. To avoid alteration they are digitally signed or
hashed. As they also may contain sensitive data, they can be encrypted.

JSON Web Token is a suite of specifications (mainly RFC7515 to RFC7520) that
introduces a new format for this type.


## Access tokens
Access tokens carry the necessary information to access a resource directly.

## Refresh tokens
Refresh tokens carry the information necessary to get a new access token.

1. When you do log in, send 2 tokens (Access token, Refresh token) in response
   to the client.
2. The access token will have less expiry time and Refresh will have long expiry
   time.
3. The client (Front end) will store refresh token in his local storage and
   access token in cookies.
4. The client will use an access token for calling APIs. But when it expires,
   pick the refresh token from local storage and call auth server API to get the
   new token.
5. Your auth server will have an API exposed which will accept refresh token and
   checks for its validity and return a new access token.
6. Once the refresh token is expired, the User will be logged out.
