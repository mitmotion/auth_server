# Auth Specification

This document contains the specification for authentication server API
and the authentication flow for game clients connecting to a game server.

### Terminology

- JWT: JSON Web Token as specified in IETF RFC 7519.

## Server API

The authentication server exposes an API over HTTPS.

### issue_jwt

Type codes:
- `1`: Client <-> Gameserver authentication

- Type: PUT
- Route: ```/issue_jwt```
- Payload:\
  ```\
  {\
    type: i32,
    username: string,\
    passkey: string,\
    ?payload: any\
  }\
  ```
- Response:\
  ```\
  {\
    jwt: string\
  }\
  ```
