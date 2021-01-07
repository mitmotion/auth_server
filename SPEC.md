# Auth Specification

This document contains the specification for authentication server API
and the authentication flow for game clients connecting to a game server.

## Terminology

- JWT: JSON Web Token as specified in IETF RFC 7519.

## JWT Types

### Standard Claims

- `iss`: issuer
- `iat`: timestamp of issuance
- `nbf`: not before timestamp
- `exp`: expiry timestamp
- `sub`: subject

### 1: Client <-> Gameserver authentication

```
{
    iss: string,
    iat: i32,
    nbf: i32,
    exp: i32,
    sub: string,
    usr: string
}
```

`sub` here is the UUID of the account that is logging in.
`usr` is the username of the account logging in.

No issuance payload.

## Server API

The authentication server exposes an API over HTTPS.

### issue_jwt

- Type: PUT
- Route: ```/issue_jwt```
- Payload:
  ```
  {
    jwt_type: i32,
    username: string,
    passkey: string,
    ?payload: any
  }
  ```
- Response:
  ```
  {
    jwt: string
  }
  ```

The JWT issued will have an expiration of 5 minutes from issuance
and a not before claim set to 5 seconds prior to the time of issuance to account for clock skew.

The payload is optional and depends on the JWT type being issued.
