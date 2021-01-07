# Auth Specification

This document contains the specification for authentication server API
and the authentication flow for game clients connecting to a game server.

## Terminology

- JWT: JSON Web Token as specified in IETF RFC 7519.
- Client: The Veloren client and the agent the player interacts with.
- Game server: A service running the Veloren multiplayer server software.
- Authentication server: A trusted central service that stores account information.

## Algorithms

AES256-GCM is used for symmetric encryption and
Ed25519 is used for asymmetric encryption.

## JWT Types

### Standard Claims

- `iss`: issuer
- `iat`: timestamp of issuance
- `nbf`: not before timestamp
- `exp`: expiry timestamp
- `sub`: subject

### 1: Client <-> Game server authentication

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

### v1 issue_jwt

- Type: POST
- Route: `/api/v1/issue_jwt`
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

### v1 username_to_uuid

- Type: GET
- Route: `/api/v1/username_to_uuid`
- Parameters: `username`
- Response:
  ```
  {
    uuid: string
  }
  ```

### v1 uuid_to_username

- Type: GET
- Route: `/api/v1/uuid_to_username`
- Parameters: `uuid`
- Response:
  ```
  {
    username: string
  }
  ```
