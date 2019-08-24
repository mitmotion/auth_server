# auth

This is the implementation of the central auth server and client for Veloren.

## Design

### Account

An account consists of 3 parts.

- A unique UUID

- A unique username

- A password

### Definitions

- Token -> A single use auth token that is coupled to a server.

### Flow of joining a server.

Client: Fetches the uuid from its playername.

Client: Sends a sign-in request to the auth server with the IPv4 address of the server and receives a token it can use.

Client: Sends token to the gameserver.

Gameserver: Sends a validity check request with the token, receives the uuid of the player.
