# auth

This is a proof of concept implementation of a central auth server and client for Veloren.

Currently very WIP.

## Design

### Account

An account consists of 3 parts.

- A unique UUID

- A username

- A password

### Definitions

- Server ID -> A unique ID for each server that is requested from the auth server at startup.

- Token -> A single use auth token that is also coupled with the hash of a server id.

### Flow of joining a server.

Client: Sends a request to the gameserver for a hash of its server id.

Client: Sends signin request to auth server and receives a token it can use.

Client: Sends token to the gameserver.

Gameserver: Sends a validity check request with the token and its server id, receives the uuid of the player.
