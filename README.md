# auth

This is a proof of concept implementation of a central auth server and client for Veloren.

Currently very WIP.

## Design

### Flow of joining a server.

Client: Sends signin request to server and receives a token it can use.

Client: Sends token along with username to the gameserver.

Gamesever: Validates that the token belongs to that username and allows a game connection.
