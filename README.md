# auth

This is the implementation of the auth server and client for Veloren.


## Setting up your own auth server

Install docker
Build docker image using `./build-server-dockerimage.sh` or without cloning the repo `docker build -t auth-server:latest https://gitlab.com/veloren/auth.git`
Run (is docker compose needed?)
If the server is meant to be connected to through a public network run behind a TLS terminator such as nginx (note: essential to keep passwords secured)
