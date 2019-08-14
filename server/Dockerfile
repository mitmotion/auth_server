FROM debian:10
apt-get update && apt-get upgrade
apt-get install -y gcc gcc-multilib make musl-tools
curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /opt/appbuild
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.8
WORKDIR /opt/app
COPY --from=0 /opt/appbuild/target/release/auth-server .
EXPOSE 19253
CMD ["./auth-server"]
