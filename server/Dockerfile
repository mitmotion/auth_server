FROM rust:1.36
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /opt/appbuild
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.8
WORKDIR /opt/app
COPY --from=0 /opt/appbuild/target/release/auth-server .
EXPOSE 19253
CMD ["./auth-server"]
