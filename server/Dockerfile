FROM rust:1.36
WORKDIR /opt/appbuild
COPY . .
RUN cargo build

FROM debian:10
WORKDIR /opt/app
COPY --from=0 /opt/appbuild/target/debug/auth-server .
EXPOSE 19253
CMD ["./auth-server"]
