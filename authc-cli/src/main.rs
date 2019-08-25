use authc::{AuthClient, AuthToken};
use clap::{load_yaml, App};

use std::net::Ipv4Addr;

fn main() {
    let yml = load_yaml!("cli.yml");
    let app = App::from_yaml(yml);
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        ("register", Some(args)) => {
            let username = get_arg(&args, "username", "Please specify the username.");
            let email = get_arg(&args, "email", "Please specify the email.");
            let password = get_arg(&args, "password", "Please specify the password.");
            let auth = set_auth_server(&args);

            if let Err(e) = auth.register(&username, &password, &email) {
                exit_with(format!("Register failed with: {}", e));
            }
            println!("Successfully registered {}", username);
        }
        ("login", Some(args)) => {
            let username = get_arg(&args, "username", "Please specify the username.");
            let password = get_arg(&args, "password", "Please specify the password.");
            let server: Ipv4Addr = match get_arg(
                &args,
                "server",
                "Please specify the server you want to join.",
            )
            .parse()
            {
                Ok(addr) => addr,
                Err(e) => exit_with(format!("failed to parse server address: {}", e)),
            };
            let auth = set_auth_server(&args);

            match auth.sign_in(&username, &password, server) {
                Ok(token) => {
                    println!("Auth Token: {}", token.serialize());
                }
                Err(e) => exit_with(format!("Login failed with: {}", e)),
            }
        }
        ("uuid", Some(args)) => {
            let username = get_arg(&args, "username", "Please specify the username.");
            let auth = set_auth_server(&args);

            match auth.username_to_uuid(&username) {
                Ok(id) => {
                    println!("UUID of {}: {}", username, id);
                }
                Err(e) => exit_with(format!("Retrieving UUID failed with: {}", e)),
            }
        }
        ("validate", Some(args)) => {
            let token: AuthToken =
                match get_arg(&args, "token", "Please specify the token to verify.").parse() {
                    Ok(token) => token,
                    Err(e) => exit_with(format!("failed to parse token: {}", e)),
                };
            let auth = set_auth_server(&args);

            match auth.validate(token) {
                Ok(id) => {
                    println!("Successfully identified login token for user {}", id);
                }
                Err(e) => exit_with(format!("Validating token failed with: {}", e)),
            }
        }
        (_, _) => {
            exit_with("Need some help buddy?");
        }
    }
}

fn set_auth_server(args: &clap::ArgMatches) -> AuthClient {
    if let Some(server) = args.value_of("auth") {
        std::env::set_var("VELOREN_AP", server);
    }

    AuthClient::new()
}

fn get_arg<T: std::fmt::Display>(args: &clap::ArgMatches, arg: T, error_msg: T) -> String
where
    T: std::convert::AsRef<str>,
{
    match args.value_of(arg) {
        Some(x) => x.to_string(),
        None => exit_with(error_msg),
    }
}

fn exit_with<T: std::fmt::Display>(message: T) -> ! {
    println!("{}", message);
    std::process::exit(0);
}