use authc::{AuthClient, AuthToken};
use clap::{load_yaml, App};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let yml = load_yaml!("cli.yml");
    let app = App::from_yaml(yml);
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        ("register", Some(args)) => {
            let username = get_arg(&args, "username", "Please specify the username.");
            let password = get_arg(&args, "password", "Please specify the password.");
            let auth = set_auth_server(&args).await;

            if let Err(e) = auth.register(&username, &password).await {
                exit_with(format!("Register failed with: {}", e));
            }
            println!("Successfully registered {}", username);
        }
        ("login", Some(args)) => {
            let username = get_arg(&args, "username", "Please specify the username.");
            let password = get_arg(&args, "password", "Please specify the password.");
            let auth = set_auth_server(&args).await;

            match auth.sign_in(&username, &password).await {
                Ok(token) => {
                    println!("Auth Token: {}", token.serialize());
                }
                Err(e) => exit_with(format!("Login failed with: {}", e)),
            }
        }
        ("uuid", Some(args)) => {
            let username = get_arg(&args, "username", "Please specify the username.");
            let auth = set_auth_server(&args).await;

            match auth.username_to_uuid(&username).await {
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
            let auth = set_auth_server(&args).await;

            match auth.validate(token).await {
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

async fn set_auth_server(args: &clap::ArgMatches<'_>) -> AuthClient {
    let authority = args.value_of("auth").unwrap_or("auth.veloren.net");
    let scheme = args.value_of("scheme").unwrap_or("https");

    if let Some(cert_file) = args.value_of("cert") {
        let cert_bytes = tokio::fs::read(cert_file).await.unwrap_or_else(|err| {
            exit_with(format!(
                "Failed to read provided certificate file {cert_file} due to error: {err:?}",
            ));
        });
        let cert = authc::Certificate::from_pem(&cert_bytes).unwrap_or_else(|err| {
            exit_with(format!("Failed to parse certificate due to error: {err:?}"));
        });

        AuthClient::with_certificate(scheme, authority, cert)
    } else {
        AuthClient::new(scheme, authority)
    }
    .unwrap()
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
