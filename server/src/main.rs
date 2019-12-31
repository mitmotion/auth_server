mod auth;
mod cache;
mod web;

fn main() {
    auth::init_db().expect("Failed to initialize database");
    web::start();
}
