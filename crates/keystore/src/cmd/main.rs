use std::sync::Arc;

use clap::Parser;
use keystore::{
    api,
    valv::keystore::v1::master_key_management_service_server::MasterKeyManagementServiceServer,
    Keystore,
};
use secrecy::{ExposeSecret, Secret};
use tonic::transport::Server;

#[derive(Parser)]
struct Cli {
    listen_addr: String,

    #[arg(short, long, value_name = "KEY")]
    master_key: Secret<String>,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let mut keystore = Keystore::new();

    let master_key = Secret::new(
        args.master_key.clone().expose_secret().clone().into_bytes()[..32]
            .try_into()
            .unwrap(),
    );

    keystore.set_master_key(master_key);

    let api = api::server::API {
        keystore: Arc::new(keystore),
    };

    let svc = MasterKeyManagementServiceServer::new(api);
    println!("Listening on {}", args.listen_addr);

    let addr = args.listen_addr.parse().unwrap();

    Server::builder()
        .add_service(svc)
        .serve(addr)
        .await
        .unwrap();
}
