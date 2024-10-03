#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use clap::Parser;
use secrecy::{ExposeSecret, Secret};
use tonic::transport::Server;
use valv::{
    api, valv::proto::v1::master_key_management_service_server::MasterKeyManagementServiceServer,
    Valv,
};

#[derive(Parser)]
struct Cli {
    listen_addr: String,

    #[arg(short, long, value_name = "KEY")]
    master_key: Secret<String>,
}

#[tokio::main]
async fn main() {
    let _guard = unsafe { foundationdb::boot() };

    let args = Cli::parse();

    let mut valv = Valv::new().await.expect("Failed to initialize Valv");

    let master_key = args.master_key.clone().expose_secret().clone().into_bytes()[..32]
        .try_into()
        .expect("Master key must be 32 bytes");

    valv.set_master_key(master_key);

    let api = api::server::API {
        valv: Arc::new(valv),
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
