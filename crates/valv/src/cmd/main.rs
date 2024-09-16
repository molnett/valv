use std::sync::Arc;

use clap::Parser;
use valv::{
    api,
    valv::valv::v1::master_key_management_service_server::MasterKeyManagementServiceServer,
    Valv,
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

    let mut valv = Valv::new().await;

    let master_key = args.master_key.clone().expose_secret().clone().into_bytes()[..32]
        .try_into()
        .unwrap();

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
