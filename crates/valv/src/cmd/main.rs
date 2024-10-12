#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::{self, Read},
    process::exit,
    sync::Arc,
};

use clap::Parser;

use tonic::transport::Server;
use valv::{
    api, valv::proto::v1::master_key_management_service_server::MasterKeyManagementServiceServer,
    Valv,
};

#[derive(Parser)]
struct Cli {
    listen_addr: String,
}

#[tokio::main]
async fn main() {
    println!("Please input the 32-byte root key (no newline):");

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .expect("Failed to read from stdin");

    let trimmed_key = buffer.trim();

    if trimmed_key.len() != 32 {
        eprintln!(
            "Error: Master key must be exactly 32 bytes. Got {} bytes.",
            trimmed_key.len()
        );
        exit(1);
    }

    let root_key: [u8; 32] = trimmed_key
        .as_bytes()
        .try_into()
        .expect("Failed to convert trimmed key to 32-byte array");

    let _guard = unsafe { foundationdb::boot() };

    let args = Cli::parse();

    let mut valv = Valv::new(root_key)
        .await
        .expect("Failed to initialize Valv");

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
