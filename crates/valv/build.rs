extern crate tonic_build;

fn main() {
    tonic_build::configure()
        .build_server(true)
        .compile(&["vendor/googleapis/google/cloud/kms/v1/service.proto"], &["vendor/googleapis/"]).unwrap();
}
