extern crate tonic_build;

fn main() {
    #[allow(clippy::unwrap_used)]
    tonic_build::configure()
        .build_server(true)
        .compile(
            &[format!(
                "{}/vendor/googleapis/google/cloud/kms/v1/service.proto",
                env!("CARGO_MANIFEST_DIR")
            )],
            &[
                format!("{}/vendor/googleapis", env!("CARGO_MANIFEST_DIR")),
                format!(
                    "{}/vendor/googleapis/google/protobuf/timestamp.proto",
                    env!("CARGO_MANIFEST_DIR")
                ),
            ],
        )
        .unwrap();
}
