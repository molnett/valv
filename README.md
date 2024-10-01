# Valv - a Cloud Native Key Management System

Valv is an open-source Key Management System (KMS) built for modern cloud environments. It is heavily inspired by Google Cloud KMS and their internal Keystore, offering compatibility layer for the Cloud KMS protobuf.

**⚠️ IMPORTANT: Valv is currently in technical alpha stage and does not implement all features fully. It is not suitable for production use. APIs and functionality may change at any time without notice. Use at your own risk.**

## Features

- Automatic key rotation (default 30-day schedule, configurable)
- Encryption of data-encryption-keys (DEKs) using key-encryption-keys (KEKs)
- Compatible with Google Cloud KMS protobuf
- Secure storage of KEKs using FoundationDB

## Keystore

Valv's Keystore is designed to encrypt millions of data-encryption-keys (DEKs) using a much smaller number of key-encryption-keys (KEKs). The KEKs are wrapped using the Root Keystore master key and stored in a highly available FoundationDB cluster.

### Key features of the Keystore

- Creation and management of cryptographic keys
- Encryption and decryption operations
- Automatic key rotation (default 30-day schedule, configurable)
- Access control and auditing

### How it works

- Each active end-user has one KEK stored in two versions to allow key rotation
- KEKs are wrapped by the Root Keystore master key before being persisted
- Keystore data is stored and replicated using FoundationDB across all Keystore instances globally
- Active backup for disaster recovery
- By default, keys are automatically rotated every 30 days, but this schedule can be customized

## Protocol Compatibility

Valv's KMS is designed to be compatible with popular cloud KMS protocols, with a focus on modern cloud environments. While the specific protocol for compatibility has not been finalized, Google Cloud KMS is a strong contender due to its alignment with the Google Cloud Envelope Encryption whitepaper, which inspired Valv's design.

A Google KMS compatibility layer can be found in the `examples/google-kms` directory, showcasing potential integration with Google Cloud KMS protobuf. However, please note that the final protocol choice is still under consideration.

For detailed API usage, refer to the documentation in the respective compatibility layer directories.

## Getting Started

### Prerequisites

- Rust (latest stable version)
- FoundationDB (for storage)

### Running the Server

1. Clone the repository:

   ```shell
   git clone https://github.com/molnett/valv.git --recurse-submodules
   cd valv
   ```

2. Build the project:

   ```shell
   cargo build --release
   ```

3. Run the server:

   ```shell
   ./target/release/valv
   ```

By default, the server will listen on `0.0.0.0:50051`. You can customize this by setting the `VALV_ADDR` environment variable: `VALV_ADDR=127.0.0.1:8080 ./target/release/valv`

## Running Tests

Valv includes a comprehensive suite of conformance tests to ensure compatibility with the Google Cloud KMS API. These tests are located in `crates/valv/src/tests.rs`.

To run the test suite:

1. Ensure you have Rust and FoundationDB installed.
2. Run:

   ```shell
   cargo test --all
   ```

   or

   ```shell
   make test
   ```

The conformance tests cover the following areas:

- CryptoKey operations (creation, retrieval, listing, and updating)
- Encryption and decryption
- CryptoKeyVersion operations (creation, retrieval, listing, and destruction)
- Key rotation and state transitions
- Pagination for listing operations
- Error cases and edge conditions

These tests use a `TestClient` struct that wraps the `KeyManagementServiceClient` to interact with the Valv server. The main test function, `run_comprehensive_tests`, orchestrates the execution of various test scenarios.

Key test scenarios include:

- Creating and managing CryptoKeys
- Encrypting and decrypting data
- Verifying key rotation schedules
- Testing pagination for large result sets
- Handling error cases and invalid inputs

For more detailed output during test execution, use:

```shell
cargo test -- --nocapture
```

This will display log messages and assertions as the tests run, providing more insight into the test process and any potential issues.

## Missing Features and Roadmap

While Valv aims to provide a comprehensive KMS solution, some features are still under development:

1. Full implementation of all Google Cloud KMS API methods
2. Advanced access control and IAM integration
3. Multi-region replication with FoundationDB
4. Hardware Security Module (HSM) integration
5. Key import and export functionality
6. Advanced FoundationDB optimizations for high-throughput scenarios

We're actively working on these features and welcome contributions from the community.

## Contributing

We welcome contributions to Valv! Please see our [Contributing Guide](CONTRIBUTING.md) for more details.

## License

Valv is open-source software licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for more details.

## Maintainers

Valv is maintained by [Molnett.com](https://www.molnett.com). For any questions or support, please open an issue on this repository or contact us through our website.
