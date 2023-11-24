# Valv - a Cloud Native Key Management System

Valv is a KMS built for a modern environment. It is heavily inspired by GCP Cloud KMS and their internal Keystore, and is compatible with the Cloud KMS protobuf.

## Design
Valv is designed for strict availability and security requirements. Based on GCP's in detail description of how they have implemented their user-facing KMS and internal Keystore, we can design based on their decades of experience.

Valv is strictly regional and cannot have any cross-regional dependencies. This would lower availability significantly. Instead Valv should be deployed in each region and it's state replicated to other regions.

All keys are rotated with a fixed schedule of 30 days. Clients are expected to follow this schedule and re-seal their DEKs on a similar schedule.

## Keystore
Keystore is a server with the capacity to encrypt millions data-encryption-keys using a much smaller number of key-encryption-keys. KEKs are wrapped using the Root Keystore master key and stored in a HA etcd cluster.
Each active end-user has one KEK stored in two versions to allow key rotation. These KEKs are in turn wrapped by the Root Keystore master key before persisted.
Each Keystores data is mirrored using etcd to all other Keystore pods globally, and actively backed up for disaster recovery.

## Root Keystore
Root Keystore is a standard Keystore. The difference is that its KEKS are encrypted and decrypted by a shared set of master keys that are distributed *globally* through different methods.
These could be:

* Root Master Key Distributor

