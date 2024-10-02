# A Functional Verification of the KMS in SPIN

Verification in SPIN that verifies the functionality of KEK assignment, encryption, decryption and re-encryption.

There are 4 different models that each verify different operations.

## Models

Model can be set by changing the MODEL constant.

1=A 2=B 3=C 4=D In the paper.

1: Assignemnt and Encryption.
2: Decryption after assignment and encryption has been finalized.
3: Re-Encryption of envelopes after assignment and encryption has been finalized.
4: Tenant 1 assignment and encryption then invalid credentials, Tenant 2 only Decrypts envelopes received from Tenant 1 with different grants.

If MODEL == 1 then IS_MODEL_1 == 1
If MODEL != 1 then IS_MODEL_1 == 0

## To Run and Verify

Most of this can be done with an external tool such as iSPIN, additional information found [here](https://spinroot.com/spin/Man/README.html).

**Run Code**
spin -T model.pml - Regular run that will halt on error and print any statements in the code.
spin -a model.pml - generates pan.c for verification.

**Compile pan.c**
gcc -DMEMLIM=N -O2 -DXUSAFE -DCOLLAPSE -DNFAIR=3 (-DSAFETY) -w -o pan pan.c

-DSAFETY used when verifying safety.

**Verify**
./pan -mN (-a -f) (-N claim)  
In -mN, N is an integer for max depth, however -N is a flag to specify which claim to verify, e.g ./pan -m1000000  -N safety
-a -f used when verifying liveness.

# Additional Documentation

This project implements a key management service (KMS) based on the design and formal verification described in the master's thesis "Formally Verifying a Key Management Service" by Sebastian Owuya. While the implementation is still in progress, it aims to realize key concepts from the thesis.

## Current Implementation Status

### Architecture

The current implementation in the Valv repository does not yet fully reflect the layered architecture described in the thesis. Instead, it implements a single-layer structure with envelope encryption, where a KEK is used to encrypt data or a DEK (see encrypt() in `crates/valv/src/lib.rs`).

### Protocol Operations

The verified protocol operations are partially implemented:

1. **KEK Assignment**: Implemented in `crates/valv/src/lib.rs` in the `create_crypto_key()` function of the `ValvAPI` trait. The `API` struct in `crates/valv/src/api/server.rs` exposes this functionality.

2. **Encryption**: Core encryption logic is in `crates/valv/src/lib.rs` in the `encrypt()` function of the `ValvAPI` trait. The `API` struct in `crates/valv/src/api/server.rs` exposes this functionality.

3. **Decryption**: Implemented in `crates/valv/src/lib.rs` in the `decrypt()` function of the `ValvAPI` trait. The `API` struct in `crates/valv/src/api/server.rs` exposes this functionality.

4. **Re-encryption**: Not explicitly implemented yet, but the foundation exists within the encryption and decryption functions.

### Components

The implementation separates the following components:

- Tenant
- Keystore
- Database

However, the Access Control component is currently missing. The assumptions around the tenant and the inductivity of how a keystore can be seen as a tenant would benefit from a more fleshed out implementation where tests can be constructed to simulate a "layered" structure.

### Message Passing

Message passing between components is implemented through function calls. For example, any call to `self.db` is treated as an asynchronously passed message. However, the storage of `self.master_key` directly within the Keystore may need reconsideration to better align with the thesis design.

## Alignment with Thesis and Future Work

While the current implementation incorporates key concepts from the thesis, there are areas that require further development to fully realize the verified design:

1. **Layered Architecture**: Implement the full layered structure as described in the thesis.
2. **Access Control**: Add the missing Access Control component.
3. **Complete Protocol Operations**: Fully implement all operations, including re-encryption.
4. **Refine Component Separation**: Ensure clear separation of concerns, especially regarding key storage.
5. **Testing**: Develop tests to verify the "layered" structure and component interactions.

It's important to note that while the implemented protocol is based on the verified model from the thesis, the current implementation may not yet fully adhere to all the requirements verified in the thesis. Further work is needed to ensure that the implementation preserves all the properties proven in the formal verification.

As development continues, this documentation should be updated to reflect progress and maintain traceability to the thesis. Any deviations from or extensions to the verified design should be carefully considered and documented.
