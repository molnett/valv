# A Functional Verification of the KMS in SPIN
Currently models user and keystore interaction where user can encrypt DEKs and request assignment of KEKs from the Keystore.

Number of DEKs: 2<br />
Number of KEKs: 2

## <u>List of assertions</u>

**User Receive - assert(temp_key == DEKs[temp_key-1])** <br />
A DEK received is one previously encrypted by the user<br />

**User Receive - assert(temp_e_key.version > encrypted_DEKs[temp_e_key.id-1].version)**<br />
If the same DEK is encrypted several times, the encryption is not identical<br />

**Keystore Encrypt - assert(kek_id == 1 || kek_id == 2)**<br />
Keystore only encrypts if a valid KEK has been included in the request<br />

