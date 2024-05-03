# A Functional Verification of the KMS in SPIN
Currently models tenant and keystore interaction where 2 tenants can encrypt DEKs and request assignment of KEKs from the Keystore. <br/>

When Tenant 1 has encrypted a DEK, it is sent to Tenant 2 together with a *grant* token. Tenant 2 will store encrypted DEKs from Tenant 1 and send them for decryption with the token *grant*. The token is controlled with constants **GRANT** and **VALID_GRANT**. Only when the two are equal, will Tenant 2 be able to decrypt enncrypted DEKs received from Tenant 1. <br/>

By flagging **SAME_KEK_ASSIGNED** as true the max number of KEKs assigned will be set to 1 and both Tenants will be assigned the same KEK from the Keystore. This alternative model introduces a faulty behavior to observe verification failure. <br/>

On set intervals defined as constants, KEKs will be rotated in the database and signals will be sent to the tenants assigned those KEKs. Tenants will then re-encrypt those encrypted DEKs in order to rotate the encryption. <br/>

## To Run and Verify
Most of this can be done with an external tool such as iSpin, additional information found [here](https://spinroot.com/spin/Man/README.html).   <br />

**Run Code**<br />
spin -T dist_coms.pml - Regular run that will halt on error and print any statements in the code. <br />
spin -T -a dist_coms.pml - generates pan.c for verification. <br />

**Compile pan.c**<br />
gcc -w -o pan pan.c - (semi-)optional flags used currently (-DMEMLIM=12000 -O2 -DVECTORSZ=1280 -DXUSAFE )<br />

**Verify**<br />
./pan -m100000000  -a -c1<br />


## Some Default Values
Number of Tenants: 2<br />
Number of DEKs per Tenant: 2<br />
Number of KEKs in Keystore: 4<br />
Max number of KEKs per Tenant: 2

