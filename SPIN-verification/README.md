# A Functional Verification of the KMS in SPIN
Verification in SPIN that verifies the functionality of KEK assignment, encryption, decryption and re-encryption.<br/>

There are 4 different models that each verify different operations. <br/>

## Models

Model can be set by changing the MODEL constant.<br/>
    
1=A 2=B 3=C 4=D In the paper.<br/>

2: Assignemnt and Encryption.<br/>
3: Decryption after assignment and encryption has been finalized.<br/>
4: Re-Encryption of envelopes after assignment and encryption has been finalized.<br/> 
5: Tenant 1 assignment and encryption then invalid credentials, Tenant 2 only Decrypts envelopes received from Tenant 1 with different grants.<br/>

If MODEL == 1 then IS_MODEL_1 == 1 <br/>
If MODEL != 1 then IS_MODEL_1 == 0<br/>

## To Run and Verify
Most of this can be done with an external tool such as iSPIN, additional information found [here](https://spinroot.com/spin/Man/README.html).   <br />

**Run Code**<br />
spin -T model.pml - Regular run that will halt on error and print any statements in the code. <br />
spin -a model.pml - generates pan.c for verification. <br />

**Compile pan.c**<br />
gcc -DMEMLIM=N -O2 -DXUSAFE -DCOLLAPSE -DNFAIR=3 (-DSAFETY) -w -o pan pan.c <br />

-DSAFETY used when verifying safety. <br/>

**Verify**<br />
./pan -mN (-a -f) (-N claim)  <br />
In -mN, N is an integer for max depth, however -N is a flag to specify which claim to verify, e.g ./pan -m1000000  -N safety <br/>
-a -f used when verifying liveness. <br/>


