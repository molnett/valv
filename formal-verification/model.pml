/*
MIT License

Copyright (c) 2024 Sebastian Owuya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/**
    MODELS 
    
    1=A 2=B 3=C 4=D In the paper.
    
    1: Assignemnt and Encryption.
    2: Decryption after assignment and encryption has been finalized
    3: Re-Encryption of envelopes after assignment and encryption has been finalized 
    4: Tenant 1 assignment and encryption then invalid credentials, Tenant 2 only Decrypts envelopes received from Tenant 1 with different grants.

    If MODEL == 1 then IS_MODEL_1 == 1 
    If MODEL != 1 then IS_MODEL_1 == 0

    Model 3 uses dek_id field in messages as an additional kek_ref field.
*/ 
#define MODEL 1
#define IS_MODEL_1 1

#define NUM_DEKS 1
#define NUM_KEKS 2
#define NUM_TENANTS 2
#define VALID_GRANT 1
#define ENC_DUMMY 5
#define EMPTY_PASS 0

// CHANNEL CAPS
#define T2K_MAX 1

// MODEL 2
#if IS_MODEL_1
    #define K2AC_MAX 2
    #define AC2K_MAX 2
    #define K2DB_MAX 2
    #define DB2K_MAX 2
    #define K2T_MAX 2
#else
    #define K2AC_MAX 1
    #define AC2K_MAX 1
    #define K2DB_MAX 1
    #define DB2K_MAX 1
    #define K2T_MAX 1
#endif

// REQUEST LIMIT OF CONCURRENT PROCESSING IN KEYSTORE
#define REQ_MAX 2


typedef KEK { 
    unsigned id : 3
    bit version
}


typedef E_DEK { /* Encrypted */
    unsigned id : 3
    unsigned ref_id : 4
    bit enc_version
    bit ref_version
}

mtype = { e_DEK, d_DEK, re_DEK, a_KEK, a_KEK2, deny }

// t1: Tenant 1
// t2: Tenant 2
// k: Keystore
// ac: Access Control
// db: Database

// { message type, DEK_ID, KEK_ID, E_KEY-ID, (E_KEY-ENC_V), E_KEY-REF_V, TENANT_ID, (GRANT), (KEK-VERSION), AUTH } 
chan t12k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte }	                    // Tenant 1 -> Keystore, |t12k| = 6
chan k2t1 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	            // Keystore -> Tenant 1, |k2t1| = 7

chan t22k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	            // Tenant 2 -> Keystore, |t22k| = 7
chan k2t2 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	        // Keystore -> Tenant 2, |k2t2| = 8

chan k2ac = [K2AC_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	        // Keystore -> Access Control, |k2ac| = 8
chan ac2k = [AC2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	        // Access Control -> Keystore, |ac2k| = 8

chan k2db = [K2DB_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	        // Keystore -> Database, |k2db| = 8
chan db2k = [DB2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte, byte }	// Database -> Keystore, |db2k| = 9

// Channel buffers
unsigned t12k_buff: 3, t22k_buff: 3
unsigned k2t1_buff: 3, k2t2_buff: 3
unsigned k2db_buff: 3, db2k_buff: 3
unsigned k2ac_buff: 3, ac2k_buff: 3
unsigned req_buff: 3

bool exit_atomic
local bool cache_cleared


// LTL variables
#define p_authentic (((Keystore[4]@Send_to_Access_Control || Keystore[4]@Send_to_Database || Keystore[4]@Encrypt_return || Keystore[4]@Decrypt_return || Keystore[4]@Assign_KEK_return) && !auth_ks) || \
                    (Database[3]@Access_KEK && !auth_db) || (AccessControl[5]@Select_state && !auth_ac))

bool p_assigned_1, p_assigned_2, p_enc_1
bool p_conf = true, p_int = true, p_sync = true, p_protocol = true, p_cache = true
local bool p_rotated_1 , p_rotated_2, p_enc_2, auth_ks, auth_db, auth_ac, auth_t1, auth_t2, grant_t2
local unsigned m3_KEK_t1 : 4, m3_KEK_t2 : 4 

// LTL claims
ltl safety { [](p_conf && p_int && p_protocol && p_sync && p_cache && !p_authentic && (Tenant_1[1]@Decrypt_receive -> p_enc_1) && 
                (Tenant_2[2]@Decrypt_receive -> (p_enc_2 || (grant_t2 && p_enc_1))) && (p_enc_1 -> p_assigned_1) && (p_enc_2 -> p_assigned_2 )) &&
                (Tenant_1[1]@Recrypt_Receive -> p_enc_1) && (Tenant_2[2]@Recrypt_Receive -> p_enc_2) 
            }


ltl liveness_model_1 { ([]<>(p_rotated_1) && []<>(!p_rotated_1)) && ([]<>(p_rotated_2) && []<>(!p_rotated_2)) }
ltl liveness_model_2 { ([]<>(Tenant_2[2]@Decrypt_receive) && []<>(Tenant_1[1]@Decrypt_receive)) && ((Database[3]@Access_KEK) -> <>(Database[3]@Cleanup)) && ((Database[3]@Cleanup) -> <>(db2k == 0)) }
ltl liveness_model_3 { ([]<>(m3_KEK_t1 == 6) && []<>(m3_KEK_t1 == 8)) && ([]<>(m3_KEK_t2 == 7) && []<>(m3_KEK_t2 == 9))  }
ltl liveness_model_4 {<>[]!(Tenant_1[1]@Encrypt_receive || Tenant_1[1]@Assign_KEK_receive) && []<>(Tenant_1[1]@Receive) && []<>(Tenant_2[2]@Decrypt_receive) && ((Database[3]@Access_KEK) -> <>(Database[3]@Cleanup)) && ((Database[3]@Cleanup) -> <>(db2k == 0))}



init {

    atomic {

        run Tenant_1()
        run Tenant_2()
        run Database()
        run Keystore()
        run AccessControl()

    }
}
/**
    Order of operations
    (DB step is optional for Decrypt when the KEK is not in v-memory)
    Assign KEK: T -> KS -> AC -> KS -> DB -> KS -> AC -> KS -> T
    Decrypt:    T -> KS -> AC -> KS -> (DB) -> KS -> T
    Encrypt:    T -> KS -> AC -> KS -> DB -> KS -> T
    Recrypt:    T -> KS -> AC -> KS -> DB -> KS -> T
 */

proctype Tenant_1()
{
    mtype msg = deny
    unsigned temp_dek: 3, assigned_KEK : 3, step : 4
    unsigned id : 2 = 1
    unsigned dek_id : 2 = 1
    bit denied
    
    E_DEK temp_e_dek, encrypted_DEK

    Select_state:

        exit_atomic = true

        atomic {
            
            do
            ::  k2t1_buff > 0 -> k2t1?msg, temp_dek, temp_e_dek.ref_id, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, auth_t1, step -> k2t1_buff-- -> 
                
                // AUTHENTICATION OR CONFIDENTIALITY VIOLATION
                if
                ::  !auth_t1 -> denied = true -> goto Cleanup 
                ::  ((temp_e_dek.id > 0 && temp_e_dek.id < ENC_DUMMY) || (temp_e_dek.ref_id > 0 && temp_e_dek.ref_id < ENC_DUMMY)) -> p_conf = false -> goto Cleanup
                ::  else -> skip
                fi

                goto Receive
            
            ::  t12k_buff < T2K_MAX && k2t1_buff == 0 -> 
                
                do
                ::  MODEL == 1 -> 
                    do
                    ::  !(denied && p_assigned_1) -> 
                            t12k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  !(denied && !p_assigned_1) ->
                            t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  !denied -> 
                            t12k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, 1 -> break
                    od
                    break
                ::  MODEL == 2 -> 

                    if
                    ::  p_enc_1 -> encrypted_DEK.ref_version = !encrypted_DEK.ref_version
                    ::  else -> skip
                    fi

                    do
                    ::  !p_assigned_1 -> 
                            t12k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  p_assigned_1 && !p_enc_1 ->
                            t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  !(denied && !p_enc_1) -> 
                            t12k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.ref_version, id, 1 -> break
                    od
                    break
                ::  MODEL == 3 -> 
                    do
                    ::  !p_assigned_1 -> 
                            t12k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  p_assigned_1 && !p_enc_1 ->
                            t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  !(denied && !p_enc_1) -> 
                            t12k!re_DEK, encrypted_DEK.ref_id, m3_KEK_t1, encrypted_DEK.id, encrypted_DEK.ref_version, id, 1 -> break
                    od
                    break
                ::  MODEL == 4 -> 
                    do
                    ::  !p_assigned_1 -> 
                            t12k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  p_assigned_1 && !p_enc_1 ->
                            t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  p_enc_1 ->
                            t12k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, 1 -> break
                    od
                    break
                od

                t12k_buff++
            
            od

        }

    Receive:

        atomic {

            req_buff--
            
            if
            ::  msg == deny -> 

                denied = true

                if
                ::  (step % 2) != 0 -> p_protocol = false
                ::  else -> skip
                fi
           
            ::  else ->

                denied = false
            
                if
                ::  msg == a_KEK -> goto Assign_KEK_receive
                ::  msg == d_DEK -> goto Decrypt_receive
                ::  msg == e_DEK -> goto Encrypt_receive
                ::  msg == re_DEK -> goto Recrypt_Receive
                fi    
            fi

            goto Cleanup
        }

    Assign_KEK_receive:

        atomic {
           
            // PROTOCOL, SYNCHRONIZATION OR INTEGRITY VIOLATION
            if
            ::  step != 8 -> p_protocol = false
            ::  assigned_KEK == temp_e_dek.ref_id -> p_int = false 
            ::  p_assigned_1 -> p_sync = false
            ::  else -> skip
            fi

            p_assigned_1 = true
            assigned_KEK = temp_e_dek.ref_id
            

            goto Cleanup
        }
    
    Decrypt_receive:

        atomic {
            // PROTOCOL OR INTEGRITY VIOLATION
            if
            ::  step != 4 && step != 6 -> p_protocol = false
            ::  dek_id != temp_dek -> p_int = false
            ::  else -> skip
            fi

            goto Cleanup
        }
    
    Encrypt_receive:

        atomic {
            // PROTOCOL, SYNCHRONIZATION OR INTEGRITY VIOLATION
            if
            ::  step != 6 -> p_protocol = false
            ::  temp_e_dek.enc_version == encrypted_DEK.enc_version -> p_sync = false
            ::  temp_e_dek.id-ENC_DUMMY != dek_id -> p_int = false
            ::  temp_e_dek.ref_id != assigned_KEK -> p_int = false
            ::  else -> skip
            fi

            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

            if
            ::  MODEL == 3 -> m3_KEK_t1 = encrypted_DEK.ref_id
            ::  else -> skip
            fi

            p_enc_1 = true

            goto Cleanup
        }
    
    Recrypt_Receive:

        atomic {

            if
            ::  step != 6 -> p_protocol = false
            ::  temp_e_dek.enc_version == encrypted_DEK.enc_version -> p_sync = false
            ::  temp_e_dek.id-ENC_DUMMY != dek_id -> p_int = false
            ::  temp_e_dek.ref_id != assigned_KEK && temp_e_dek.ref_id != 8 -> p_int = false
            ::  else -> skip
            fi
            
            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

            if
            ::  MODEL == 3 -> 
                if
                ::  encrypted_DEK.ref_id == 6 -> m3_KEK_t1 = 8
                ::  else -> m3_KEK_t1 = 6
                fi
            ::  else -> skip
            fi
            
            goto Cleanup
        }

    Cleanup:

        atomic {

            auth_t1 = 0
            step = 0
            msg = deny
            temp_dek = 0
            temp_e_dek.ref_id = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_version = 0

            goto Select_state
        }
}

proctype Tenant_2()
{
    mtype msg = deny
    unsigned temp_dek: 3, assigned_KEK : 3, step : 4
    unsigned id : 2 = 2
    unsigned dek_id : 2 = 2
    bit denied

    E_DEK temp_e_dek, encrypted_DEK, received_e_DEK

    Select_state:

        exit_atomic = true

        atomic {

            do
            ::  k2t2_buff > 0 -> k2t2?msg, temp_dek, temp_e_dek.ref_id, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant_t2, auth_t2, step -> k2t2_buff-- -> 

                // AUTHENTICATION OR CONFIDENTIALITY VIOLATION
                if
                ::  !auth_t2 -> denied = true -> goto Cleanup
                ::  temp_e_dek.id > 0 && temp_e_dek.id < ENC_DUMMY -> p_conf = false -> goto Cleanup
                ::  temp_e_dek.ref_id > 0 && temp_e_dek.ref_id < ENC_DUMMY -> p_conf = false -> goto Cleanup
                ::  else -> skip
                fi

                goto Receive

            ::  t22k_buff < T2K_MAX && k2t2_buff == 0 -> 

                do
                ::  MODEL == 1 -> 
                    do
                    ::  !(denied && p_assigned_2) -> 
                            t22k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant_t2, 1 -> break
                    ::  !(denied && !p_assigned_2) ->
                            t22k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, grant_t2, 1 -> break
                    ::  !denied -> 
                            t22k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, grant_t2, 1 -> break
                    od
                    break
                ::  MODEL == 2 -> 

                    if
                    ::  p_enc_2 -> encrypted_DEK.ref_version = !encrypted_DEK.ref_version
                    ::  else -> skip
                    fi

                    do
                    ::  !p_assigned_2 -> 
                            t22k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant_t2, 1 -> break
                    ::  p_assigned_2 && !p_enc_2  ->
                            t22k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, grant_t2, 1 -> break
                    ::  !(denied & !p_enc_2) ->
                             t22k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.ref_version, id, grant_t2, 1 -> break
                    od
                    break

                ::  MODEL == 3 -> 
                    do
                    ::  !p_assigned_2 -> 
                            t22k!a_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant_t2, 1 -> break
                    ::  p_assigned_2 && !p_enc_2  ->
                            t22k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, grant_t2, 1 -> break
                    ::  !(denied && !p_enc_2)
                            t22k!re_DEK, encrypted_DEK.ref_id, m3_KEK_t2, encrypted_DEK.id, encrypted_DEK.ref_version, id, grant_t2, 1 -> break
                    od
                    break
                ::  MODEL == 4 -> 
                    
                    received_e_DEK.ref_version = !received_e_DEK.ref_version
                    
                    if
                    ::  p_enc_1 && received_e_DEK.id == 0 -> 
                            received_e_DEK.id = 6
                            received_e_DEK.ref_id = 6   
                    ::  else -> skip
                    fi

                    do
                    ::  !denied ->
                            t22k!d_DEK, EMPTY_PASS, received_e_DEK.ref_id, received_e_DEK.id, received_e_DEK.ref_version, id, grant_t2, 1 -> break
                    ::  t22k!d_DEK, EMPTY_PASS, received_e_DEK.ref_id, received_e_DEK.id, received_e_DEK.ref_version, id, VALID_GRANT, 1 -> break
                    od
                    break
                od

                t22k_buff++
            
            od
            
        }

    Receive: 

        atomic {   

            req_buff--
            
            if
            ::  msg == deny -> 

                denied = true

                // PROTOCOL VIOLATION
                if
                ::  (step % 2) != 0 -> p_protocol = false
                ::  else -> skip
                fi
            
            ::  else ->
               
                denied = false
               
                if
                ::  msg == a_KEK -> goto Assign_KEK_receive
                ::  msg == d_DEK -> goto Decrypt_receive
                ::  msg == e_DEK -> goto Encrypt_receive
                ::  msg == re_DEK -> goto Recrypt_Receive
                fi    
            fi

            goto Cleanup
        }
    
    Assign_KEK_receive:

        atomic {

            // PROTOCOL, SYNCHRONIZATION OR INTEGRITY VIOLATION
            if
            ::  step != 8 -> p_protocol = false
            ::  temp_e_dek.ref_id != 7 -> p_int = false 
            ::  p_assigned_2 -> p_sync = false // liveness
            ::  else -> skip
            fi

            p_assigned_2 = true
            assigned_KEK = temp_e_dek.ref_id

            goto Cleanup
        }
    
    Decrypt_receive:

        atomic {
            
            // PROTOCOL OR INTEGRITY VIOLATION
            if
            ::  step != 4 && step != 6 -> p_protocol = false
            ::  !(dek_id == temp_dek || (grant_t2 && temp_dek == 1)) -> p_int = false
            ::  else -> skip
            fi

            goto Cleanup
        }
    
    Encrypt_receive:

        atomic {
            
            // PROTOCOL, SYNCHRONIZATION OR INTEGRITY VIOLATION
            if
            ::  step != 6 -> p_protocol = false
            ::  temp_e_dek.enc_version == encrypted_DEK.enc_version -> p_sync = false
            ::  temp_e_dek.id-ENC_DUMMY != dek_id -> p_int = false
            ::  temp_e_dek.ref_id != assigned_KEK -> p_int = false
            ::  else -> skip
            fi

            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version
            
            if
            ::  MODEL == 3 -> m3_KEK_t2 = encrypted_DEK.ref_id
            ::  else -> skip
            fi

            p_enc_2 = true

            goto Cleanup
        }
    
    Recrypt_Receive:

        atomic {
            
            // PROTOCOL, SYNCHRONIZATION OR INTEGRITY VIOLATION
            if
            ::  step != 6 -> p_protocol = false
            ::  temp_e_dek.enc_version == encrypted_DEK.enc_version -> p_sync = false
            ::  temp_e_dek.id-ENC_DUMMY != dek_id -> p_int = false
            ::  temp_e_dek.ref_id != assigned_KEK && temp_e_dek.ref_id != 9 -> p_int = false
            ::  else -> skip
            fi

            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

            if
            ::  MODEL == 3 -> 
                if
                ::  encrypted_DEK.ref_id == 7 -> m3_KEK_t2 = 9
                ::  else -> m3_KEK_t2 = 7
                fi
            ::  else -> skip
            fi

            goto Cleanup
        }

    Cleanup:

        atomic {
            auth_t2 = 0
            grant_t2 = 0
            msg = deny
            temp_dek = 0
            temp_e_dek.ref_id = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_version = 0
            step = 0

            goto Select_state
        }
}

proctype Keystore()
{
    mtype msg = deny
    unsigned dek_id : 4, kek_id : 3, kek_ref : 4, tenant_id : 3, grant : 2, kek_version : 1, step : 3, array_size : 3 = 4
    bit id = 1
    bit last_enc_1, last_enc_2, turn 
    bool db_skip_1, db_skip_2
    
    if
    ::  MODEL != 3 -> 
            array_size = NUM_KEKS
    ::  else -> skip
    fi
    
    E_DEK temp_e_dek
    KEK temp_key
    KEK v_KEKs[array_size]

    Select_state:


        do
        ::  MODEL == 2 || MODEL == 4 -> cache_cleared = !cache_cleared -> break
        ::  else -> cache_cleared = cache_cleared -> break
        od

        atomic {

            do  //FROM AC
            ::  ac2k_buff > 0 && db2k_buff == 0 -> ac2k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth_ks, step -> ac2k_buff-- ->  

                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  !auth_ks -> goto Cleanup
                ::  else -> skip
                fi
                if
                ::  msg == a_KEK2 && step != 7 -> p_protocol = false
                ::  msg != a_KEK2 && msg != deny && step != 3 -> p_protocol = false
                ::  msg == deny && step != 7 && step != 3 -> p_protocol = false
                ::  else -> skip
                fi
                
                if  // Dereference KEK encryption with MK
                ::  kek_ref > 5 -> kek_id = kek_ref-ENC_DUMMY
                ::  else -> kek_id = 0
                fi

                do
                ::  msg == a_KEK2 -> goto Assign_KEK_return
                ::  msg == d_DEK -> goto Decrypt_Database_Check  
                ::  msg == deny -> goto Deny_request
                ::  msg == a_KEK -> kek_id = tenant_id -> goto Send_to_Database
                ::  else -> goto Send_to_Database
                od

                
               
                //FROM DB
            ::  db2k_buff > 0 -> db2k?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, kek_version, auth_ks, step -> db2k_buff-- ->  

                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  !auth_ks -> goto Cleanup
                ::  step != 5 -> p_protocol = false
                ::  else -> skip
                fi

                // Update KEKs
                if
                ::  msg == deny -> goto Deny_request
                ::  else -> 
                        v_KEKs[kek_id-1].id = kek_id
                        v_KEKs[kek_id-1].version = kek_version
                fi
                
                // ROTATION CHECK
                if
                ::  tenant_id == 1 ->
                    if
                    ::  v_KEKs[kek_id-1].version == 0 -> 
                            p_rotated_1 = true
                    ::  else -> p_rotated_1 = false
                    fi
                ::  tenant_id == 2 ->
                    if
                    ::  v_KEKs[kek_id-1].version == 0 -> 
                            p_rotated_2 = true
                    ::  else -> p_rotated_2 = false
                    fi
                fi

                do
                ::  msg == a_KEK -> 
                        msg = a_KEK2 
                        kek_ref = kek_id+ENC_DUMMY 
                        goto Send_to_Access_Control 
                ::  msg == d_DEK -> goto Decrypt_return  
                ::  msg == e_DEK || msg == re_DEK -> goto Encrypt_return
                od

             
                // FROM TENANT 
            ::  (turn == 1 || (turn == 0 && t22k_buff == 0)) && req_buff < REQ_MAX && t12k_buff > 0  && ac2k_buff == 0 && db2k_buff == 0 -> 
                    t12k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, step -> req_buff++ -> t12k_buff-- ->                  

                turn = 0
                auth_ks = tenant_id

                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  !auth_ks -> tenant_id = 1 -> goto Deny_request
                ::  step != 1 -> p_protocol = false
                ::  else -> skip
                fi
                
                goto Send_to_Access_Control

            ::  (turn == 0 || (turn == 1 && t12k_buff == 0)) && req_buff < REQ_MAX && t22k_buff > 0 && ac2k_buff == 0 && db2k_buff == 0 -> 
                    t22k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, step -> req_buff++ -> t22k_buff-- ->  
                
                turn = 1
                auth_ks = tenant_id/2
                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  !auth_ks -> tenant_id = 2 -> goto Deny_request
                ::  step != 1 -> p_protocol = false
                ::  else -> skip
                fi
                
                goto Send_to_Access_Control
                    
            od
        }

    
    Send_to_Access_Control:

        atomic {
            
            if
            ::  MODEL == 1 -> 
                    k2ac_buff < K2AC_MAX  
                    k2ac!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, step+1  
                    k2ac_buff++
            ::  else -> skip
            fi
            k2ac_buff < K2AC_MAX  
            k2ac!msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1  
            k2ac_buff++

            goto Cleanup   
        }

    Send_to_Database:
                    
        atomic {
            if
            ::  msg == re_DEK -> dek_id = dek_id-ENC_DUMMY
            ::  else -> skip
            fi
            if
            ::  MODEL == 1 -> 
                    k2db_buff < K2DB_MAX 
                    k2db!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, step+1
                    k2db_buff++
            ::  else -> skip
            fi
            k2db_buff < K2DB_MAX 
            k2db!msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
            k2db_buff++

            goto Cleanup
        }
            

    Decrypt_Database_Check:

        atomic {
            
            if // Already in memory so skip Database
            ::  !(cache_cleared || (v_KEKs[kek_id-1].version == 1 && temp_e_dek.ref_version == 0)) ->
                
                if
                ::  tenant_id == 1 -> db_skip_1 = true -> skip
                ::  tenant_id == 2 -> db_skip_2 = true -> skip
                fi
            ::  else ->
                if
                ::  tenant_id == 1 -> db_skip_1 = false -> skip
                ::  tenant_id == 2 -> db_skip_2 = false -> skip
                fi
            fi

            // CACHE VIOLATION
            if
            ::  !(v_KEKs[kek_id-1].version == 1 && temp_e_dek.ref_version == 0) -> 
                if
                ::  tenant_id == 1 -> p_cache = (db_skip_1 || cache_cleared) && !(db_skip_1 && cache_cleared)
                ::  tenant_id == 2 -> p_cache = (db_skip_2 || cache_cleared) && !(db_skip_2 && cache_cleared) 
                fi
            ::  else -> skip         
            fi

           
            if
            ::  tenant_id == 1 && !db_skip_1 -> goto Send_to_Database
            ::  tenant_id == 2 && !db_skip_2 -> goto Send_to_Database
            ::  else -> skip
            fi

            goto Decrypt_return
        }
    
    Decrypt_return:

        atomic {

            if
            ::  tenant_id == 1 -> 
                    k2t1_buff < K2T_MAX 
                    k2t1!d_DEK, temp_e_dek.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, step+1
                    k2t1_buff++
            ::  else -> 
                    k2t2_buff < K2T_MAX
                    k2t2!d_DEK, temp_e_dek.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id, step+1
                    k2t2_buff++
            fi

            goto Cleanup
        }
            
    Assign_KEK_return:

        atomic {

            if // ack from Tenant was received during concurrent processing
            ::  tenant_id == 1 && p_assigned_1 -> goto Deny_request
            ::  tenant_id == 2 && p_assigned_2 -> goto Deny_request
            ::  else -> skip
            fi
            
            if
            ::  tenant_id == 1 -> 
                if
                ::  MODEL == 1 -> 
                    k2t1_buff < K2T_MAX 
                    k2t1!a_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, step+1
                    k2t1_buff++
                ::  else -> skip
                fi
                k2t1_buff < K2T_MAX 
                k2t1!a_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, step+1
                k2t1_buff++
            ::  else -> 
                if
                ::  MODEL == 1 -> 
                    k2t2_buff < K2T_MAX
                    k2t2!a_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, 0, step+1
                    k2t2_buff++
                ::  else -> skip
                fi
                k2t2_buff < K2T_MAX
                k2t2!a_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id, step+1
                k2t2_buff++
            fi

            goto Cleanup
        }

    // Also used for Recrypt
    Encrypt_return:

        // From Database to Tenant
        atomic {
                
            if
            ::  msg == e_DEK -> temp_e_dek.id = dek_id+ENC_DUMMY
            ::  msg == re_DEK && dek_id != kek_id -> 
                    db2k_buff > 0  
                    db2k?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, kek_version, auth_ks, step 
                    db2k_buff--
                    // Update KEKs
                    if
                    ::  msg == deny -> goto Deny_request
                    ::  else -> 
                            v_KEKs[kek_id-1].id = kek_id
                            v_KEKs[kek_id-1].version = kek_version
                    fi
                    
                    // ROTATION CHECK
                    if
                    ::  tenant_id == 1 ->
                        if
                        ::  v_KEKs[kek_id-1].version == 0 -> 
                                p_rotated_1 = true
                        ::  else -> p_rotated_1 = false
                        fi
                    ::  tenant_id == 2 ->
                        if
                        ::  v_KEKs[kek_id-1].version == 0 -> 
                                p_rotated_2 = true
                        ::  else -> p_rotated_2 = false
                        fi
                    fi
            ::  else -> skip
            fi

            temp_e_dek.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
            temp_e_dek.ref_version = v_KEKs[kek_id-1].version
            
            do
            ::  tenant_id == 1 ->

                last_enc_1 = !last_enc_1
                temp_e_dek.enc_version = last_enc_1 
            
                k2t1_buff < K2T_MAX 
                k2t1!msg, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, id, step+1
                k2t1_buff++ 
                break

            ::  tenant_id == 2 ->
                
                last_enc_2 = !last_enc_2
                temp_e_dek.enc_version = last_enc_2
                
                k2t2_buff < K2T_MAX 
                k2t2!msg, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, id, step+1
                k2t2_buff++
                break
            od
            
            goto Cleanup
        }

    Deny_request:

        atomic {
            
            if
            ::  tenant_id == 1 -> 
                if
                ::  p_assigned_1 && MODEL == 1 ->
                    // SYNCHRONIZATION VIOLATION
                    if
                    ::  (msg != a_KEK || msg != a_KEK2) && kek_ref == 6 -> p_sync = false
                    ::  else -> skip
                    fi
                ::  else -> skip
                fi
                k2t1_buff < K2T_MAX 
                k2t1!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, step+1
                k2t1_buff++
            ::  else -> 
                if
                ::  p_assigned_2 && MODEL == 1 ->
                    // SYNCHRONIZATION VIOLATION
                    if
                    ::  (msg != a_KEK || msg != a_KEK2) && kek_ref == 7 -> p_sync = false
                    ::  else -> skip
                    fi
                ::  else -> skip
                fi
                k2t2_buff < K2T_MAX 
                k2t2!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id, step+1
                k2t2_buff++
            fi

            goto Cleanup
        } 

    Cleanup:

        atomic {
            auth_ks = 0
            grant = 0
            msg = deny
            dek_id = 0
            kek_id = 0
            kek_ref = 0
            kek_version = 0
            tenant_id = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_id = 0
            temp_e_dek.ref_version = 0
            temp_key.version = 0
            temp_key.id = 0
            step = 0
        }       
        goto Select_state
}


proctype Database() {

    mtype msg = deny
    unsigned kek_id : 3, i : 3, tenant_id : 3, dek_id : 3, grant : 2, step : 3, array_size : 3 = 4
    bit id = 1

    if
    ::  MODEL != 3 -> 
            array_size = NUM_KEKS
    ::  else -> skip
    fi

    KEK p_KEKs[array_size]
    E_DEK temp_e_dek

    for (i : 0 .. array_size-1) {
        p_KEKs[i].id = i+1
    }

    Select_state:
        
        k2db_buff > 0 

        atomic {

            k2db?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth_db, step
            k2db_buff--

            // PROTOCOL, AUTHENTICATION OR INTEGRITY VIOLATION
            if
            ::  !auth_db -> goto Cleanup
            ::  else -> skip
            fi
            
            if
            ::  step != 4 -> p_protocol = false
            ::  else -> skip
            fi
            
            do
            ::  (msg == e_DEK || msg == d_DEK || msg == a_KEK || msg == re_DEK) -> goto Access_KEK
            ::  else -> goto Deny_request
            od
            
        }

    Access_KEK:

        atomic {

            i = 0
            for (i : 0 .. array_size-1) {
                if 
                ::  p_KEKs[i].id == kek_id -> 
                        if
                        ::  msg == re_DEK -> goto Send_Recrypt
                        ::  else -> goto Send
                        fi
                ::  else -> skip
                fi
            }
            
            goto Deny_request
        
        }        

    Send:

        atomic {

            p_KEKs[i].version = !p_KEKs[i].version
            
            if
            ::  MODEL == 1 -> 
                    db2k_buff < DB2K_MAX 
                    db2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, step+1
                    db2k_buff++
            ::  else -> skip
            fi
            db2k_buff < DB2K_MAX 
            db2k!msg, dek_id, p_KEKs[i].id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, p_KEKs[i].version, id, step+1
            db2k_buff++

            goto Cleanup
        }

    Send_Recrypt:

        atomic {

            if
            ::  dek_id != kek_id && i > 1 -> i = i-2
            ::  dek_id != kek_id && i < 2 -> i = i+2
            ::  else -> goto Send
            fi

            p_KEKs[i].version = !p_KEKs[i].version
            
            db2k_buff < DB2K_MAX 
            db2k!msg, kek_id, p_KEKs[i].id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, p_KEKs[i].version, id, step+1
            db2k_buff++

            if
            ::  i > 1 -> i = i-2
            ::  i < 2 -> i = i+2
            fi

            goto Send
        }

    Deny_request:
        
        atomic {
            
            db2k_buff < DB2K_MAX 
            db2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, EMPTY_PASS, EMPTY_PASS, id, step+1
            db2k_buff++

            // SYNCHRONIZATION VIOLATION IN ACCESS CONTROL
            p_sync = false

            goto Cleanup
        }

    Cleanup:

        atomic {

            auth_db = 0
            i = 0
            msg = deny
            dek_id = 0
            kek_id = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_version = 0
            tenant_id = 0
            grant = 0
            step = 0

            goto Select_state
        }
}

proctype AccessControl()
{
    mtype msg = deny
    unsigned kek_ref : 4, tenant_id : 3, dek_id : 4, grant : 1, assigned_1 : 3, assigned_2 : 3, step : 3
    bit id = 1
    E_DEK temp_e_dek
    
    Receive:
        
        k2ac_buff > 0 

        atomic {

            k2ac?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth_ac, step
            k2ac_buff--

            if
            ::  !auth_ac -> goto Cleanup
            ::  else -> skip
            fi

            // PROTOCOL, AUTHENTICATION OR CONFIDENTIALITY VIOLATION
            if
            ::  temp_e_dek.ref_id > 0 && temp_e_dek.ref_id < ENC_DUMMY -> p_conf = false
            ::  temp_e_dek.id > 0 && temp_e_dek.id < ENC_DUMMY -> p_conf = false 
            ::  kek_ref > 0 && kek_ref < ENC_DUMMY -> p_conf = false
            ::  !auth_ac -> goto Cleanup
            ::  msg != a_KEK2 && step != 2 -> p_protocol = false
            ::  msg == a_KEK2 && step != 6 -> p_protocol = false
            ::  else -> skip
            fi

            goto Select_state
        }

    Select_state:

        atomic {
            if
            ::  msg == a_KEK -> goto Assign_KEK_authorize
            ::  msg == a_KEK2 -> goto Assign_KEK2_authorize
            ::  (msg == d_DEK || msg == e_DEK || msg == re_DEK) -> goto Authorize
            ::  else -> goto Deny_request
            fi
        }
    
    Assign_KEK_authorize:

        // Request access to generate a KEK
        atomic {

            if
            ::  kek_ref == 0 -> 
                if
                ::  tenant_id == 1 && assigned_1 > 0 -> goto Deny_request
                ::  tenant_id == 2 && assigned_2 > 0 -> goto Deny_request
                ::  else -> skip
                fi
            ::  else -> goto Deny_request
            fi

            ac2k_buff < AC2K_MAX
            ac2k!a_KEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
            ac2k_buff++

            goto Cleanup
        }        

    Assign_KEK2_authorize:

        // Newly generated key assigned
        atomic {

            if 
            ::  tenant_id == 1 && assigned_1 == 0 -> assigned_1 = kek_ref 
            ::  tenant_id == 2 && assigned_2 == 0 -> assigned_2 = kek_ref 
            ::  else -> goto Deny_request
            fi
            
            ac2k_buff < AC2K_MAX
            ac2k!a_KEK2, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
            ac2k_buff++

            goto Cleanup
        }    


    Authorize:

        atomic {
            
            if
            ::  kek_ref == 0 -> goto Deny_request
            ::  else -> skip
            fi

            if
            ::  msg == re_DEK ->
                if
                ::  tenant_id == 1 && (kek_ref != assigned_1 && dek_id != assigned_1 + 2 && dek_id != assigned_1 && kek_ref != assigned_1 + 2) -> 
                        goto Deny_request
                ::  tenant_id == 2 && (kek_ref != assigned_2 && dek_id != assigned_2 + 2 && dek_id != assigned_2 && kek_ref != assigned_2 + 2) -> 
                        goto Deny_request
                ::  else -> skip
                fi
            ::  else -> skip
            fi

            if
            ::  tenant_id == 1 && (kek_ref != assigned_1 && kek_ref != assigned_1 + 2) -> goto Deny_request
            ::  tenant_id == 2 && (kek_ref != assigned_2 && kek_ref != assigned_2 + 2) -> 
                if 
                ::  grant == VALID_GRANT && assigned_1 == kek_ref && msg == d_DEK -> skip
                ::  else -> goto Deny_request
                fi
            ::  else -> skip
            fi

            if
            ::  MODEL == 1 -> 
                    ac2k_buff < AC2K_MAX
                    ac2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, 0, step+1
                    ac2k_buff++
            ::  else -> skip
            fi
            ac2k_buff < AC2K_MAX
            ac2k!msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
            ac2k_buff++
            
            goto Cleanup
        }
    
    Deny_request:
        
        atomic {
            
            if 
            ::  msg == e_DEK || msg == re_DEK || msg == d_DEK -> 
                // SYNCHRONIZATION VIOLATION                
                if
                ::  tenant_id == 1 && kek_ref == 6 ->
                        p_sync = false
                ::  tenant_id == 2 && kek_ref == 7  && grant != VALID_GRANT ->
                        p_sync = false
                ::  else -> skip
                fi
            ::  else -> skip
            fi

            ac2k_buff < AC2K_MAX 
            ac2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, EMPTY_PASS, id, step+1
            ac2k_buff++


            goto Cleanup
        }
    
    Cleanup:

        atomic {

            auth_ac = 0
            msg = deny
            dek_id = 0
            kek_ref = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_version = 0
            tenant_id = 0
            grant = 0
            step = 0

            goto Receive
        }
}
