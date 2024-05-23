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

#define NUM_DEKS 1
#define NUM_KEKS 2
#define NUM_TENANTS 2
#define VALID_GRANT 1
#define ENC_DUMMY 5
#define EMPTY_PASS 0

// CHANNEL CAPS
#define T2K_MAX 1
#define K2T_MAX 1
#define K2AC_MAX 1
#define AC2K_MAX 1
#define K2DB_MAX 1
#define DB2K_MAX 1

// REQUEST LIMIT OF CONCURRENT PROCESSING IN KEYSTORE
#define REQ_MAX 2

/**
    MODELS
    1: Assignemnt and Encryption.
    2: Decryption with 
    2: Tenant 1 full operations, Tenant 2 only Decrypts encrypted DEKs received from Tenant 1 with different grants
    3: Re-Encryption of encrypted DEKs 
*/ 
#define MODEL 1

typedef KEK { /* Unencrypted */
    unsigned id : 2
    bit version
}


typedef E_DEK { /* Encrypted */
    unsigned id : 3
    unsigned ref_id : 3
    bit enc_version
    bit ref_version
}

mtype = { e_DEK, d_DEK, re_DEK, ass_KEK, ass_KEK2, deny }

// t1: Tenant 1
// t2: Tenant 2
// k: Keystore
// ac: Access Control
// db: Database

// { message type, DEK_ID, KEK_ID, E_KEY-ID, (E_KEY-ENC_V), E_KEY-REF_V, TENANT_ID, (GRANT), (KEK-VERSION), AUTH } 
chan t12k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte }	                // Tenant 1 -> Keystore, |t12k| = 6
chan k2t1 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	            // Keystore -> Tenant 1, |k2t1| = 7

chan t22k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	            // Tenant 2 -> Keystore, |t22k| = 7
chan k2t2 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	    // Keystore -> Tenant 2, |k2t2| = 8

chan k2ac = [K2AC_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	    // Keystore -> Access Control, |k2ac| = 8
chan ac2k = [AC2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	    // Access Control -> Keystore, |ac2k| = 8

chan k2db = [K2DB_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	    // Keystore -> Database, |k2db| = 8
chan db2k = [DB2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte, byte }	// Database -> Keystore, |db2k| = 9

bool exit_atomic
local bool cache_cleared

// Channel buffers
unsigned t12k_buff: 3, t22k_buff: 3
unsigned k2t1_buff: 3, k2t2_buff: 3
unsigned k2db_buff: 3, db2k_buff: 3
unsigned k2ac_buff: 3, ac2k_buff: 3
unsigned req_buff: 3

// LTL variables
bool p_assigned_1, p_assigned_2, curr_rotation//, db_active
bool p_conf = true, p_authentic = true, p_int = true, p_sync = true, p_protocol = true
local bool p_rotated_1 , p_rotated_2, p_enc_1, p_enc_2, db_skip_1, db_skip_2//, p_dec_1, p_dec_2
//unsigned p_enc_1 : 3, p_enc_2 : 3, p_dec_1 : 3, p_dec_2 : 3 //, p_will_rotate_1, p_will_rotate_2
// unsigned count_1 : 2, count_2 : 2

// LTL claims
ltl safety_model_1 { [](p_conf && p_authentic && p_int && p_protocol && p_sync && (Tenant_1[1]@Decrypt_receive -> p_enc_1) && (Tenant_2[2]@Decrypt_receive -> p_enc_2) && (p_enc_1 -> p_assigned_1) && (p_enc_2 -> p_assigned_2 )) }
// ltl liveness_existence_1 {!([]<>(Tenant_1[1]@Encrypt_receive))}
// ltl liveness_existence_2 {!([]<>(Tenant_1[1]@Decrypt_receive))}
// ltl liveness_existence_3 {!([]<>(Tenant_1[1]@Decrypt_receive) && ![]<>(Tenant_1[1]@Encrypt_receive))}
// ltl liveness_existence_4 {!([]<>(Tenant_2[2]@Encrypt_receive))}
// ltl liveness_existence_5 {!([]<>(Tenant_2[2]@Decrypt_receive))}
// ltl liveness_existence_6 {!([]<>(Tenant_2[2]@Decrypt_receive) && ![]<>(Tenant_2[2]@Encrypt_receive))}
// ltl liveness_existence_7 {!([]<>(Tenant_1[1]@Encrypt_receive) && []<>(Tenant_1[1]@Decrypt_receive && Tenant_2[2]@Encrypt_receive) && []<>(Tenant_2[2]@Decrypt_receive))}
ltl liveness_model_1 {  ([]<>(Tenant_1[1]@Encrypt_receive) -> ([]<>(p_rotated_1) && []<>(!p_rotated_1))) && ([]<>(Tenant_2[2]@Encrypt_receive) -> ([]<>(p_rotated_2) && []<>(!p_rotated_2))) &&
                        ([]<>(Tenant_1[1]@Decrypt_receive) -> ([]<>(p_rotated_1) && []<>(!p_rotated_1))) && ([]<>(Tenant_2[2]@Decrypt_receive) -> ([]<>(p_rotated_2) && []<>(!p_rotated_2))) &&
                        (([]<>(Tenant_1[1]@Decrypt_receive) && ![]<>(Tenant_1[1]@Encrypt_receive))-> ([]<>(db_skip_1) && []<>(!db_skip_1))) &&
                        (([]<>(Tenant_2[2]@Decrypt_receive) && ![]<>(Tenant_2[2]@Encrypt_receive))-> ([]<>(db_skip_2) && []<>(!db_skip_2))) }


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
    unsigned temp_dek: 3, assigned_KEK : 3, ref_version_1 : 1, ref_version_2 : 1, step : 4
    unsigned id : 2 = 1
    unsigned dek_id : 2 = 1
    bit auth, denied
    
    E_DEK temp_e_dek, encrypted_DEK

    atomic {
        do
        ::  MODEL == 1 -> break
        ::  MODEL == 2 -> 
                encrypted_DEK.id = 6
                encrypted_DEK.ref_id = 6
                ref_version_1 = 0
                ref_version_2 = 1
                break
        ::  MODEL == 3 -> 
                encrypted_DEK.id = 6
                encrypted_DEK.ref_id = 6
                break
        od
    }

    Select_state:

        exit_atomic = true

        atomic {
            
            do
            ::  k2t1_buff > 0 -> k2t1?msg, temp_dek, temp_e_dek.ref_id, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, auth, step -> req_buff-- -> k2t1_buff-- -> 
                // AUTHENTICATION OR CONFIDENTIALITY VIOLATION
                if
                ::  temp_e_dek.id == 1 || temp_e_dek.id == 2 -> p_conf = false
                ::  temp_e_dek.ref_id == 1 || temp_e_dek.ref_id == 2 -> p_conf = false
                ::  auth != 1 -> p_authentic = false
                ::  else -> skip
                fi

                if
                ::  msg == deny -> 
                        denied = true
                        // if
                        // ::  step != 2 -> p_protocol = false
                        // ::  else -> skip
                        // fi
                ::  else ->
                    denied = false
                    if
                    ::  msg == ass_KEK -> goto Assign_KEK_receive
                    ::  msg == d_DEK -> goto Decrypt_receive
                    ::  msg == e_DEK -> goto Encrypt_receive
                    ::  msg == re_DEK -> goto Recrypt_Receive
                    fi    
                fi
                // break
            
            ::  t12k_buff < T2K_MAX -> 
                
                do
                ::  MODEL == 1 -> 
                    do
                    ::  !(denied && p_assigned_1) -> 
                        Assign_send:
                            t12k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  !(denied && !p_assigned_1) ->
                        Encrypt_send:
                            t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, 1 -> break
                    ::  !(denied && encrypted_DEK.id == 0) -> 
                        Decrypt_send:
                            t12k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.ref_version, id, 1 -> break
                    od
                    break
                ::  MODEL == 2 -> 
                    do
                    ::  t12k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, ref_version_1, id -> break
                    ::  t12k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, ref_version_2, id -> break
                    ::  t12k!d_DEK, EMPTY_PASS, EMPTY_PASS, encrypted_DEK.id, ref_version_2, id -> break
                    od
                    break
                ::  MODEL == 3 -> t12k!re_DEK, assigned_KEK, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.ref_version, id -> break
                od
                t12k_buff++
                // break
            od

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
            // printf("1\n")
            assert(dek_id == temp_dek)
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

            p_enc_1 = true

            goto Cleanup
        }
    
    Recrypt_Receive:

        atomic {
            assert(temp_e_dek.enc_version != encrypted_DEK.enc_version)
            assert(temp_e_dek.id-ENC_DUMMY == dek_id)
            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

            goto Cleanup
        }

    Cleanup:

        atomic {
            step = 0
            auth = 0
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
    unsigned temp_dek: 3, assigned_KEK : 3, grant : 2, ref_version_1 : 1, ref_version_2 : 1, step : 4
    unsigned id : 2 = 2
    unsigned dek_id : 2 = 2
    bit auth, denied
    E_DEK temp_e_dek, encrypted_DEK, received_e_DEK

    atomic {

        do
        ::  MODEL == 1 -> break
        ::  MODEL == 2 -> 
                received_e_DEK.id = 6
                received_e_DEK.ref_id = 6 
                encrypted_DEK.id = 7
                encrypted_DEK.ref_id = 7
                ref_version_1 = 0
                ref_version_2 = 1
                break
        // ::  MODEL == 2 -> 
        //         break
        ::  MODEL == 3 -> 
                encrypted_DEK.id = 7
                encrypted_DEK.ref_id = 7
                received_e_DEK.id = 6
                received_e_DEK.ref_id = 6 
                break
        od
    }

    Select_state:

        exit_atomic = true

        atomic {

            do
            ::  k2t2_buff > 0 -> k2t2?msg, temp_dek, temp_e_dek.ref_id, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, auth, step -> req_buff-- -> k2t2_buff-- -> 
                // AUTHENTICATION OR CONFIDENTIALITY VIOLATION
                if
                ::  auth != 1 -> p_authentic = false
                ::  temp_e_dek.id == 1 || temp_e_dek.id == 2 -> p_conf = false
                ::  temp_e_dek.ref_id == 1 || temp_e_dek.ref_id == 2 -> p_conf = false
                ::  else -> skip
                fi

                if
                ::  msg == deny -> 
                    denied = true
                    // PROTOCOL VIOLATION
                    // if
                    // ::  step != 4 -> p_protocol = false
                    // ::  else -> skip
                    // fi
                ::  else ->
                    denied = false
                    if
                    ::  msg == ass_KEK -> goto Assign_KEK_receive
                    ::  msg == d_DEK -> goto Decrypt_receive
                    ::  msg == e_DEK -> goto Encrypt_receive
                    ::  msg == re_DEK -> goto Recrypt_Receive
                    fi    
                fi

                // break
            ::  t22k_buff < T2K_MAX -> 

                do
                ::  MODEL == 1 -> 
                    do
                    ::  !(denied && p_assigned_2) -> 
                        Assign_send:
                            t22k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant, 1 -> break
                    ::  !(denied && !p_assigned_2) ->
                        Encrypt_send:
                            t22k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, grant, 1 -> break
                    ::  !(denied && encrypted_DEK.id == 0) -> 
                        Decrypt_send:
                            t22k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.ref_version, id, grant, 1 -> break
                    od
                    break
                ::  MODEL == 2 -> 
                    do
                    ::  t22k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, ref_version_1, id, grant -> break
                    ::  t22k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, ref_version_2, id, grant -> break
                    ::  t22k!d_DEK, EMPTY_PASS, EMPTY_PASS, encrypted_DEK.id, ref_version_1, id, grant -> break
                    // ::  t22k!d_DEK, EMPTY_PASS, received_e_DEK.ref_id, received_e_DEK.id, ref_version_1, id, VALID_GRANT -> break
                    // ::  t22k!d_DEK, EMPTY_PASS, received_e_DEK.ref_id, received_e_DEK.id, ref_version_2, id, VALID_GRANT -> break
                    // ::  t22k!d_DEK, EMPTY_PASS, received_e_DEK.ref_id, received_e_DEK.id, ref_version_1, id, grant -> break
                    // ::  t22k!d_DEK, EMPTY_PASS, received_e_DEK.ref_id, received_e_DEK.id, ref_version_2, id, grant -> break
                    od
                    break
                ::  MODEL == 3 -> t22k!re_DEK, assigned_KEK, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.ref_version, id, grant -> break
                od
                t22k_buff++
                // break
            od
            
        }


    
    Assign_KEK_receive:

        atomic {
            // PROTOCOL, SYNCHRONIZATION OR INTEGRITY VIOLATION
            if
            ::  step != 8 -> p_protocol = false
            ::  assigned_KEK == temp_e_dek.ref_id -> p_int = false 
            ::  p_assigned_2 -> p_sync = false // liveness
            ::  else -> skip
            fi
            p_assigned_2 = true
            assigned_KEK = temp_e_dek.ref_id
            
            goto Cleanup
        }
    
    Decrypt_receive:

        atomic {
            // printf("2\n")
            // PROTOCOL OR INTEGRITY VIOLATION
            if
            ::  step != 4 && step != 6 -> p_protocol = false
            ::  dek_id != temp_dek -> p_int = false
            ::  grant == 1 && temp_dek != 1 -> p_int = false
            ::  else -> skip
            fi
            // assert(false)
            
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
            
            p_enc_2 = true

            goto Cleanup
        }
    
    Recrypt_Receive:

        atomic {
            
            assert(temp_e_dek.enc_version != encrypted_DEK.enc_version)
            assert(temp_e_dek.id-ENC_DUMMY == dek_id)

            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

            goto Cleanup
        }

    Cleanup:

        atomic {

            auth = 0
            grant = 0
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
    unsigned dek_id : 3, kek_id : 3, kek_ref : 3, tenant_id : 3, select_case : 3, grant : 2, kek_version : 1, auth : 1, step : 3
    bit id = 1
    bit last_enc_1, last_enc_2, turn 
    E_DEK temp_e_dek
    KEK temp_key
    KEK v_KEKs[NUM_KEKS]

    atomic{

        if
        ::  MODEL != 1 -> 
            v_KEKs[0].id = 1        
            v_KEKs[0].id = 2 
        ::  else -> skip
        fi
    }   

    Select_state:

        cache_cleared = !cache_cleared

        atomic {


            do  //FROM AC
            ::  ac2k_buff > 0 -> ac2k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth, step -> ac2k_buff-- ->  
                
                select_case = 2

                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  auth != 1 -> p_authentic = false -> goto Deny_request
                ::  msg == ass_KEK2 && step != 7 -> p_protocol = false
                ::  msg != ass_KEK2 && msg != deny && step != 3 -> p_protocol = false
                ::  msg == deny && step != 7 && step != 3 -> p_protocol = false
                ::  else -> skip
                fi

                if  // Dereference KEK encryption with MK
                ::  kek_ref > 5 -> kek_id = kek_ref-ENC_DUMMY
                ::  else -> kek_id = 0
                fi

                do
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  msg == ass_KEK2 -> select_case = 4 -> goto Assign_KEK
                ::  msg == d_DEK -> goto Decrypt  
                ::  msg == e_DEK -> goto Encrypt 
                ::  msg == re_DEK -> goto Recrypt 
                ::  msg == deny -> goto Deny_request
                od
            
                //FROM DB
            ::  db2k_buff > 0 -> db2k?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, kek_version, auth, step -> db2k_buff-- ->  

                select_case = 3

                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  auth != 1 -> p_authentic = false -> goto Deny_request
                ::  step != 5 -> p_protocol = false
                ::  else -> skip
                fi

                do
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  msg == d_DEK -> goto Decrypt  
                ::  msg == e_DEK -> goto Encrypt 
                ::  msg == re_DEK -> goto Recrypt
                ::  msg == deny -> goto Deny_request
                od

             
                // FROM TENANT 
            ::  (turn == 1 || (turn == 0 && t22k_buff == 0)) && req_buff < REQ_MAX && t12k_buff > 0 -> t12k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, step -> req_buff++ -> t12k_buff-- ->                  

                select_case = 1
                turn = 0
                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  tenant_id != 1 -> p_authentic = false -> goto Deny_request
                ::  step != 1 -> p_protocol = false
                ::  else -> skip
                fi

                do
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == e_DEK -> goto Encrypt
                ::  msg == re_DEK -> goto Recrypt
                od
            ::   (turn == 0 || (turn == 1 && t12k_buff == 0)) && req_buff < REQ_MAX && t22k_buff > 0 -> t22k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, step -> req_buff++ -> t22k_buff-- ->  
                
                select_case = 1
                turn = 1
                // PROTOCOL OR AUTHENTICATION VIOLATION
                if
                ::  tenant_id != 2 -> p_authentic = false -> goto Deny_request
                ::  step != 1 -> p_protocol = false
                ::  else -> skip
                fi

                do
                ::  msg == ass_KEK ->  goto Assign_KEK
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == e_DEK -> goto Encrypt
                ::  msg == re_DEK -> goto Recrypt
                od
            od
        }
            
        
    Assign_KEK:

        atomic {
            
            if  // From Tenant to Access Control
            ::  select_case == 1 -> 
                    
                    k2ac_buff < K2AC_MAX 
                    k2ac!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, grant, id, step+1
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 
                // if
                // ::  !SAME_KEK_ASSIGNED -> kek_id = tenant_id  
                // ::  else -> kek_id = 1 
                // fi
                kek_id = tenant_id

                k2db_buff < K2DB_MAX  
                k2db!ass_KEK, EMPTY_PASS, kek_id, EMPTY_PASS, EMPTY_PASS, tenant_id, grant, id, step+1
                k2db_buff++
                
                // From Database to Access Control
            ::  select_case == 3 -> 

                    v_KEKs[kek_id-1].id = kek_id
                    v_KEKs[kek_id-1].version = kek_version

                    k2ac_buff < K2AC_MAX 
                    k2ac!ass_KEK2, EMPTY_PASS, kek_id+ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, tenant_id, grant, id, step+1 
                    k2ac_buff++

                // From Access Control to Tenant
            ::  select_case == 4 -> 

                if // ack from Tenant was received during concurrent processing
                ::  tenant_id == 1 && p_assigned_1 -> goto Deny_request
                ::  tenant_id == 2 && p_assigned_2 -> goto Deny_request
                ::  else -> skip
                fi
            
                if
                ::  tenant_id == 1 -> k2t1_buff < K2T_MAX 
                    k2t1!ass_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, step+1
                    // req_buff-- ->
                    k2t1_buff++
                ::  else -> k2t2_buff < K2T_MAX
                    k2t2!ass_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id, step+1
                    // req_buff-- ->
                    k2t2_buff++
                fi
            fi

            goto Cleanup
        }

    Decrypt:

        atomic {

            if  // From Tenant to Access Control
            ::  select_case == 1 -> 
                    
                    k2ac_buff < K2AC_MAX  
                    k2ac!d_DEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1  
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 
                if // Already in memory so skip Database
                ::  !cache_cleared || !(v_KEKs[kek_id-1].version == 1 && temp_e_dek.ref_version == 0) ->
                    
                    select_case = 4 
                    
                    if
                    ::  tenant_id == 1 -> db_skip_1 = true -> skip
                    ::  tenant_id == 2 -> db_skip_2 = true -> skip
                    fi
                ::  else ->
                    if
                    ::  tenant_id == 1 -> db_skip_1 = false -> skip
                    ::  tenant_id == 2 -> db_skip_2 = false -> skip
                    fi
                    k2db_buff < K2DB_MAX -> 
                    k2db!d_DEK, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
                    k2db_buff++
                fi
                
                // From Database to Tenant
            ::  select_case == 3 -> 
                    
                    select_case = 4
                    
                    v_KEKs[kek_id-1].id = kek_id
                    v_KEKs[kek_id-1].version = kek_version

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
            fi

            if  // DB -> KS -> T or Database skip from case 2 AC -> KS -> T
            ::  select_case == 4 ->
                if
                ::  tenant_id == 1 -> k2t1_buff < K2T_MAX 
                    k2t1!d_DEK, temp_e_dek.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, step+1
                    // req_buff-- -> 
                    k2t1_buff++
                ::  else -> k2t2_buff < K2T_MAX
                    k2t2!d_DEK, temp_e_dek.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id, step+1
                    // req_buff-- -> 
                    k2t2_buff++
                fi
            ::  else -> skip
            fi

            goto Cleanup
        }

    Encrypt:

        atomic {
            
            if  // From Tenant to Access Control
            ::  select_case == 1 -> 

                    k2ac_buff < K2AC_MAX   
                    k2ac!e_DEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 ->

                    k2db_buff < K2DB_MAX 
                    k2db!e_DEK, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
                    k2db_buff++
                
                // From Database to Tenant
            ::  select_case == 3 -> 
                    
                    v_KEKs[kek_id-1].version = kek_version
                    v_KEKs[kek_id-1].id = kek_id
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



                    temp_e_dek.id = dek_id+ENC_DUMMY
                    temp_e_dek.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
                    temp_e_dek.ref_version = v_KEKs[kek_id-1].version

                    do
                    ::  tenant_id == 1 ->
                        last_enc_1 = !last_enc_1
                        temp_e_dek.enc_version = last_enc_1 

                        k2t1_buff < K2T_MAX 
                        k2t1!e_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, id, step+1
                        k2t1_buff++ 
                        break

                    ::  tenant_id == 2 ->
                        
                        last_enc_2 = !last_enc_2
                        temp_e_dek.enc_version = last_enc_2
                        
                        k2t2_buff < K2T_MAX 
                        k2t2!e_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, id, step+1
                        k2t2_buff++ 
                        break
                    od
            fi
            
            goto Cleanup
        }

    Recrypt:
           
        atomic {

            if  // From Tenant to Access Control
            ::  select_case == 1 -> 
                    
                    k2ac_buff < K2AC_MAX 
                    k2ac!re_DEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 

                // "if" decrypts before accessing DB to receive a fresh encryption KEK
                //  "else" needs a fresh KEK to decrypt, but will use that KEK to encrypt

                if 
                ::  cache_cleared || v_KEKs[kek_id-1].version == temp_e_dek.ref_version ->
                // ::  v_KEKs[kek_id-1].id == kek_id && v_KEKs[kek_id-1].version == temp_e_dek.ref_version ->
                        dek_id = temp_e_dek.id-ENC_DUMMY // decrypted here
                ::  else -> skip
                fi

                k2db_buff < K2DB_MAX 
                k2db!re_DEK, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
                k2db_buff++

                // From Database to Tenant
            ::  select_case == 3 ->

                v_KEKs[kek_id-1].id = kek_id
                v_KEKs[kek_id-1].version = kek_version

                // "if" 1 and 2 where decrypted in case 2 above
                //  "if" 6 and 7 needed a fresh KEK to be decrypted 

                if // Mainly to ensure that every path is hit
                ::  dek_id == 1 ->
                        temp_e_dek.id = dek_id+ENC_DUMMY // encrypted here
                ::  dek_id == 2 ->
                        temp_e_dek.id = dek_id+ENC_DUMMY // encrypted here
                ::  else -> 
                    if
                    ::  temp_e_dek.id == 6 -> 
                            assert(6 < 86) // decrypted and encrypted here
                    ::  temp_e_dek.id == 7 -> 
                            assert(6 < 88) // decrypted and encrypted here
                    fi
                fi 

                temp_e_dek.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
                temp_e_dek.ref_version = v_KEKs[kek_id-1].version

                do
                ::  tenant_id == 1 ->

                        last_enc_1 = !last_enc_1
                        temp_e_dek.enc_version = last_enc_1 
                        
                        k2t1_buff < K2T_MAX 
                        k2t1!re_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, id, step+1
                        // req_buff-- 
                        k2t1_buff++ 
                        break

                ::  tenant_id == 2 ->
                      
                        last_enc_2 = !last_enc_2
                        temp_e_dek.enc_version = last_enc_2
                        
                        k2t2_buff < K2T_MAX 
                        k2t2!re_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, id, step+1
                        // req_buff-- 
                        k2t2_buff++ 
                        break
                od
            fi

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
                    ::  (msg != ass_KEK || msg != ass_KEK2) && kek_ref == 6 -> p_sync = false
                    ::  else -> skip
                    fi
                ::  else -> skip
                fi
                k2t1_buff < K2T_MAX 
                k2t1!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, step+1
                k2t1_buff++
                // req_buff--
            ::  else -> 
                if
                ::  p_assigned_2 && MODEL == 1 ->
                    // SYNCHRONIZATION VIOLATION
                    if
                    ::  (msg != ass_KEK || msg != ass_KEK2) && kek_ref == 7 -> p_sync = false
                    ::  else -> skip
                    fi
                ::  else -> skip
                fi
                k2t2_buff < K2T_MAX 
                k2t2!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id, step+1
                k2t2_buff++
                // req_buff--
            fi

            goto Cleanup
        } 

    Cleanup:

        atomic {

            auth = 0
            grant = 0
            msg = deny
            dek_id = 0
            kek_id = 0
            kek_ref = 0
            kek_version = 0
            tenant_id = 0
            select_case = 0
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
    unsigned kek_id : 3, i : 3, tenant_id : 3, dek_id : 2, grant : 2, auth : 1, step : 3
    bit id = 1

    KEK p_KEKs[NUM_KEKS]
    p_KEKs[0].id = 1
    p_KEKs[1].id = 2
    E_DEK temp_e_dek

    Select_state:
        
        exit_atomic = true

        atomic {
            k2db_buff > 0 
            k2db?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth, step
            k2db_buff--

            // PROTOCOL, AUTHENTICATION OR INTEGRITY VIOLATION
            if
            ::  step != 4 -> p_protocol = false
            ::  auth != 1 -> p_authentic = false -> goto Deny_request
            ::  kek_id != 1 && kek_id != 2 -> p_int = false
            ::  else -> skip
            fi
            
            do
            ::  (msg == e_DEK || msg == d_DEK || msg == ass_KEK || msg == re_DEK) -> goto Access_KEK
            ::  else -> goto Deny_request
            od
            
        }

    Access_KEK:

        atomic {

            for (i : 0 .. NUM_KEKS-1) {
                if 
                ::  p_KEKs[i].id == kek_id ->

                    db2k_buff < DB2K_MAX 
                    // curr_rotation = !curr_rotation
                    // p_KEKs[0].version = curr_rotation
                    // p_KEKs[1].version = curr_rotation
                    p_KEKs[i].version = !p_KEKs[i].version
                    db2k!msg, dek_id, p_KEKs[i].id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, p_KEKs[i].version, id, step+1
                    db2k_buff++

                    goto Cleanup

                ::  else -> skip
                fi
            }
            
            goto Deny_request
        
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

            auth = 0
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
    unsigned kek_ref : 3, tenant_id : 3, auth : 1, dek_id : 2, grant : 2, assigned_1 : 3, assigned_2 : 3, step : 3
    bit id = 1
    E_DEK temp_e_dek
    
    atomic {
        
        if
        ::  MODEL != 1 -> 
                assigned_1 = 6
                assigned_2 = 7
        ::  else -> skip
        fi
    
    }

    Select_state:
        
        exit_atomic = true

        atomic {
            k2ac_buff > 0 
            k2ac?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth, step
            k2ac_buff--
            
            // PROTOCOL, AUTHENTICATION OR CONFIDENTIALITY VIOLATION
            if
            ::  temp_e_dek.id == 1 || temp_e_dek.id == 2 -> p_conf = false
            ::  temp_e_dek.ref_id == 1 || temp_e_dek.ref_id == 2 -> p_conf = false
            ::  kek_ref == 1 || kek_ref == 2 -> p_conf = false
            ::  auth != 1 -> p_authentic = false -> goto Deny_request
            ::  msg != ass_KEK2 && step != 2 -> p_protocol = false
            ::  msg == ass_KEK2 && step != 6 -> p_protocol = false
            ::  else -> skip
            fi


            if
            ::  msg == ass_KEK -> goto Assign_KEK_authorize
            ::  msg == ass_KEK2 -> goto Assign_KEK2_authorize
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
            ac2k!ass_KEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
            ac2k_buff++

            goto Cleanup
        }        

    Assign_KEK2_authorize:

        // Newly generated key assigned
        atomic {

            assert(kek_ref > 5)
            
            if 
            ::  tenant_id == 1 && assigned_1 == 0 -> assigned_1 = kek_ref 
            ::  tenant_id == 2 && assigned_2 == 0 -> assigned_2 = kek_ref 
            ::  else -> goto Deny_request
            fi
            
            ac2k_buff < AC2K_MAX
            ac2k!ass_KEK2, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id, step+1
            ac2k_buff++

            goto Cleanup
        }    


    Authorize:

        atomic {
            
            if
            ::  kek_ref != 6 && kek_ref != 7 -> goto Deny_request
            ::  else -> skip
            fi

            if
            ::  tenant_id == 1 && (kek_ref != assigned_1) -> goto Deny_request
            ::  tenant_id == 2 && (kek_ref != assigned_2) -> 
                if 
                ::  grant == VALID_GRANT && assigned_1 == kek_ref && msg == d_DEK -> skip
                ::  else -> goto Deny_request
                fi
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
            // db_active = false
            auth = 0
            msg = deny
            dek_id = 0
            kek_ref = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_version = 0
            tenant_id = 0
            grant = 0
            step = 0

            goto Select_state
        }
}
