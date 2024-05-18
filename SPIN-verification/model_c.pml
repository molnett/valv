#define NUM_DEKS 1
#define NUM_KEKS 2
#define NUM_TENANTS 2
#define VALID_GRANT 1
#define ENC_DUMMY 5
#define EMPTY_PASS 0
#define SAME_KEK_ASSIGNED false

// CHANNEL CAPS
#define T2K_MAX 1
#define K2T_MAX 1
#define K2AC_MAX 1
#define AC2K_MAX 1
#define K2DB_MAX 1
#define DB2K_MAX 1
#define REQ_MAX 2

/**
    MODELS
    1: Assignemnt and Encryption.
    2: Decryption
    2: Tenant 1 full operations, Tenant 2 only Decrypts encrypted DEKs received from Tenant 1 with different grants
    3: Re-Encryption of encrypted DEKs 
*/ 
#define MODEL 3

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
chan t12k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte }	                // Tenant 1 -> Keystore, |t12k| = 6
chan k2t1 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte, byte }	                // Keystore -> Tenant 1, |k2t1| = 7

chan t22k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte }	            // Tenant 2 -> Keystore, |t22k| = 7
chan k2t2 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	            // Keystore -> Tenant 2, |k2t2| = 8

chan k2ac = [K2AC_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	    // Keystore -> Access Control, |k2ac| = 8
chan ac2k = [AC2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	    // Access Control -> Keystore, |ac2k| = 8

chan k2db = [K2DB_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	    // Keystore -> Database, |k2db| = 8
chan db2k = [DB2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	// Database -> Keystore, |db2k| = 9

bool exit_atomic
local bool cache_cleared, p_rotated_1, p_rotated_2

// Channel buffers
unsigned t12k_buff: 3, t22k_buff: 3
unsigned k2t1_buff: 3, k2t2_buff: 3
unsigned k2db_buff: 3, db2k_buff: 3
unsigned k2ac_buff: 3, ac2k_buff: 3
unsigned req_buff: 3

// LTL variables
bool p_assigned_1, p_assigned_2, p_enc_1, p_enc_2, p_1 = true, p_2 = true, p_conf = true, p_authentic = true, p_int = true


// LTL claims
// ltl { [] conf }
// ltl Confidentiality { [] (enc_1 != u_enc_1 && enc_2 != u_enc_2 && enc_1 > 4 && enc_2 > 4 && (u_enc_1 == 14||u_enc_1 < 5) && (u_enc_2 == 14 || u_enc_2 < 5)) }
// bool ps_confidentiality, ps_integrity, ps_authentication, ps_authorization, ps_consistency, pl_confidentiality, pl_integrity, pl_authentication, pl_authorization, pl_consistency
// TRY TO VIOLATE LTL
ltl safety_model_1 { [](p_conf && p_authentic && p_int) && [](p_1 && p_2)&& ( p_enc_1 -> p_assigned_1 ) && ( p_enc_2 -> p_assigned_2 ) }
ltl liveness_model_1 {[]<>(p_enc_1 && p_enc_2) && (!p_enc_1 U p_assigned_1) && (!p_enc_2 U p_assigned_2)}
// ltl safety_model_2
// ltl liveness_model_2
// ltl safety_model_3
// ltl liveness_model_3
// ltl safety_model_4
// ltl liveness_model_4
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
    unsigned temp_dek: 3, assigned_KEK : 3, ref_version_1 : 1, ref_version_2 : 1
    unsigned id : 2 = 1
    unsigned dek_id : 2 = 1
    bit auth
    
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
            ::  k2t1_buff > 0 -> k2t1?msg, temp_dek, temp_e_dek.ref_id, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, auth -> k2t1_buff-- -> 
                
                // CONFIDENTIALITY VIOLATION
                if
                ::  temp_e_dek.id == 1 || temp_e_dek.id == 2 -> p_conf = false
                ::  temp_e_dek.ref_id == 1 || temp_e_dek.ref_id == 2 -> p_conf = false
                ::  else -> skip
                fi

                // AUTHENTICATION VIOLATION
                if
                ::  auth != 1 -> p_authentic = false
                ::  else -> skip
                fi

                if
                ::  msg == ass_KEK -> goto Assign_KEK_receive
                ::  msg == d_DEK -> goto Decrypt_receive
                ::  msg == e_DEK -> goto Encrypt_receive
                ::  msg == re_DEK -> goto Recrypt_Receive
                ::  else -> 
                    if
                    ::  MODEL == 1 -> 
                        if
                        ::  assigned_KEK != 0 -> p_1 = false
                        ::  else -> skip
                        fi
                    ::  else -> skip
                    fi
                fi

                break
                
            ::  t12k_buff < T2K_MAX -> 
                do
                ::  MODEL == 1 -> 
                    do
                    ::  t12k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                    ::  t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id -> break
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
                break

            ::  else -> break
            od

            goto Select_state
        }
    
    Assign_KEK_receive:

        atomic {
            
            // P VIOLATION
            d_step { 
                if
                ::  assigned_KEK == temp_e_dek.ref_id -> p_int = false 
                ::  p_assigned_2 -> p_1 = false
                ::  else -> skip
                fi
            }

            p_assigned_1 = true
            assigned_KEK = temp_e_dek.ref_id
            
            goto Cleanup
        }
    
    Decrypt_receive:

        atomic {

            assert(dek_id == temp_dek)

            goto Cleanup
        }
    
    Encrypt_receive:

        atomic {

            p_enc_1 = true
            
            // P VIOLATION
            d_step {
                if
                ::  temp_e_dek.enc_version == encrypted_DEK.enc_version -> p_1 = false
                ::  temp_e_dek.id-ENC_DUMMY != dek_id -> p_int = false
                ::  temp_e_dek.ref_id != assigned_KEK -> p_int = false
                ::  else -> skip
                fi
            }

            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

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
    unsigned temp_dek: 3, assigned_KEK : 3, grant : 2, ref_version_1 : 1, ref_version_2 : 1
    unsigned id : 2 = 2
    unsigned dek_id : 2 = 2
    bit auth
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
            ::  k2t2_buff > 0 -> k2t2?msg, temp_dek, temp_e_dek.ref_id, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, auth -> k2t2_buff-- -> 
                // CONFIDENTIALITY VIOLATION
                if
                ::  temp_e_dek.id == 1 || temp_e_dek.id == 2 -> p_conf = false
                ::  temp_e_dek.ref_id == 1 || temp_e_dek.ref_id == 2 -> p_conf = false
                ::  else -> skip
                fi

                // AUTHENTICATION VIOLATION
                if
                ::  auth != 1 -> p_authentic = false
                ::  else -> skip
                fi

                if
                ::  msg == ass_KEK -> goto Assign_KEK_receive
                ::  msg == d_DEK -> goto Decrypt_receive
                ::  msg == e_DEK -> goto Encrypt_receive
                ::  msg == re_DEK -> goto Recrypt_Receive
                ::  else -> 
                    if
                    ::  MODEL == 1 -> 
                        if
                        ::  assigned_KEK != 0 -> p_2 = false
                        ::  else -> skip
                        fi
                    ::  else -> skip
                    fi
                fi

                break

            ::  t22k_buff < T2K_MAX -> 

                do
                ::  MODEL == 1 -> 
                    do
                    :: t22k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                    :: t22k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, id, grant -> break
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
                break

            ::  else -> break
            od

            goto Select_state
        }

    
    Assign_KEK_receive:

        atomic {

            // P VIOLATION
            d_step { 
                if
                ::  assigned_KEK == temp_e_dek.ref_id -> p_int = false 
                ::  p_assigned_2 -> p_2 = false // liveness
                ::  else -> skip
                fi
            }

            p_assigned_2 = true
            assigned_KEK = temp_e_dek.ref_id
            
            goto Cleanup
        }
    
    Decrypt_receive:

        atomic {

            assert(dek_id == temp_dek || (grant != 0 && temp_dek == 1))
            // assert(false)
            
            goto Cleanup
        }
    
    Encrypt_receive:

        atomic {
            
            // printf("Received 2\n")
            // if
            // ::  encrypted_DEK.id == 0 -> skip
            // ::  encrypted_DEK.id != 0 && temp_e_dek.ref_version < encrypted_DEK.ref_version -> //TODO
            //     if
            //     ::  temp_e_dek.ref_id-ENC_DUMMY == 1 -> assert(curr_rotation_1) -> curr_rotation_1 = false
            //     ::  else -> assert(curr_rotation_2) -> curr_rotation_2 = false
            //     fi
            // ::  else -> assert(temp_e_dek.ref_version >= encrypted_DEK.ref_version)
            // fi
            p_enc_2 = true
            // SAFETY VIOLATION
            if
            ::  temp_e_dek.enc_version == encrypted_DEK.enc_version -> p_2 = false
            ::  temp_e_dek.id-ENC_DUMMY != dek_id -> p_2 = false
            ::  temp_e_dek.ref_id != assigned_KEK -> p_2 = false
            ::  else -> skip
            fi

            encrypted_DEK.id = temp_e_dek.id
            encrypted_DEK.enc_version = temp_e_dek.enc_version
            encrypted_DEK.ref_id = temp_e_dek.ref_id
            encrypted_DEK.ref_version = temp_e_dek.ref_version

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

            goto Select_state
        }
}

proctype Keystore()
{
    mtype msg = deny, enc_msg
    unsigned dek_id : 3, kek_id : 3, kek_ref : 3, tenant_id : 3, select_case : 3, grant : 2, kek_version : 1, auth : 1
    bit id = 1
    bit last_enc_1, last_enc_2
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

        exit_atomic = true

        atomic {

            if
            ::  MODEL == 1 -> skip
            ::  else -> cache_cleared = !cache_cleared
            fi

            p_rotated_1 = false
            p_rotated_2 = false
            // do  // Cache clear
            // ::  v_KEKs[0].id = 0        
            //     v_KEKs[0].id = 0 
            //     break       
            // ::  v_KEKs[0].id = 1        
            //     v_KEKs[0].id = 2        
            //     break       
            // od


            do  //FROM AC
            ::  ac2k_buff > 0 -> ac2k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth -> ac2k_buff-- ->  
                
                select_case = 2

                if
                ::  auth != 1 -> p_authentic = false -> goto Deny_request
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
            ::  db2k_buff > 0 -> db2k?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, kek_version, auth -> db2k_buff-- ->  
                
                select_case = 3

                if
                ::  auth != 1 -> p_authentic = false -> goto Deny_request
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
            ::  req_buff < REQ_MAX && t12k_buff > 0 -> t12k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id -> req_buff++ -> t12k_buff-- ->                  
                
                select_case = 1

                if
                ::  tenant_id != 1 -> p_authentic = false -> goto Deny_request
                ::  else -> skip
                fi

                do
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == e_DEK -> goto Encrypt
                ::  msg == re_DEK -> goto Recrypt
                od
            ::  req_buff < REQ_MAX && t22k_buff > 0 -> t22k?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant -> req_buff++ -> t22k_buff-- ->  
                
                select_case = 1

                if
                ::  tenant_id != 2 -> p_authentic = false -> goto Deny_request
                ::  else -> skip
                fi

                do
                ::  msg == ass_KEK ->  goto Assign_KEK
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == e_DEK -> goto Encrypt
                ::  msg == re_DEK -> goto Recrypt
                od
            ::  else -> break
            od
            
            goto Select_state
        }
        
    Assign_KEK:

        atomic {
            
            if  // From Tenant to Access Control
            ::  select_case == 1 -> 
                    k2ac_buff < K2AC_MAX 
                    k2ac!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, grant, id 
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 
                // if
                // ::  !SAME_KEK_ASSIGNED -> kek_id = tenant_id  
                // ::  else -> kek_id = 1 
                // fi
                kek_id = tenant_id

                k2db_buff < K2DB_MAX  
                k2db!ass_KEK, EMPTY_PASS, kek_id, EMPTY_PASS, EMPTY_PASS, tenant_id, grant, id 
                k2db_buff++
                
                // From Database to Access Control
            ::  select_case == 3 -> 

                    v_KEKs[kek_id-1].id = kek_id
                    v_KEKs[kek_id-1].version = kek_version

                    k2ac_buff < K2AC_MAX 
                    k2ac!ass_KEK2, EMPTY_PASS, kek_id+ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, tenant_id, grant, id  
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
                    k2t1!ass_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id
                    req_buff-- -> k2t1_buff++
                ::  else -> k2t2_buff < K2T_MAX
                    k2t2!ass_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id
                    req_buff-- -> k2t2_buff++
                fi
            ::  else -> assert(false)
            fi

            goto Cleanup
        }

    Decrypt:

        atomic {

            if  // From Tenant to Access Control
            ::  select_case == 1 -> 
                    
                    k2ac_buff < K2AC_MAX  
                    k2ac!d_DEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id  
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 
                if // Already in memory so skip Database
                // ::  v_KEKs[kek_id-1].id == kek_id && v_KEKs[kek_id-1].version == temp_e_dek.ref_version ->
                ::  cache_cleared || v_KEKs[kek_id-1].version == temp_e_dek.ref_version ->
                        select_case = 4 
                ::  else ->
                        k2db_buff < K2DB_MAX -> 
                        k2db!d_DEK, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id 
                        k2db_buff++
                fi
                
                // From Database to Tenant
            ::  select_case == 3 -> 
                    select_case = 4
                    v_KEKs[kek_id-1].id = kek_id
                    v_KEKs[kek_id-1].version = kek_version
            fi

            if  // DB -> KS -> T or Database skip from case 2 AC -> KS -> T
            ::  select_case == 4 ->
                if
                ::  tenant_id == 1 -> k2t1_buff < K2T_MAX 
                    k2t1!d_DEK, temp_e_dek.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id
                    req_buff-- -> k2t1_buff++
                ::  else -> k2t2_buff < K2T_MAX
                    k2t2!d_DEK, temp_e_dek.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id
                    req_buff-- -> k2t2_buff++
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
                    k2ac!e_DEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id  
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 ->

                    k2db_buff < K2DB_MAX 
                    k2db!e_DEK, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id 
                    k2db_buff++
                
                // From Database to Tenant
            ::  select_case == 3 -> 

                    v_KEKs[kek_id-1].id = kek_id
                    if
                    ::  tenant_id == 1 && v_KEKs[kek_id-1].version != kek_version -> 
                            p_rotated_1 = true
                    ::  tenant_id == 2 && v_KEKs[kek_id-1].version != kek_version -> 
                            p_rotated_2 = true
                    ::  else skip
                    fi
                    v_KEKs[kek_id-1].version = kek_version

                    temp_e_dek.id = dek_id+ENC_DUMMY
                    temp_e_dek.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
                    temp_e_dek.ref_version = v_KEKs[kek_id-1].version
                    do
                    ::  tenant_id == 1 ->
                        
                        last_enc_1 = !last_enc_1
                        temp_e_dek.enc_version = last_enc_1 

                        k2t1_buff < K2T_MAX 
                        k2t1!e_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, id
                        req_buff-- 
                        k2t1_buff++ 
                        break

                    ::  tenant_id == 2 ->
                        
                        last_enc_2 = !last_enc_2
                        temp_e_dek.enc_version = last_enc_2
                        
                        k2t2_buff < K2T_MAX 
                        k2t2!e_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, id
                        req_buff-- 
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
                    k2ac!re_DEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id
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
                k2db!re_DEK, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id
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
                        k2t1!re_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, id
                        req_buff-- 
                        k2t1_buff++ 
                        break

                ::  tenant_id == 2 ->
                      
                        last_enc_2 = !last_enc_2
                        temp_e_dek.enc_version = last_enc_2
                        
                        k2t2_buff < K2T_MAX 
                        k2t2!re_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_dek.id, temp_e_dek.enc_version, temp_e_dek.ref_version, grant, id
                        req_buff-- 
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
                     k2t1_buff < K2T_MAX 
                     k2t1!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id
                     k2t1_buff++
                     req_buff--
            ::  else -> 
                     k2t2_buff < K2T_MAX 
                     k2t2!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, grant, id
                     k2t2_buff++
                     req_buff--
            fi

            goto Cleanup
        } 

    Cleanup:

        atomic {

            auth = 0
            grant = 0
            select_case = 0
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

            goto Select_state
        }       
}


proctype Database() {

    mtype msg = deny
    unsigned kek_id : 3, i : 3, tenant_id : 3, dek_id : 2, grant : 2, version : 1, auth : 1 
    bit id = 1
    bit curr_rotation

    KEK p_KEKs[NUM_KEKS]
    p_KEKs[0].id = 1
    p_KEKs[1].id = 2
    E_DEK temp_e_dek

    Select_state:
        
        // exit_atomic = true
        curr_rotation = !curr_rotation

        atomic {

            // do // Rotation
            // ::  curr_rotation = 0 -> break
            // ::  curr_rotation = 1 -> break
            // od

            p_KEKs[0].version = curr_rotation
            p_KEKs[1].version = curr_rotation

            k2db_buff > 0 
            k2db?msg, dek_id, kek_id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth
            k2db_buff--

            // AUTHENTICATION VIOLATION
            if
            ::  auth != 1 -> p_authentic = false -> goto Deny_request
            ::  else -> skip
            fi

            assert(kek_id>0 && kek_id<3)
            
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
                    db2k!msg, dek_id, p_KEKs[i].id, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, p_KEKs[i].version, id
                    db2k_buff++

                    goto Cleanup

                ::  else -> skip
                fi
            }
            
            goto Deny_request
        
        }        

    Rotate_KEK:

        atomic {

            goto Cleanup
        }

    Deny_request:
        
        atomic {
            
            db2k_buff < DB2K_MAX 
            db2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, EMPTY_PASS, EMPTY_PASS, id
            db2k_buff++

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

            goto Select_state
        }
}

proctype AccessControl()
{
    mtype msg = deny
    unsigned kek_ref : 3, tenant_id : 3, auth : 1, i : 3, num_assigned : 3, dek_id : 2, grant : 2, assigned_1 : 3, assigned_2 : 3
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
            k2ac?msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, auth
            k2ac_buff--
            
            // CONFIDENTIALITY VIOLATION
            if
            ::  temp_e_dek.id == 1 || temp_e_dek.id == 2 -> p_conf = false
            ::  temp_e_dek.ref_id == 1 || temp_e_dek.ref_id == 2 -> p_conf = false
            ::  kek_ref == 1 || kek_ref == 2 -> p_conf = false
            ::  else -> skip
            fi
            // AUTHENTICATION VIOLATION
            if
            ::  auth != 1 -> p_authentic = false -> goto Deny_request
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
            ac2k!ass_KEK, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id 
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
            ac2k!ass_KEK2, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id
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
            ac2k!msg, dek_id, kek_ref, temp_e_dek.id, temp_e_dek.ref_version, tenant_id, grant, id
            ac2k_buff++
            
            goto Cleanup
        }
    
    Deny_request:
        
        atomic {
            
            ac2k_buff < AC2K_MAX 
            ac2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, EMPTY_PASS, id
            ac2k_buff++


            goto Cleanup
        }
    
    Cleanup:

        atomic {

            auth = 0
            msg = deny
            dek_id = 0
            kek_ref = 0
            temp_e_dek.id = 0
            temp_e_dek.enc_version = 0
            temp_e_dek.ref_version = 0
            tenant_id = 0
            grant = 0

            goto Select_state
        }
}
