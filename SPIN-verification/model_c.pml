#define NUM_DEKS 1
#define NUM_KEKS 2
#define NUM_TENANTS 2
#define T2K_MAX 1
#define K2T_MAX 1
#define K2AC_MAX 1
#define AC2K_MAX 1
#define K2DB_MAX 1
#define DB2K_MAX 1
#define REQ_MAX 2
#define DB2T_MAX 1
#define T_SEND_MAX 1
#define ASS_MAX 1
#define GRANT 1
#define VALID_GRANT 1
#define ENC_DUMMY 5
#define EMPTY_PASS 0
#define ROT_KEK_1 5
#define ROT_KEK_2 17
#define CACHE_CLEAR 8
#define SAME_KEK_ASSIGNED false

typedef KEK { /* Unencrypted */
    unsigned id : 2
    bit version
}


typedef E_Key { /* Encrypted */
    unsigned id : 3
    unsigned ref_id : 3
    bit enc_version
    bit ref_version
}

mtype = { e_DEK, d_DEK, re_DEK, ass_KEK, ass_KEK2 rot_KEK, send_e_DEK, deny, ack }

// t: Tenant
// k: Keystore
// ac: Access Control
// db: Database

// { message type, DEK_ID, KEK_ID, E_KEY-ID, E_KEY-ENC_V, E_KEY-REF_V, TENANT_ID, (GRANT) } 
chan t12k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte }	// Tenant 1 -> Keystore, |t12k| = 7
chan t22k = [T2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	// Tenant 2 -> Keystore, |t22k| = 8
chan k2t1 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte }	// Keystore -> Tenant 1, |k2t1| = 8
chan k2t2 = [K2T_MAX] of { mtype, byte, byte, byte, byte, byte }	// Keystore -> Tenant 2, |k2t2| = 8
// { message type, E_KEY-ID, E_KEY-REF_ID, E_KEY-ENC_V, E_KEY-REF_V, GRANT } size = 6
chan t12t2 = [T_SEND_MAX] of { mtype, byte }	// Tenant 1 -> Tenant 2

//                  { message type, KEK_ID, TENANT_ID, GRANT} 
chan k2ac = [K2AC_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	// Keystore -> Access Control, |k2ac| = 8
chan ac2k = [AC2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	// Access Control -> Keystore, |ac2k| = 8

//                  { message type, KEK_ID, TENANT_ID}
chan k2db = [K2DB_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte }	// Keystore -> Database, |k2db| = 8
//              { message type, KEK_ID, KEK-VERSION, KEK-ASS_TO }
chan db2k = [DB2K_MAX] of { mtype, byte, byte, byte, byte, byte, byte, byte, byte }	// Database -> Keystore, |db2k| = 10

// This  channel emulates an external component notifying 
// the tenant when a curr_rotation has taken place 
//                  { message type, KEK_ID }
chan db2t1 = [DB2T_MAX] of { mtype, byte }  // Database -> Tenant 1, |db2t1| = 1
chan db2t2 = [DB2T_MAX] of { mtype, byte }  // Database -> Tenant 2, |db2t2| = 1

int timer
bool clear_cache, curr_rotation, start
// LTL variables
unsigned enc_1 : 4 = 15, u_enc_1 : 4 = 14, enc_2 : 4 = 15, u_enc_2 : 4 = 14 
unsigned db2t1_buff: 1, db2t2_buff: 1
unsigned t12k_buff: 3, t22k_buff: 3
unsigned k2t1_buff: 3, k2t2_buff: 3
unsigned k2db_buff: 3, db2k_buff: 3
unsigned k2ac_buff: 3, ac2k_buff: 3
unsigned req_buff: 3



// LTL claims
// ltl { [] conf }
// ltl Confidentiality { [] (enc_1 != u_enc_1 && enc_2 != u_enc_2 && enc_1 > 4 && enc_2 > 4 && (u_enc_1 == 14||u_enc_1 < 5) && (u_enc_2 == 14 || u_enc_2 < 5)) }
// bool ps_confidentiality, ps_integrity, ps_authentication, ps_authorization, ps_consistency, pl_confidentiality, pl_integrity, pl_authentication, pl_authorization, pl_consistency
// TRY TO VIOLATE LTL
init {
    atomic {

        timer = 0
          
        run Tenant(1)
        run Tenant(2)
        run Database()
        run Keystore()
        run AccessControl()
    }
}


proctype Tenant(unsigned id : 2)
{
    mtype msg = deny
    unsigned temp_key : 3, recrypt_idx : 4, assigned_KEK : 3, dek_id : 2 = id
    bit grant
    E_Key temp_e_key, encrypted_DEK, received_e_DEK
    bool sent2tenant
    
    Select_id: 
       
        if
        ::  id == 1 -> goto ID_1
        ::  id == 2 -> goto ID_2
        fi

    ID_1:
        // printf("ID1\n")
        start = true
        atomic {
            if
            ::  k2t1_buff > 0 -> k2t1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version -> k2t1_buff-- -> 
                if
                ::  msg == ass_KEK -> goto Assign_KEK_receive
                ::  msg == d_DEK -> goto Decrypt_receive
                ::  msg == e_DEK -> goto Encrypt_receive
                ::  else -> skip
                fi
            ::  else -> skip
            fi

            if
            ::  t12k_buff < T2K_MAX -> 
                do
                ::  t12k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                ::  t12k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.enc_version, encrypted_DEK.ref_version, id -> break
                ::  t12k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                od
 
                t12k_buff++
                
            ::  else -> skip
            fi

            goto ID_1
        }
        

    ID_2:

        // printf("ID2\n")
        start = true
        atomic {

            if
            ::  k2t2_buff > 0 -> k2t2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version -> k2t2_buff-- -> 
                if
                ::  msg == ass_KEK -> goto Assign_KEK_receive
                ::  msg == d_DEK -> goto Decrypt_receive
                ::  msg == e_DEK -> goto Encrypt_receive
                ::  else -> skip
                fi
            ::  else -> skip
            fi

            if
            ::  t22k_buff < T2K_MAX -> 
                do
                ::  t22k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                ::  t22k!d_DEK, EMPTY_PASS, encrypted_DEK.ref_id, encrypted_DEK.id, encrypted_DEK.enc_version, encrypted_DEK.ref_version, id, grant -> break
                ::  t22k!e_DEK, dek_id, assigned_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                od

                t22k_buff++

            ::  else -> skip
            fi

            goto ID_2
        }

    
    Assign_KEK_receive:

        atomic {

            assigned_KEK = temp_e_key.ref_id
            
            goto Cleanup
        }
    
    Decrypt_receive:

        atomic {
            assert(dek_id == temp_key)
            
            goto Cleanup
        }
    
    Encrypt_receive:

        atomic {
            
            // if
            // ::  encrypted_DEK.id == 0 -> skip
            // ::  encrypted_DEK.id != 0 && temp_e_key.ref_version < encrypted_DEK.ref_version -> //TODO
            //     if
            //     ::  temp_e_key.ref_id-ENC_DUMMY == 1 -> assert(curr_rotation_1) -> curr_rotation_1 = false
            //     ::  else -> assert(curr_rotation_2) -> curr_rotation_2 = false
            //     fi
            // ::  else -> assert(temp_e_key.ref_version >= encrypted_DEK.ref_version)
            // fi
            // printf("NUMBER %d SAYS HELLO\n", id)
            if
            ::  encrypted_DEK.id != 0 -> 
                    // assert( temp_e_key.enc_version != encrypted_DEK.enc_version ) //TODO
                    assert(temp_e_key.id-ENC_DUMMY == dek_id)
                    assert(temp_e_key.ref_id == assigned_KEK)
            ::  else -> skip
            fi
            
            encrypted_DEK.id = temp_e_key.id
            encrypted_DEK.enc_version = temp_e_key.enc_version
            encrypted_DEK.ref_id = temp_e_key.ref_id
            encrypted_DEK.ref_version = temp_e_key.ref_version

            goto Cleanup
        }
    
    Cleanup:

        atomic {

            msg = deny
            temp_key = 0
            temp_e_key.ref_id = 0
            temp_e_key.id = 0
            temp_e_key.enc_version = 0
            temp_e_key.ref_version = 0

            if
            ::  id == 1 -> goto ID_1
            ::  else -> goto ID_2
            fi
        }
}

proctype Keystore()
{
    mtype msg = deny, enc_msg
    unsigned dek_id : 3, kek_id : 3, kek_ref : 3, i : 3, tenant_id : 3, id : 2, version: 1, is_case : 2, select_case : 3

    bit grant
    bool valid, cache_cleared

    KEK temp_key
    E_Key temp_e_key

    KEK v_KEKs[NUM_KEKS]

    Select_state:

        // printf("KEYSTORE\n")
        //FROM AC
        

        // cache_cleared = !cache_cleared
        start = true
        atomic {

            grant = 0
            
            if
            ::  ac2k_buff > 0 -> ac2k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant -> ac2k_buff-- ->  
                
                select_case = 2

                if
                ::  kek_ref > 5 -> kek_id = kek_ref-ENC_DUMMY
                ::  else -> kek_id = 0
                fi

                if
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  msg == ass_KEK2 -> select_case = 4 -> goto Assign_KEK
                // ::  msg == d_DEK ->  k2db_buff < K2DB_MAX -> k2db!d_DEK, dek_id, kek_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant -> k2db_buff++
                ::  msg == d_DEK -> goto Decrypt  
                ::  msg == e_DEK -> goto Encrypt 
                ::  msg == deny -> goto Deny_request
                ::  else -> skip
                fi
            
        //FROM DB
            ::  db2k_buff > 0 -> db2k?msg, dek_id, kek_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant, version -> db2k_buff-- ->  
                
                select_case = 3

                if
                ::  tenant_id == 1 ->
                    if
                    ::  msg == ass_KEK -> goto Assign_KEK
                    // ::  msg == d_DEK -> k2t1_buff < K2T_MAX -> k2t1!d_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version -> req_buff-- -> k2t1_buff++
                    ::  msg == d_DEK -> goto Decrypt  
                    ::  msg == e_DEK -> goto Encrypt 
                    ::  msg == deny -> goto Deny_request
                    ::  else -> skip
                    fi
                ::  else -> 
                    if
                    ::  msg == ass_KEK -> goto Assign_KEK
                    // ::  msg == d_DEK -> k2t2_buff < K2T_MAX -> k2t2!d_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version -> req_buff-- -> k2t2_buff++
                    ::  msg == d_DEK -> goto Decrypt  
                    ::  msg == e_DEK -> goto Encrypt 
                    ::  msg == deny -> goto Deny_request
                    ::  else -> skip
                    fi
                fi
            ::  else -> skip
            fi
            
            //FROM TENANT
            if
            ::  req_buff < REQ_MAX && t12k_buff > 0 -> t12k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id -> req_buff++ -> t12k_buff-- ->                  
                
                select_case = 1

                if
                ::  msg == ass_KEK -> goto Assign_KEK
                // ::  msg == d_DEK -> k2ac_buff < K2AC_MAX -> k2ac!d_DEK, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant -> k2ac_buff++
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == e_DEK -> goto Encrypt
                ::  else -> assert(false)
                fi
            ::  req_buff < REQ_MAX && t22k_buff > 0 -> t22k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant -> req_buff++ -> t22k_buff-- ->  
                
                select_case = 1
                
                if
                ::  kek_ref > 5 -> kek_id = kek_ref-ENC_DUMMY
                ::  else -> kek_id = 0 
                fi

                if
                ::  msg == ass_KEK ->  goto Assign_KEK
                // ::  msg == d_DEK -> k2ac_buff < K2AC_MAX -> k2ac!d_DEK, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant -> k2ac_buff++
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == e_DEK -> goto Encrypt
                ::  else -> assert(false)
                fi
            ::  else -> skip
            fi
            
            goto Select_state
        }
        
    Assign_KEK:

        atomic {
            
            assert(msg == ass_KEK && select_case == 3 || msg == ass_KEK && select_case == 2 || msg == ass_KEK && select_case == 1 || msg == ass_KEK2 && select_case == 4)
            
            if  // From Tenant to Access Control
            ::  select_case == 1 -> 
                    k2ac_buff < K2AC_MAX 
                    k2ac!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, grant 
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 
                // if
                // ::  !SAME_KEK_ASSIGNED -> kek_id = tenant_id  
                // ::  else -> kek_id = 1 
                // fi

                assert(kek_id > 0)

                if // Already in memory so skip Database
                ::  (v_KEKs[kek_id-1].id == kek_id && !cache_cleared) || (v_KEKs[kek_id-1].id == kek_id && v_KEKs[kek_id-1].version != temp_e_key.ref_version) ->
                        select_case = 5 
                ::  else -> 
                        k2db_buff < K2DB_MAX  
                        k2db!ass_KEK, EMPTY_PASS, kek_id, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, grant 
                        k2db_buff++
                fi
                
                // From Database to Access Control
            ::  select_case == 3 -> 
                    select_case = 5
                    v_KEKs[kek_id-1].id = kek_id
                    v_KEKs[kek_id-1].version = version
                    assert(kek_id > 0)

                // From Access Control to Tenant
            ::  select_case == 4 -> 
                if
                ::  tenant_id == 1 -> k2t1_buff < K2T_MAX 
                    k2t1!ass_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
                    req_buff-- -> k2t1_buff++
                ::  else -> k2t2_buff < K2T_MAX
                    k2t2!ass_KEK, EMPTY_PASS, kek_ref, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
                    req_buff-- -> k2t2_buff++
                fi
            ::  else -> assert(false)
            fi

            if  // DB -> KS -> AC or Database skip from case 2 AC -> KS -> AC
            ::  select_case == 5 ->
                    k2ac_buff < K2AC_MAX 
                    k2ac!ass_KEK2, EMPTY_PASS, kek_id+ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, grant  
                    k2ac_buff++
            ::  else -> skip
            fi

            goto Cleanup
        }

    Decrypt:

        atomic {

            if  // From Tenant to Access Control
            ::  select_case == 1 -> k2ac_buff < K2AC_MAX -> 
                    
                    k2ac!d_DEK, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant  
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> 
                if // Already in memory so skip Database
                ::  (v_KEKs[kek_id-1].id == kek_id && !cache_cleared) || (v_KEKs[kek_id-1].id == kek_id && v_KEKs[kek_id-1].version != temp_e_key.ref_version) ->
                        select_case = 4 
                ::  else ->
                        k2db_buff < K2DB_MAX -> 
                        k2db!d_DEK, dek_id, kek_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant 
                        k2db_buff++
                fi
                
                // From Database to Tenant
            ::  select_case == 3 -> 
                    select_case = 4
                    v_KEKs[id-1].id = id
                    v_KEKs[id-1].version = version
            ::  else -> assert(false)
            fi

            if  // DB -> KS -> T or Database skip from case 2 AC -> KS -> T
            ::  select_case == 4 ->
                if
                ::  tenant_id == 1 -> k2t1_buff < K2T_MAX 
                    k2t1!d_DEK, temp_e_key.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
                    req_buff-- -> k2t1_buff++
                ::  else -> k2t2_buff < K2T_MAX
                    k2t2!d_DEK, temp_e_key.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
                    req_buff-- -> k2t2_buff++
                fi
            ::  else -> skip
            fi

            goto Cleanup
        }

    Encrypt:

        atomic {
            
            if  // From Tenant to Access Control
            ::  select_case == 1 -> k2ac_buff < K2AC_MAX ->  
                    
                    k2ac!e_DEK, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant  
                    k2ac_buff++
                
                // From Access Control to Database
            ::  select_case == 2 -> k2db_buff < K2DB_MAX ->

                    k2db!e_DEK, dek_id, kek_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant 
                    k2db_buff++
                
                // From Database to Tenant
            ::  select_case == 3 -> 
                    v_KEKs[kek_id-1].id = kek_id
                    v_KEKs[kek_id-1].version = version

                    temp_e_key.id = dek_id+ENC_DUMMY
                    temp_e_key.enc_version = !temp_e_key.enc_version // PUT IN A GLOBAL HERE THAT ENCRYPYTS DIFFERENT BEFORE EACH SEND
                    temp_e_key.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
                    temp_e_key.ref_version = v_KEKs[kek_id-1].version

                    if
                    ::  tenant_id == 1 -> k2t1_buff < K2T_MAX ->

                            k2t1!e_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version 
                            req_buff-- 
                            k2t1_buff++ 

                    ::  else -> k2t2_buff < K2T_MAX ->

                            k2t2!e_DEK, dek_id, kek_id+ENC_DUMMY, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version 
                            req_buff-- 
                            k2t2_buff++ 

                    fi
            ::  else -> assert(false)
            fi
            

            goto Cleanup
        }

    Deny_request:

        atomic {

            if
            ::  tenant_id == 1 -> 
                     k2t1_buff < K2T_MAX 
                     k2t1!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
                     k2t1_buff++
                     req_buff--
            ::  else -> 
                     k2t2_buff < K2T_MAX 
                     k2t2!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
                     k2t2_buff++
                     req_buff--
            fi
            select_case = 0

            msg = deny
            goto Cleanup
        } 

    Cleanup:

        atomic {
            
            select_case = 0
            msg = deny
            dek_id = 0
            kek_id = 0
            kek_ref = 0
            i = 0
            tenant_id = 0
            id = 0
            version= 0
            is_case = 0
            select_case = 0
            temp_e_key.id = 0
            temp_e_key.enc_version = 0
            temp_e_key.ref_id = 0
            temp_e_key.ref_version = 0
            temp_key.version = 0
            temp_key.id = 0

            goto Select_state
        }       
}


proctype Database() {

    mtype msg = deny
    unsigned kek_id : 3, i : 3, tenant_id : 3, dek_id : 2, version : 1
    bit grant
    KEK p_KEKs[NUM_KEKS]
    E_Key temp_e_key
    bool accessed

    atomic {
        i = 0
        for (i : 0 .. NUM_KEKS-1) {
            p_KEKs[i].id = i+1
        }
        i = 0
    }
    
    Select_state:
        
        // curr_rotation = !curr_rotation
        start = true
        atomic {

            p_KEKs[1].version = curr_rotation
            p_KEKs[0].version = curr_rotation

            k2db_buff > 0 
            k2db?msg, dek_id, kek_id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant 
            k2db_buff--
            
            assert(kek_id>0)

            do
            ::  (msg == e_DEK || msg == d_DEK || msg == ass_KEK || msg == re_DEK) -> goto Access_KEK
            ::  msg == rot_KEK -> goto Rotate_KEK
            od
            
        }

    Access_KEK:

        atomic {

            i = 0
            for (i : 0 .. NUM_KEKS-1) {
                if 
                ::  p_KEKs[i].id == kek_id ->
                    
                    db2k_buff < DB2K_MAX 
                    db2k!msg, dek_id, p_KEKs[i].id, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant, p_KEKs[i].version 
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
            db2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, EMPTY_PASS, EMPTY_PASS
            db2k_buff++

            goto Cleanup
        }

    Cleanup:

        atomic {

            accessed = false
            i = 0
            msg = deny
            dek_id = 0
            kek_id = 0
            temp_e_key.id = 0
            temp_e_key.enc_version = 0
            temp_e_key.ref_version = 0
            tenant_id = 0
            grant = 0

            goto Select_state
        }
}

proctype AccessControl()
{
    mtype msg = deny
    unsigned kek_ref : 3, tenant_id : 3, i : 3, num_assigned : 3, dek_id : 2, assigned_1 : 3, assigned_2 : 3
    bit grant
    E_Key temp_e_key
    
    
    Select_state:
        
        start = true
        // printf("ACCESS CONTROL\n")
        atomic {

            k2ac_buff > 0 
            k2ac?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant
            k2ac_buff--
            
            if
            ::  msg == ass_KEK -> goto Assign_KEK_authorize
            ::  msg == ass_KEK2 -> goto Assign_KEK2_authorize
            ::  msg == d_DEK || msg == e_DEK || msg == re_DEK -> goto Authorize
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
            ac2k!ass_KEK, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant  
            ac2k_buff++

            goto Cleanup
        }        

    Assign_KEK2_authorize:

        // Newly generated key assigned
        atomic {

            assert(kek_ref > 5)

            if 
            ::  tenant_id == 1 -> assigned_1 = kek_ref 
            ::  tenant_id == 2 -> assigned_2 = kek_ref 
            fi
            
            ac2k_buff < AC2K_MAX
            ac2k!ass_KEK2, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant  
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
                    ::  grant == VALID_GRANT && assigned_1 == kek_ref -> skip
                    ::  else -> goto Deny_request
                    fi
            ::  else -> skip
            fi

            ac2k_buff < AC2K_MAX
            ac2k!msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.enc_version, temp_e_key.ref_version, tenant_id, grant  
            ac2k_buff++
            
            goto Cleanup
        }
    
    Deny_request:
        
        atomic {
            
            ac2k_buff < AC2K_MAX 
            ac2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, tenant_id, EMPTY_PASS
            ac2k_buff++


            goto Cleanup
        }
    
    Cleanup:

        atomic {

            num_assigned = 0
            i = 0
            msg = deny
            dek_id = 0
            kek_ref = 0
            temp_e_key.id = 0
            temp_e_key.enc_version = 0
            temp_e_key.ref_version = 0
            tenant_id = 0
            grant = 0

            goto Select_state
        }
}
