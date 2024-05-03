#define NUM_DEKS 2
#define NUM_KEKS 4
#define NUM_TENANTS 2
#define T2K_MAX 1
#define K2T_MAX 0
#define K2AC_MAX 0
#define AC2K_MAX 0
#define K2DB_MAX 1
#define DB2K_MAX 0
#define DB2T_MAX 2
#define T_SEND_MAX 2
#define ASS_MAX 2
#define SAME_KEK_MAX 1
#define GRANT 1
#define VALID_GRANT 1
#define ENC_DUMMY 5
#define EMPTY_PASS 0
#define ROT_KEK_1 15000
#define ROT_KEK_2 18000
#define ROT_KEK_3 25000
#define ROT_KEK_4 24000
#define CACHE_CLEAR 4000
#define SAME_KEK_ASSIGNED false

typedef KEK { /* Unencrypted */
    unsigned id : 3
    int version
    unsigned assigned_to : 2
}

typedef E_Key { /* Encrypted */
    unsigned id : 4
    int version 
    unsigned ref_id : 4
    int ref_version
}

mtype = { e_DEK, d_DEK, re_DEK, ass_KEK, rot_KEK, send_e_DEK, deny, ack }

// t: Tenant
// k: Keystore
// ac: Access Control
// db: Database

// { message type, DEK_ID, KEK_ID, E_KEY-ID, E_KEY-VERSION, E_KEY-REF_V, TENANT_ID, (GRANT) }
// KEK_ID shares index to E_KEY-REF-ID in channels to reduce channel width
chan t12k = [T2K_MAX] of { mtype, byte, byte, byte, int, int, byte }	// Tenant 1 -> Keystore
chan t22k = [T2K_MAX] of { mtype, byte, byte, byte, int, int, byte, byte }	// Tenant 2 -> Keystore, added byte field for grant token from Tenant 1
chan k2t1 = [K2T_MAX] of { mtype, byte, byte, byte, int, int }	// Keystore -> Tenant 1
chan k2t2 = [K2T_MAX] of { mtype, byte, byte, byte, int, int }	// Keystore -> Tenant 2

// { message type, E_KEY-ID, E_KEY-VERSION, E_KEY-REF_ID, E_KEY-REF_V, GRANT }
chan t12t2 = [T_SEND_MAX] of { mtype, byte, byte, byte, int, byte }	// Tenant 1 -> Tenant 2

//                  { message type, KEK_ID, TENANT_ID, GRANT}
chan k2ac = [K2AC_MAX] of { mtype, byte, byte, byte }	// Keystore -> Access Control
chan ac2k = [AC2K_MAX] of { mtype }	// Access Control -> Keystore

//                  { message type, KEK_ID, TENANT_ID}
chan k2db = [K2DB_MAX] of { mtype, byte, byte }	// Keystore -> Database
//              { message type, KEK_ID, KEK-VERSION, KEK-ASS_TO }
chan db2k = [DB2K_MAX] of { mtype, byte, int, byte }	// Database -> Keystore

// This  channel emulates an external component notifying 
// the tenant when a rotation has taken place 
//                  { message type, KEK_ID }
chan db2t1 = [DB2T_MAX] of { mtype, byte }  // Database -> Tenant 1
chan db2t2 = [DB2T_MAX] of { mtype, byte }  // Database -> Tenant 2


int timer
bool clear_cache
// LTL variables
unsigned enc_1 : 4, u_enc_1 : 3, enc_2 : 4, u_enc_2 : 3


// LTL claims
// ltl { [] conf }
//ltl Confidentiality { [] (enc_1 != u_enc_1 && enc_2 != u_enc_2 && enc_1 > 100 && enc_2 > 100 && u_enc_1 < 5 && u_enc_2 < 5) }

init {

    atomic {
        enc_1 = 15
        u_enc_1 = 0
        enc_2 = 15
        u_enc_2 = 0
        timer = 0
        clear_cache = false
          
        unsigned i : 2 

        for (i : 1 .. NUM_TENANTS) {
            run Tenant(i)
        }
        run Database()
        run Keystore()
        run AccessControl()
        
    }
}

proctype Tenant(unsigned id : 2)
{
    mtype msg
    unsigned temp_key : 3, i : 3, ass_idx : 2, recrypt_idx : 4
    bit grant
    byte assigned_KEKs[NUM_KEKS/2], DEKs[NUM_DEKS]
    E_Key temp_e_key
    E_Key encrypted_DEKs[NUM_DEKS], received_e_DEKs[NUM_DEKS]
    bool sent_1, sent_2
    
    atomic {
        for (i : 0 .. NUM_DEKS-1) {
            DEKs[i] = i + 1 + NUM_DEKS*(id-1)
        }
    }

    Select_state: 
        
        atomic{ 
            if
            ::  SAME_KEK_ASSIGNED -> assert(assigned_KEKs[1] == 0)
            ::  else -> skip
            fi
        // Receive rotation update ping
            if
            ::  id == 1 ->
                if
                ::  db2t1?[msg, recrypt_idx] -> db2t1?msg, recrypt_idx ->
                        goto Recrypt
                ::  else -> skip
                fi
            ::  else -> 
                if
                ::  db2t2?[msg, recrypt_idx] -> db2t2?msg, recrypt_idx ->
                        goto Recrypt
                ::  else -> skip
                fi
            fi
        // Receive from tenant 1 
            if
            ::  id == 2 -> 
                if
                ::  t12t2?[msg, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version, grant] ->
                        t12t2?msg, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version, grant  ->
                        assert(temp_e_key.id-ENC_DUMMY-1 < 2)
                        received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].id = temp_e_key.id
                        received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].version = temp_e_key.version
                        received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].ref_id = temp_e_key.ref_id
                        received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].ref_version = temp_e_key.ref_version
                ::  else -> skip
                fi
            ::  else -> skip
            fi
        }
        
        // Main selection loop
        do
        ::  if
            ::  id == 1 && !(sent_1 && sent_2) && (encrypted_DEKs[0].id != 0 || encrypted_DEKs[1].id != 0) -> 
                    goto Send_to_tenant  
            ::  else -> skip
            fi
        ::  goto Encrypt
        ::  goto Decrypt
        ::  goto Request_KEK
        od

    Encrypt:

        atomic {
            if
            ::  id == 1 ->
                do
                ::  t12k!e_DEK, DEKs[0], assigned_KEKs[0], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                ::  t12k!e_DEK, DEKs[0], assigned_KEKs[1], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                ::  t12k!e_DEK, DEKs[1], assigned_KEKs[0], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                ::  t12k!e_DEK, DEKs[1], assigned_KEKs[1], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id -> break
                od
            ::  else ->
                do
                ::  t22k!e_DEK, DEKs[0], assigned_KEKs[0], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                ::  t22k!e_DEK, DEKs[0], assigned_KEKs[1], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                ::  t22k!e_DEK, DEKs[1], assigned_KEKs[0], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                ::  t22k!e_DEK, DEKs[1], assigned_KEKs[1], EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id, grant -> break
                od
            fi
        }

        goto Receive
    
    Decrypt:
        
        atomic {
            if
            ::  id == 1 ->
                if
                ::  encrypted_DEKs[0].id != 0 -> 
                        t12k!d_DEK, EMPTY_PASS, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id
                ::  encrypted_DEKs[1].id != 0 -> 
                        t12k!d_DEK, EMPTY_PASS, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id
                ::  else -> goto Select_state 
                fi
            ::  else ->
                if
                ::  encrypted_DEKs[0].id != 0 -> 
                        t22k!d_DEK, EMPTY_PASS, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id, grant
                ::  encrypted_DEKs[1].id != 0 -> 
                        t22k!d_DEK, EMPTY_PASS, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id, grant
                ::  received_e_DEKs[0].id != 0 ->
                        t22k!d_DEK, EMPTY_PASS, received_e_DEKs[0].ref_id, received_e_DEKs[0].id, received_e_DEKs[0].version, received_e_DEKs[0].ref_version, id, grant
                ::  received_e_DEKs[1].id != 0 ->
                        t22k!d_DEK, EMPTY_PASS, received_e_DEKs[1].ref_id, received_e_DEKs[1].id, received_e_DEKs[1].version, received_e_DEKs[1].ref_version, id, grant
                ::  else -> goto Select_state 
                fi
            fi
        }

        goto Receive

    Recrypt:

        i = 0 
        for (i in encrypted_DEKs) {
            if 
            ::  encrypted_DEKs[i].ref_id == recrypt_idx -> 
                if  // Send and Receive
                ::  id == 1 -> 
                        t12k!re_DEK, EMPTY_PASS, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id
                        k2t1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                ::  else -> 
                        t22k!re_DEK, EMPTY_PASS, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id, grant
                        k2t2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                fi
                
                d_step {
                    if
                    ::  msg != deny -> 
                                assert(temp_e_key.version > encrypted_DEKs[i].version)
                                assert(temp_e_key.ref_version >= encrypted_DEKs[i].ref_version)
                                assert(encrypted_DEKs[i].id == temp_e_key.id)
                                assert(recrypt_idx == temp_e_key.ref_id)
                                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].id = temp_e_key.id
                                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].version = temp_e_key.version
                                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].ref_id = temp_e_key.ref_id
                                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].ref_version = temp_e_key.ref_version
                    ::  else -> skip
                    fi
                }
            ::  else -> skip
            fi
        }

        goto Select_state

    Request_KEK:
       
        atomic {
            if  
            ::  id == 1 -> t12k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id
            ::  else -> t22k!ass_KEK, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, id
            fi
        }

        goto Receive

    Send_to_tenant:

        atomic {
            if
            ::  encrypted_DEKs[0].id != 0 ->
                    t12t2!send_e_DEK, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].ref_version, GRANT
                    sent_1 = true
            ::  encrypted_DEKs[1].id != 0 ->
                    t12t2!send_e_DEK, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].ref_version, GRANT
                    sent_2 = true
            ::  else -> skip
            fi
        }

        goto Select_state

    Receive:

        if
        ::  id == 1 ->
                k2t1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
        ::  else ->
                k2t2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
        fi

        d_step {
            if
            ::  msg == ass_KEK -> 
                    assigned_KEKs[ass_idx] = temp_e_key.ref_id 
                    ass_idx++
            ::  msg == d_DEK ->
                    assert(temp_key == DEKs[(temp_key-1)%2] || (temp_key == received_e_DEKs[(temp_key-1)%2].id-ENC_DUMMY && grant == VALID_GRANT))
                    assert(DEKs[0] != received_e_DEKs[(temp_key-1)%2].id-ENC_DUMMY)
                    assert(DEKs[1] != received_e_DEKs[(temp_key-1)%2].id-ENC_DUMMY)
                    if
                    :: id == 1 -> 
                            enc_1 = encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].id
                            u_enc_1 = temp_key
                    ::  else -> 
                            enc_2 = encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].id
                            u_enc_2 = temp_key
                            enc_2 = received_e_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].id
                    fi
            ::  msg == deny -> skip
            ::  msg == e_DEK ->
                    assert(temp_e_key.version > encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].version)
                    if
                    :: id == 1 -> 
                            enc_1 = temp_e_key.id
                            u_enc_1 = DEKs[(temp_e_key.id-ENC_DUMMY-1)%2]
                    ::  else -> 
                            enc_2 = temp_e_key.id
                            u_enc_2 = DEKs[(temp_e_key.id-ENC_DUMMY-1)%2]
                    fi
                    encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].id = temp_e_key.id
                    encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].version = temp_e_key.version
                    encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].ref_id = temp_e_key.ref_id
                    encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].ref_version = temp_e_key.ref_version
            fi
            enc_1 = 15
            u_enc_1 = 0
            enc_2 = 15
            u_enc_2 = 0
        }
        
        goto Select_state
}

proctype Keystore()
{
    mtype msg, enc_msg
    int version
    unsigned dek_id : 3, kek_id : 3, kek_ref : 4, i : 3, tenant_id : 2, id : 3, is_case : 2, kek_idx : 3, assigned_to : 2 
    bit grant
    bool valid, received

    KEK temp_key
    E_Key temp_e_key

    KEK v_KEKs[NUM_KEKS]

    Select_state:

        atomic {
            if // Clear Cache
            ::  clear_cache -> 
                    i = 0
                    for (i in v_KEKs) {
                        v_KEKs[i].id = 0 
                        v_KEKs[i].version = 0
                        v_KEKs[i].assigned_to = 0
                    }
                clear_cache = false
            ::  else -> skip
            fi
        }

        goto Receive

    Receive:
        
        atomic {

            received = false

            if 
            ::  t12k?[msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id] ->
                    t12k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id  ->
                    received = true
                    if
                    ::  kek_ref > 0 -> kek_id = kek_ref-ENC_DUMMY
                    ::  else -> skip
                    fi
            ::  t22k?[msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id, grant] ->
                    t22k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id, grant  ->
                    received = true
                    if
                    ::  kek_ref > 0 -> kek_id = kek_ref-ENC_DUMMY
                    ::  else -> skip
                    fi
            ::  else -> skip
            fi
        }

        if
        ::  received ->
            if
            ::  msg == e_DEK || msg == re_DEK -> goto Encrypt
            ::  msg == d_DEK -> goto Decrypt
            ::  msg == ass_KEK -> goto Assign_KEK
            ::  else -> skip
            fi
        :: else -> skip
        fi
        
        goto Select_state

    Assign_KEK: 

        k2db!ass_KEK, kek_idx+1, tenant_id
        db2k?msg, id, version, assigned_to

        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi
        
        atomic {
            v_KEKs[kek_idx].id = id
            v_KEKs[kek_idx].version = version
            v_KEKs[kek_idx].assigned_to = assigned_to

            k2ac!msg, id, tenant_id, grant
        }
    
        ac2k?msg

        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        atomic {
            if
            ::  tenant_id == 1 -> k2t1!ass_KEK, EMPTY_PASS, v_KEKs[kek_idx].id+ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
            ::  else -> k2t2!ass_KEK, EMPTY_PASS, v_KEKs[kek_idx].id+ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
            fi

            if
            ::  !SAME_KEK_ASSIGNED -> kek_idx++
            ::  else -> skip
            fi
        }

        goto Select_state

    Decrypt:

        atomic {
            valid = true
        }

        k2ac!msg, kek_id, tenant_id, grant
        ac2k?msg 
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        d_step {
            if 
            ::  v_KEKs[kek_id-1].id == 0 -> is_case = 1
            ::  v_KEKs[kek_id-1].id == kek_id -> is_case = 2
            ::  else -> is_case = 0 -> valid = false
            fi
        }

        if 
        ::  is_case == 1 -> 
                k2db!d_DEK, kek_id, tenant_id
                db2k?msg, id, version, assigned_to

                d_step {
                    if
                    ::  msg != deny -> 
                            v_KEKs[id-1].id = id
                            v_KEKs[id-1].version = version
                        
                        if
                        ::  v_KEKs[kek_id-1].version < temp_e_key.ref_version -> valid = false 
                        ::  else -> skip
                        fi
                    ::  else -> valid = false 
                    fi
                }
        ::  is_case == 2
            if
            ::  v_KEKs[kek_id-1].version >= temp_e_key.ref_version -> 
                    skip
            ::  else -> 
                    k2db!d_DEK, kek_id, tenant_id
                    db2k?msg, id, version, assigned_to

                    d_step {
                        v_KEKs[id-1].version = id
                        v_KEKs[id-1].version = version

                        if
                        ::  v_KEKs[id-1].version < temp_e_key.ref_version -> valid = false 
                        ::  else -> skip
                        fi
                    }
            fi
        ::  else -> skip
        fi

        if
        ::  valid -> assert(v_KEKs[kek_id-1].version >= temp_e_key.ref_version)
        ::  else -> goto Deny_request
        fi

        atomic {
            if
            ::  tenant_id == 1 -> k2t1!d_DEK, temp_e_key.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
            ::  else -> k2t2!d_DEK, temp_e_key.id-ENC_DUMMY, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
            fi
        }

        goto Select_state

    Encrypt:

        atomic {
            if 
            ::  msg == re_DEK -> enc_msg = re_DEK
            ::  else -> enc_msg = e_DEK
            fi
        }

        k2ac!msg, kek_id, tenant_id, grant
        ac2k?msg

        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        k2db!e_DEK, kek_id, tenant_id
        db2k?msg, id, version, assigned_to

        if
        ::  msg != deny -> 
            d_step {
                v_KEKs[id-1].id = id
                v_KEKs[id-1].version = version
                v_KEKs[id-1].assigned_to = assigned_to
            }
        ::  else -> goto Deny_request
        fi
        
        assert(kek_id > 0 && kek_id <= NUM_KEKS)

        d_step {
            if 
            ::  enc_msg == re_DEK -> 
                    assert(temp_e_key.ref_version <= v_KEKs[kek_id-1].version && temp_e_key.ref_version > v_KEKs[kek_id-1].version-2)
            ::  else -> temp_e_key.id = dek_id+ENC_DUMMY
            fi
            temp_e_key.version = timer
            temp_e_key.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
            temp_e_key.ref_version = v_KEKs[kek_id-1].version
        }

        atomic {
            if
            ::  tenant_id == 1 -> k2t1!enc_msg, EMPTY_PASS, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version
            ::  else -> k2t2!enc_msg, EMPTY_PASS, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version
            fi
        }

        goto Select_state

    Deny_request:
        
        atomic {
            if
            ::  tenant_id == 1 -> k2t1!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
            ::  else -> k2t2!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS
            fi
        }

        goto Select_state
}

/**
    The Database contains a timer that acts as a clock sending signals to 
    tenants when rotation has been executed. Rotation is not time-sensitive 
    such that it is affected by distributed clock-sync issues, so it could 
    also be seen as a tenant quering a clock to see if the scheduled rotation 
    that could be part of the metadata in the KEK information available to 
    the tenant has taken place.  
 */
proctype Database() {

    mtype msg
    unsigned kek_id : 3, i : 3, tenant_id : 2
    KEK p_KEKs[NUM_KEKS]
    bool accessed

    atomic {
        for (i in p_KEKs) {
            p_KEKs[i].id = i+1
            p_KEKs[i].version = 1
        }
    }
    
    Main:

        atomic {
            timer++

            if  // Cache timer
            ::  timer%CACHE_CLEAR == 0 -> 
                    clear_cache = true
            ::  else -> skip
            fi

            if  // Rotation 1
            ::  timer%ROT_KEK_1 == 0 ->
                    p_KEKs[0].version++

                    if
                    ::  p_KEKs[0].assigned_to == 1 ->
                            db2t1!rot_KEK, p_KEKs[0].id+ENC_DUMMY
                    ::  p_KEKs[0].assigned_to == 2 ->
                            db2t2!rot_KEK, p_KEKs[0].id+ENC_DUMMY
                    ::  p_KEKs[0].assigned_to == 3 ->
                            db2t2!rot_KEK, p_KEKs[0].id+ENC_DUMMY
                            db2t1!rot_KEK, p_KEKs[0].id+ENC_DUMMY
                    ::  else -> skip
                    fi
            ::  else -> skip
            fi

            if  // Rotation 2
            ::  timer%ROT_KEK_2 == 0 ->
                    p_KEKs[1].version++

                    if
                    ::  p_KEKs[1].assigned_to == 1 ->
                            db2t1!rot_KEK, p_KEKs[1].id+ENC_DUMMY
                    ::  p_KEKs[1].assigned_to == 2 ->
                            db2t2!rot_KEK, p_KEKs[1].id+ENC_DUMMY
                    ::  p_KEKs[1].assigned_to == 3 ->
                            db2t2!rot_KEK, p_KEKs[1].id+ENC_DUMMY
                            db2t1!rot_KEK, p_KEKs[1].id+ENC_DUMMY
                    ::  else -> skip 
                    fi
            ::  else -> skip
            fi

            if  // Rotation 3
            ::  timer%ROT_KEK_3 == 0 ->
                    p_KEKs[2].version++

                    if
                    ::  p_KEKs[2].assigned_to == 1 ->
                            db2t1!rot_KEK, p_KEKs[2].id+ENC_DUMMY
                    ::  p_KEKs[2].assigned_to == 2 ->
                            db2t2!rot_KEK, p_KEKs[2].id+ENC_DUMMY
                    ::  p_KEKs[2].assigned_to == 3 ->
                            db2t2!rot_KEK, p_KEKs[2].id+ENC_DUMMY
                            db2t1!rot_KEK, p_KEKs[2].id+ENC_DUMMY
                    ::  else -> skip
                    fi
            ::  else -> skip
            fi

            if  // Rotation 4
            ::  timer%ROT_KEK_4 == 0 ->
                    p_KEKs[3].version++

                    if
                    ::  p_KEKs[3].assigned_to == 1 ->
                            db2t1!rot_KEK, p_KEKs[3].id+ENC_DUMMY
                    ::  p_KEKs[3].assigned_to == 2 ->
                            db2t2!rot_KEK, p_KEKs[3].id+ENC_DUMMY
                    ::  p_KEKs[3].assigned_to == 3 ->
                            db2t2!rot_KEK, p_KEKs[3].id+ENC_DUMMY
                            db2t1!rot_KEK, p_KEKs[3].id+ENC_DUMMY
                    ::  else -> skip
                    fi
            ::  else -> skip
            fi
        }

        if 
        ::  atomic{ k2db?[msg, kek_id, tenant_id] -> k2db?msg, kek_id, tenant_id } ->
            if
            ::  (msg == e_DEK || msg == d_DEK || msg == ass_KEK || msg == re_DEK) -> goto Access_KEK
            ::  else -> goto Deny_request
            fi
        ::  else -> skip
        fi

        goto Main

    Access_KEK:

        atomic {
            accessed = false
            i = 0
            for (i in p_KEKs) {
                if 
                ::  p_KEKs[i].id == kek_id -> 
                        
                        timer++

                        if
                        ::  msg == ass_KEK -> 
                            if
                            ::  p_KEKs[i].assigned_to > 0 -> p_KEKs[i].assigned_to = 3
                            ::  else -> p_KEKs[i].assigned_to = tenant_id
                            fi
                        ::  else -> skip
                        fi
                        
                        db2k!msg, p_KEKs[i].id, p_KEKs[i].version, p_KEKs[i].assigned_to
                        accessed = true
                ::  else -> skip
                fi
            }
        }
        
        if
        ::  accessed -> goto Main
        ::  else -> goto Deny_request
        fi

    Deny_request:
        
        atomic { db2k!deny, EMPTY_PASS, EMPTY_PASS, EMPTY_PASS }

        goto Main

}

/*
    ## Access Control Info ##

    tenant_x_kek - Relations between tenants and KEKs

    0 - No relation
    1 - KEK relation exists

    Indexation is a 2d array inside a single array

*/

proctype AccessControl()
{
    mtype msg
    unsigned kek_id : 3, tenant_id : 2, idx : 4, i : 3, num_assigned : 3
    bit grant
    bool authorized
    byte tnt_x_kek[NUM_TENANTS*NUM_KEKS]
    
    Select_state:

        k2ac?msg, kek_id, tenant_id, grant

        if
        ::  msg == ass_KEK -> goto Assign_KEK
        ::  msg == d_DEK || msg == e_DEK || msg == re_DEK -> goto Authorize
        ::  else -> goto Deny_request
        fi

        goto Select_state
    
    Assign_KEK:
        
        atomic {
            num_assigned = 0
            i = 0
            authorized = true
            do
            ::  i < NUM_KEKS -> i++
                if
                ::  tnt_x_kek[(tenant_id-1)*NUM_KEKS+i-1] > 0 -> num_assigned++
                ::  else -> skip
                fi

                if
                ::  num_assigned >= ASS_MAX -> authorized = false -> break
                ::  SAME_KEK_ASSIGNED && num_assigned >= SAME_KEK_MAX -> authorized = false -> break
                ::  else -> skip
                fi
            ::  else -> break
            od
            num_assigned = 0
            i = 0
        }
        
        if
        ::  !authorized -> goto Deny_request
        ::  else -> skip
        fi

        d_step {
            idx = (tenant_id - 1) * NUM_KEKS + (kek_id - 1) 

            if
            ::  tnt_x_kek[idx] > 1 -> authorized = false
            ::  else -> tnt_x_kek[idx] = 1 
            fi
            idx = 0
        }

        if
        ::  !authorized -> goto Deny_request
        ::  else -> skip
        fi

        goto Ack_request

    Authorize:

        atomic {
            if
            ::  kek_id == 0 -> authorized = false 
            ::  else -> skip
            fi

            if 
            :: authorized -> 
                idx = (tenant_id - 1) * NUM_KEKS + (kek_id - 1)
                
                if
                ::  idx >= 0 && idx < NUM_TENANTS*NUM_KEKS ->  
                    if
                    ::  tnt_x_kek[idx] < 1 ->
                        if
                        ::  grant == VALID_GRANT ->
                            idx = kek_id - 1
                            if
                            ::  tnt_x_kek[idx] < 1 -> authorized = false
                            ::  else -> skip
                            fi
                        ::  else -> authorized = false
                        fi
                    ::  else -> skip
                    fi
                ::  else -> authorized = false
                fi
            ::  else -> skip
            fi

            idx = 0
        }

        if
        ::  !authorized -> goto Deny_request
        ::  else -> skip
        fi

        goto Ack_request

    Ack_request:

        atomic { ac2k!ack }

        goto Select_state
    
    Deny_request:

        atomic { ac2k!deny }

        goto Select_state

}
