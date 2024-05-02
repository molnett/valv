#define NUM_DEKS 2
#define NUM_KEKS 4
#define NUM_TENANTS 2
#define T2K_MAX 3
#define K2T_MAX 0
#define K2AC_MAX 0
#define AC2K_MAX 0
#define K2DB_MAX 3
#define DB2K_MAX 0
#define DB2T_MAX 5
#define T_SEND_MAX 2
#define ASS_MAX 2
#define SAME_KEK_MAX 1
#define GRANT 123
#define VALID_GRANT 123
#define ENC_DUMMY 100
#define ROT_KEK_1 15000
#define ROT_KEK_2 18000
#define ROT_KEK_3 25000
#define ROT_KEK_4 24000
#define CACHE_CLEAR 4000
#define SAME_KEK_ASSIGNED false

typedef Key { /* Unencrypted */
    int id
    int version
    int assigned_to
}

typedef E_Key { /* Encrypted */
    int id
    int version 
    int ref_id
    int ref_version
}

mtype = { e_DEK, d_DEK, re_DEK, ass_KEK, rot_KEK, send_e_DEK, deny, ack }

// u: Tenant
// k: Keystore
// ac: Access Control

// { message type, DEK_ID, KEK_ID, E_KEY-ID, E_KEY-VERSION, E_KEY-REF-V, TENANT_ID, (GRANT) }
// KEK_ID shares index to E_KEY-REF-ID in channels to reduce channel width
chan t12k = [T2K_MAX] of { mtype, int, int, int, int, int, int }	// Tenant 1 -> Keystore
chan t22k = [T2K_MAX] of { mtype, int, int, int, int, int, int, int }	// Tenant 2 -> Keystore, added int field for grant token from Tenant 1
chan k2t1 = [K2T_MAX] of { mtype, int, int, int, int, int }	// Keystore -> Tenant 1
chan k2t2 = [K2T_MAX] of { mtype, int, int, int, int, int }	// Keystore -> Tenant 2

// { message type, E_KEY-ID, E_KEY-VERSION, E_KEY-REF_ID, E_KEY-REF-V, GRANT }
chan t12t2 = [T_SEND_MAX] of { mtype, int, int, int, int, int }	// Tenant 1 -> Tenant 2

//                  { message type, KEK_ID, TENANT_ID, GRANT}
chan k2ac = [K2AC_MAX] of { mtype, int, int, int }	// Keystore -> Access Control
chan ac2k = [AC2K_MAX] of { mtype }	// Access Control -> Keystore

//                  { message type, KEK_ID, TENANT_ID}
chan k2db = [K2DB_MAX] of { mtype, int, int }	// Keystore -> Database
//              { message type, KEK_ID, KEK_VERSION, KEK_ASS-TO }
chan db2k = [DB2K_MAX] of { mtype, int, int, int }	// Database -> Keystore

// This  channel emulates an external component notifying 
// the tenant when a rotation has taken place 
//                  { message type, KEK_ID }
chan db2t1 = [DB2T_MAX] of { mtype, int }  // Database -> Tenant 1
chan db2t2 = [DB2T_MAX] of { mtype, int }  // Database -> Tenant 2


int timer
bool clear_cache

init {

    timer = 0
    clear_cache = false

    atomic {

          
        int i

        for (i : 1 .. NUM_TENANTS) {
            run Tenant(i)
        }
        run Database()
        run Keystore()
        run AccessControl()
        
    }
}

proctype Tenant(int id)
{
    mtype msg
    int temp_key, i, ass_idx, recrypt_idx, grant
    int assigned_KEKs[NUM_KEKS/2], DEKs[NUM_DEKS]
    E_Key temp_e_key
    E_Key encrypted_DEKs[NUM_DEKS], received_e_DEKs[NUM_DEKS]
    bool sent_1, sent_2

    for (i : 0 .. NUM_DEKS-1) {
        DEKs[i] = i + 1 + NUM_DEKS*(id-1)
    }

    Select_state: 
        
        if
        ::  SAME_KEK_ASSIGNED -> assert(assigned_KEKs[1] == 0)
        ::  else -> skip
        fi
        // Receive rotation update ping
        if
        ::  id == 1 ->
            if
            ::  atomic{ db2t1?[msg, recrypt_idx] -> db2t1?msg, recrypt_idx } ->
                    goto Recrypt
            ::  else -> skip
            fi
        ::  else -> 
            if
            ::  atomic{ db2t2?[msg, recrypt_idx] -> db2t2?msg, recrypt_idx } ->
                    goto Recrypt
            ::  else -> skip
            fi
        fi


        // Receive from tenant 1 
        if
        ::  id == 2 -> 
            if
            ::  atomic{ t12t2?[msg, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version, grant] ->
                    t12t2?msg, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version, grant } ->
                    assert(temp_e_key.id-ENC_DUMMY-1 < 2)
                    received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].id = temp_e_key.id
                    received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].version = temp_e_key.version
                    received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].ref_id = temp_e_key.ref_id
                    received_e_DEKs[temp_e_key.id-ENC_DUMMY-1].ref_version = temp_e_key.ref_version
            ::  else -> skip
            fi
        ::  else -> skip
        fi
        
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

        if
        ::  id == 1 ->
            do
            ::  t12k!e_DEK, DEKs[0], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  t12k!e_DEK, DEKs[0], assigned_KEKs[1], -1, -1, -1, id -> break
            ::  t12k!e_DEK, DEKs[1], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  t12k!e_DEK, DEKs[1], assigned_KEKs[1], -1, -1, -1, id -> break
            od
        ::  else ->
            do
            ::  t22k!e_DEK, DEKs[0], assigned_KEKs[0], -1, -1, -1, id, grant -> break
            ::  t22k!e_DEK, DEKs[0], assigned_KEKs[1], -1, -1, -1, id, grant -> break
            ::  t22k!e_DEK, DEKs[1], assigned_KEKs[0], -1, -1, -1, id, grant -> break
            ::  t22k!e_DEK, DEKs[1], assigned_KEKs[1], -1, -1, -1, id, grant -> break
            od
        fi

        goto Receive
    
    Decrypt:
        
        if
        ::  id == 1 ->
            if
            ::  encrypted_DEKs[0].id != 0 -> 
                    t12k!d_DEK, -1, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id
            ::  encrypted_DEKs[1].id != 0 -> 
                    t12k!d_DEK, -1, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id
            ::  else -> goto Select_state 
            fi
        ::  else ->
            if
            ::  encrypted_DEKs[0].id != 0 -> 
                    t22k!d_DEK, -1, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id, grant
            ::  encrypted_DEKs[1].id != 0 -> 
                    t22k!d_DEK, -1, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id, grant
            ::  received_e_DEKs[0].id != 0 ->
                    t22k!d_DEK, -1, received_e_DEKs[0].ref_id, received_e_DEKs[0].id, received_e_DEKs[0].version, received_e_DEKs[0].ref_version, id, grant
            ::  received_e_DEKs[1].id != 0 ->
                    t22k!d_DEK, -1, received_e_DEKs[1].ref_id, received_e_DEKs[1].id, received_e_DEKs[1].version, received_e_DEKs[1].ref_version, id, grant
            ::  else -> goto Select_state 
            fi
        fi

        goto Receive

    Recrypt:

        i = 0;
        for (i in encrypted_DEKs) {
            if 
            ::  encrypted_DEKs[i].ref_id == recrypt_idx -> 
                if  // Send and Receive
                ::  id == 1 -> 
                        t12k!re_DEK, -1, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id
                        k2t1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                ::  else -> 
                        t22k!re_DEK, -1, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id, grant
                        k2t2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                fi
                
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
            ::  else -> skip
            fi
        }

        goto Select_state

    Request_KEK:
       
        if  
        ::  id == 1 -> t12k!ass_KEK, -1, -1, -1, -1, -1, id
        ::  else -> t22k!ass_KEK, -1, -1, -1, -1, -1, id
        fi

        goto Receive

    Send_to_tenant:

        if
        ::  encrypted_DEKs[0].id != 0 ->
                t12t2!send_e_DEK, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].ref_version, GRANT
                sent_1 = true
        ::  encrypted_DEKs[1].id != 0 ->
                t12t2!send_e_DEK, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].ref_version, GRANT
                sent_2 = true
        ::  else -> skip
        fi

        goto Select_state

    Receive:

        if
        ::  id == 1 ->
                k2t1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
        ::  else ->
                k2t2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
        fi
        
        if
        ::  msg == ass_KEK -> 
                // KEK.id is stored in temp_e_key.ref_id to simplify channel operation  
                assigned_KEKs[ass_idx] = temp_e_key.ref_id 
                ass_idx++
        ::  msg == d_DEK ->
                assert(temp_key == DEKs[(temp_key-1)%2] || (temp_key == received_e_DEKs[(temp_key-1)%2].id-ENC_DUMMY && grant == VALID_GRANT))
                assert(DEKs[0] != received_e_DEKs[(temp_key-1)%2].id-ENC_DUMMY)
                assert(DEKs[1] != received_e_DEKs[(temp_key-1)%2].id-ENC_DUMMY)
        ::  msg == deny -> skip
        ::  msg == e_DEK ->
                assert(temp_e_key.version > encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].version)
                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].id = temp_e_key.id
                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].version = temp_e_key.version
                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].ref_id = temp_e_key.ref_id
                encrypted_DEKs[(temp_e_key.id-ENC_DUMMY-1)%2].ref_version = temp_e_key.ref_version
        fi
        
        goto Select_state
}

proctype Keystore()
{
    mtype msg, enc_msg
    int dek_id, kek_id, kek_ref, i, tenant_id, id, version, is_case, kek_idx, assigned_to, grant
    bool valid, received

    Key temp_key
    E_Key temp_e_key

    Key v_KEKs[NUM_KEKS]

    Select_state:

        grant = 0

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

        goto Receive

    Receive:

        received = false

        if 
        ::  atomic{ t12k?[msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id] ->
                t12k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id } ->
                received = true
                kek_id = kek_ref-ENC_DUMMY
        ::  atomic{ t22k?[msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id, grant] ->
                t22k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id, grant } ->
                received = true
                kek_id = kek_ref-ENC_DUMMY
        ::  else -> skip
        fi

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

        v_KEKs[kek_idx].id = id
        v_KEKs[kek_idx].version = version
        v_KEKs[kek_idx].assigned_to = assigned_to

        k2ac!msg, id, tenant_id, grant
    
        ac2k?msg

        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        if
        ::  tenant_id == 1 -> k2t1!ass_KEK, -1, v_KEKs[kek_idx].id+ENC_DUMMY, -1, -1, -1
        ::  else -> k2t2!ass_KEK, -1, v_KEKs[kek_idx].id+ENC_DUMMY, -1, -1, -1
        fi

        if
        ::  !SAME_KEK_ASSIGNED -> kek_idx++
        ::  else -> skip
        fi

        goto Select_state

    Decrypt:

        valid = true

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
        ::  is_case == 2
            if
            ::  v_KEKs[kek_id-1].version >= temp_e_key.ref_version -> 
                    skip
            ::  else -> 
                    k2db!d_DEK, kek_id, tenant_id
                    db2k?msg, id, version, assigned_to
                    
                    v_KEKs[id-1].version = id
                    v_KEKs[id-1].version = version

                    if
                    ::  v_KEKs[id-1].version < temp_e_key.ref_version -> valid = false
                    ::  else -> skip
                    fi
            fi
        ::  else -> skip
        fi

        if
        ::  valid -> assert(v_KEKs[kek_id-1].version >= temp_e_key.ref_version)
        ::  else -> goto Deny_request
        fi

        if
        ::  tenant_id == 1 -> k2t1!d_DEK, temp_e_key.id-ENC_DUMMY, -1, -1, -1, -1
        ::  else -> k2t2!d_DEK, temp_e_key.id-ENC_DUMMY, -1, -1, -1, -1
        fi

        goto Select_state

    Encrypt:

        if 
        ::  msg == re_DEK -> enc_msg = re_DEK
        ::  else -> enc_msg = e_DEK
        fi

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
                v_KEKs[id-1].id = id
                v_KEKs[id-1].version = version
                v_KEKs[id-1].assigned_to = assigned_to
        ::  else -> goto Deny_request
        fi
        
        assert(kek_id > 0 && kek_id <= NUM_KEKS)

        if 
        ::  enc_msg == re_DEK -> 
                assert(temp_e_key.ref_version <= v_KEKs[kek_id-1].version && temp_e_key.ref_version > v_KEKs[kek_id-1].version-2)
        ::  else -> temp_e_key.id = dek_id+ENC_DUMMY
        fi
        
        temp_e_key.version = timer
        temp_e_key.ref_id = v_KEKs[kek_id-1].id+ENC_DUMMY
        temp_e_key.ref_version = v_KEKs[kek_id-1].version

        if
        ::  tenant_id == 1 -> k2t1!enc_msg, -1, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version
        ::  else -> k2t2!enc_msg, -1, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version
        fi

        goto Select_state

    Deny_request:
        
        if
        ::  tenant_id == 1 -> k2t1!deny, -1, -1, -1, -1, -1
        ::  else -> k2t2!deny, -1, -1, -1, -1, -1
        fi

        goto Select_state
}

/**
    When the Clock component is disabled, the Database contains a timer 
    that acts as a clock sending signals to tenants when rotation has 
    been executed. Rotation is not time-sensitive such that it is affected 
    by distributed clock-sync issues, so it could also be seen as a tenant 
    quering a clock to see if the scheduled rotation that could be part 
    of the metadata in the KEK information available to the tenant has 
    taken place.  
 */
proctype Database() {

    mtype msg
    int dek_id, kek_id, i, tenant_id
    Key p_KEKs[NUM_KEKS]

    for (i in p_KEKs) {
        p_KEKs[i].id = i+1
        p_KEKs[i].version = 1
    }
    
    Main:

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

                    goto Main

            ::  else -> skip
            fi
        }

        goto Deny_request

    Deny_request:
        
        db2k!deny, -1, -1, -1

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
    int kek_id, tenant_id, idx, i, num_assigned, grant
    int tnt_x_kek[NUM_TENANTS*NUM_KEKS]
    
    Select_state:

        k2ac?msg, kek_id, tenant_id, grant

        if
        ::  msg == ass_KEK -> goto Assign_KEK
        ::  msg == d_DEK || msg == e_DEK || msg == re_DEK -> goto Authorize
        ::  else -> goto Deny_request
        fi

        goto Select_state
    
    Assign_KEK:
        
        num_assigned = 0
        i = 0

        do
        ::  i < NUM_KEKS -> i++
            if
            ::  tnt_x_kek[(tenant_id-1)*NUM_KEKS+i-1] > 0 -> num_assigned++
            ::  else -> skip
            fi

            if
            ::  num_assigned >= ASS_MAX -> goto Deny_request
            ::  SAME_KEK_ASSIGNED && num_assigned >= SAME_KEK_MAX -> goto Deny_request
            ::  else -> skip
            fi
        ::  else -> break
        od

        idx = (tenant_id - 1) * NUM_KEKS + (kek_id - 1) 

        if
        ::  tnt_x_kek[idx] > 1 -> goto Deny_request
        ::  else -> tnt_x_kek[idx] = 1
        fi

        goto Ack_request

    Authorize:

        idx = (tenant_id - 1) * NUM_KEKS + (kek_id - 1)
        
        if
        ::  idx >= 0 && idx < NUM_TENANTS*NUM_KEKS ->  
            if
            ::  tnt_x_kek[idx] < 1 ->
                if
                ::  grant == VALID_GRANT ->
                    idx = kek_id - 1
                    if
                    ::  tnt_x_kek[idx] < 1 -> goto Deny_request
                    ::  else -> skip
                    fi
                ::  else -> goto Deny_request
                fi
            ::  else -> skip
            fi
        ::  else -> goto Deny_request
        fi


        goto Ack_request

    Ack_request:

        ac2k!ack

        goto Select_state
    
    Deny_request:

        ac2k!deny

        goto Select_state

}
