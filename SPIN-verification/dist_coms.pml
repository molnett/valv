#define NUM_DEKS 2
#define NUM_KEKS 4
#define NUM_KEYSTORES 1
#define NUM_TENANTS 1
#define U2K_MAX 3
#define K2U_MAX 0
#define K2AC_MAX 0
#define AC2K_MAX 0
#define K2DB_MAX 3
#define DB2K_MAX 0
#define DB2U_MAX 5
#define ASS_MAX 2
#define ROT_KEK_1 15000
#define ROT_KEK_2 18000
#define ROT_KEK_3 25000
#define ROT_KEK_4 24000
#define CACHE_CLEAR 4000
#define USE_CLOCK false 
#define SAME_TNT_ID false
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

mtype = { e_DEK, d_DEK, re_DEK, ass_KEK, rot_KEK, deny, ack }

// u: Tenant
// k: Keystore
// ac: Access Control

// { message type, DEK_ID, KEK_ID, E_KEY-ID, E_KEY-VERSION, E_KEY-REF-V, TENANT-ID }
// KEK_ID shares index to E_KEY-REF-ID in channels to reduce channel width
chan u12k = [U2K_MAX] of { mtype, int, int, int, int, int, int }	// Tenant 1 -> Keystore
chan u22k = [U2K_MAX] of { mtype, int, int, int, int, int, int }	// Tenant 2 -> Keystore
chan k2u1 = [K2U_MAX] of { mtype, int, int, int, int, int }	// Keystore -> Tenant 1
chan k2u2 = [K2U_MAX] of { mtype, int, int, int, int, int }	// Keystore -> Tenant 2

//                  { message type, KEK_ID, tenant_id}
chan k2ac = [K2AC_MAX] of { mtype, int, int }	// Keystore -> Access Control
chan ac2k = [AC2K_MAX] of { mtype }	// Access Control -> Keystore

//                  { message type, KEK_ID, tenant_id}
chan k2db = [K2DB_MAX] of { mtype, int, int }	// Keystore -> Database
//              { message type, KEK_ID, KEK_VERSION, KEK_ASS-TO }
chan db2k = [DB2K_MAX] of { mtype, int, int, int }	// Database -> Keystore

// This  channel emulates an external component notifying 
// the tenant when a rotation has taken place 
//                  { message type, KEK_ID }
chan db2u1 = [DB2U_MAX] of { mtype, int }  // Database -> Tenant 1
chan db2u2 = [DB2U_MAX] of { mtype, int }  // Database -> Tenant 2

int timer, rotate_1, rotate_2, rotate_3, rotate_4, commit_1, commit_2, commit_3, commit_4
bool clear_cache

init {

    timer = 0
    clear_cache = false

    atomic {
        run Tenant(1)
        run Keystore()
        run Database()
        run AccessControl()
        if
        ::  USE_CLOCK -> run Clock()
        ::  else -> skip
        fi
    }

}

proctype Tenant(int id)
{
    mtype msg
    int temp_key, i, ass_idx, recrypt_idx
    int assigned_KEKs[NUM_KEKS], DEKs[NUM_DEKS]
    E_Key temp_e_key
    E_Key encrypted_DEKs[NUM_DEKS]
    bool recrypt_1, recrypt_2, recrypt_3, never_true

    for (i in DEKs) {
        DEKs[i] = i+1
    }

    Select_state: 
        
        if
        ::  id == 1 ->
            if
            ::  atomic{ db2u1?[msg, recrypt_idx] -> db2u1?msg, recrypt_idx } ->
                    goto Recrypt
            ::  else -> skip
            fi
        ::  else -> 
            if
            ::  atomic{ db2u2?[msg, recrypt_idx] -> db2u2?msg, recrypt_idx } ->
                    goto Recrypt
            ::  else -> skip
            fi
        fi
        
        do
        ::  goto Encrypt
        ::  goto Decrypt
        ::  goto Request_KEK
        od

    Encrypt:

        if
        ::  id == 1 ->
            do
            ::  u12k!e_DEK, DEKs[0], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  u12k!e_DEK, DEKs[0], assigned_KEKs[1], -1, -1, -1, id -> break
            ::  u12k!e_DEK, DEKs[1], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  u12k!e_DEK, DEKs[1], assigned_KEKs[1], -1, -1, -1, id -> break
            od
        ::  else ->
            do
            ::  u22k!e_DEK, DEKs[0], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  u22k!e_DEK, DEKs[0], assigned_KEKs[1], -1, -1, -1, id -> break
            ::  u22k!e_DEK, DEKs[1], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  u22k!e_DEK, DEKs[1], assigned_KEKs[1], -1, -1, -1, id -> break
            od
        fi

        goto Receive
    
    Decrypt:
        
        if
        ::  id == 1 ->
            if
            ::  encrypted_DEKs[0].id != 0 -> 
                    u12k!d_DEK, -1, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id
            ::  encrypted_DEKs[1].id != 0 -> 
                    u12k!d_DEK, -1, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id
            ::  else -> goto Select_state 
            fi
        ::  else ->
            if
            ::  encrypted_DEKs[0].id != 0 -> 
                    u22k!d_DEK, -1, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id
            ::  encrypted_DEKs[1].id != 0 -> 
                    u22k!d_DEK, -1, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id
            ::  else -> goto Select_state 
            fi
        fi

        goto Receive

    Recrypt:

        if
        ::  recrypt_1 && assigned_KEKs[0] != 0 && id == 1 ->
                i = 0
                for (i in encrypted_DEKs) {
                    if 
                    ::  encrypted_DEKs[i].ref_id == assigned_KEKs[0] -> 
                            u12k!re_DEK, -1, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id
                            k2u1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                            if
                            ::  msg != deny -> 
                                    assert(temp_e_key.version > encrypted_DEKs[i].version)
                                    assert(temp_e_key.ref_version > encrypted_DEKs[i].ref_version)
                                    encrypted_DEKs[temp_e_key.id-1].id = temp_e_key.id
                                    encrypted_DEKs[temp_e_key.id-1].version = temp_e_key.version
                                    encrypted_DEKs[temp_e_key.id-1].ref_id = temp_e_key.ref_id
                                    encrypted_DEKs[temp_e_key.id-1].ref_version = temp_e_key.ref_version
                            ::  else -> skip
                            fi
                    ::  else -> skip
                    fi
                }
                recrypt_1 = false
        ::  else -> skip
        fi

        if
        ::  recrypt_2 && assigned_KEKs[1] != 0 -> 
                i = 0
                for (i in encrypted_DEKs) {
                    if 
                    ::  encrypted_DEKs[i].ref_id == assigned_KEKs[1] -> 
                        if
                        ::  id == 1 ->
                                u12k!re_DEK, -1, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id
                                k2u1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                        ::  else ->   
                                u22k!re_DEK, -1, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id
                                k2u2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                        fi
                    
                        if
                        ::  msg != deny -> 
                                assert(temp_e_key.version > encrypted_DEKs[i].version)
                                assert(temp_e_key.ref_version > encrypted_DEKs[i].ref_version)
                                encrypted_DEKs[temp_e_key.id-1].id = temp_e_key.id
                                encrypted_DEKs[temp_e_key.id-1].version = temp_e_key.version
                                encrypted_DEKs[temp_e_key.id-1].ref_id = temp_e_key.ref_id
                                encrypted_DEKs[temp_e_key.id-1].ref_version = temp_e_key.ref_version
                        ::  else -> skip
                        fi
                    ::  else -> skip
                    fi
                }
                recrypt_2 = false
        ::  else -> skip
        fi

        if
        ::  recrypt_3 && assigned_KEKs[2] != 0 && id == 2 -> skip
                i = 0
                for (i in encrypted_DEKs) {
                    if 
                    ::  encrypted_DEKs[i].ref_id == assigned_KEKs[2] -> 
                            u22k!re_DEK, -1, encrypted_DEKs[i].ref_id, encrypted_DEKs[i].id, encrypted_DEKs[i].version, encrypted_DEKs[i].ref_version, id
                            k2u2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
                            if
                            ::  msg != deny -> 
                                    assert(temp_e_key.version > encrypted_DEKs[i].version)
                                    assert(temp_e_key.ref_version > encrypted_DEKs[i].ref_version)
                                    encrypted_DEKs[temp_e_key.id-1].id = temp_e_key.id
                                    encrypted_DEKs[temp_e_key.id-1].version = temp_e_key.version
                                    encrypted_DEKs[temp_e_key.id-1].ref_id = temp_e_key.ref_id
                                    encrypted_DEKs[temp_e_key.id-1].ref_version = temp_e_key.ref_version
                            ::  else -> skip
                            fi
                    ::  else -> skip
                    fi
                }
                recrypt_3 = false
        ::  else -> skip
        fi

        goto Select_state

    Request_KEK:
       
        if  
        ::  id == 1 -> u12k!ass_KEK, -1, -1, -1, -1, -1, id
        ::  else -> u22k!ass_KEK, -1, -1, -1, -1, -1, id
        fi

        goto Receive

    Receive:

        if
        ::  id == 1 ->
                k2u1?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
        ::  else ->
                k2u2?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
        fi
        
        if
        ::  msg == ass_KEK -> 
                // KEK.id is stored in temp_e_key.ref_id to simplify channel operation  
                assigned_KEKs[ass_idx] = temp_e_key.ref_id 
                ass_idx++
        ::  msg == d_DEK ->
                assert(temp_key == DEKs[temp_key-1])
        ::  msg == deny -> skip
        ::  msg == e_DEK ->
                assert(temp_e_key.version > encrypted_DEKs[temp_e_key.id-1].version)
                encrypted_DEKs[temp_e_key.id-1].id = temp_e_key.id
                encrypted_DEKs[temp_e_key.id-1].version = temp_e_key.version
                encrypted_DEKs[temp_e_key.id-1].ref_id = temp_e_key.ref_id
                encrypted_DEKs[temp_e_key.id-1].ref_version = temp_e_key.ref_version
        fi
        
        goto Select_state
}

proctype Keystore()
{
    mtype msg
	int dek_id, kek_id, kek_ref, i, tenant_id, id, version, is_case, kek_idx, assigned_to
    bool valid, received

    Key temp_key
    E_Key temp_e_key

    Key v_KEKs[NUM_KEKS]

    Select_state:

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
        ::  atomic{ u12k?[msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id] ->
                u12k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id } ->
                received = true
                kek_id = kek_ref-100
        ::  atomic{ u22k?[msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id] ->
                u22k?msg, dek_id, kek_ref, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, tenant_id } ->
                received = true
                kek_id = kek_ref-100
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

        if 
        ::  v_KEKs[kek_idx].id == 0 ->
                k2db!ass_KEK, kek_idx+1, tenant_id
                db2k?msg, id, version, assigned_to
                v_KEKs[kek_idx].id = id
                v_KEKs[kek_idx].version = version
                v_KEKs[kek_idx].assigned_to = assigned_to
                k2ac!msg, id, tenant_id
        ::  else -> k2ac!msg, v_KEKs[kek_idx], tenant_id
        fi
    
        ac2k?msg
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi


        if
        ::  tenant_id == 1 -> k2u1!ass_KEK, -1, v_KEKs[kek_idx].id+100, -1, -1, -1
        ::  else -> k2u2!ass_KEK, -1, v_KEKs[kek_idx].id+100, -1, -1, -1
        fi

        kek_idx++

        goto Select_state

    Decrypt:

        valid = true

        k2ac!msg, kek_id, tenant_id
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

        k2u1!d_DEK, temp_e_key.id, -1, -1, -1, -1

        goto Select_state

    Encrypt:

        k2ac!msg, kek_id, tenant_id
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
        ::  msg == re_DEK -> 
                assert(temp_e_key.ref_version < v_KEKs[kek_id-1].version && temp_e_key.ref_version > v_KEKs[kek_id-1].version-2)
        ::  else -> temp_e_key.id = dek_id
        fi
        
        temp_e_key.version = timer
        temp_e_key.ref_id = v_KEKs[kek_id-1].id+100
        temp_e_key.ref_version = v_KEKs[kek_id-1].version

        k2u1!e_DEK, -1, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version

        goto Select_state

    Deny_request:
      
        k2u1!deny, -1, -1, -1, -1, -1

        goto Select_state
}

/**
    In this model, the Database contains a timer that acts as a clock
    that sends signals to tenants when rotation has been executed. 
    Rotation is not time-sensitive such that it is affected by
    distributed clock-sync issues, so it could also be seen as a tenant 
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
        
        if
        ::  !USE_CLOCK -> timer++
        ::  else -> skip
        fi

        if  // Cache timer
        ::  !USE_CLOCK && timer%CACHE_CLEAR == 0 -> 
                clear_cache = true
        ::  else -> skip
        fi

        if  // Rotation 1
        ::  !USE_CLOCK && timer%ROT_KEK_1 == 0 ->
                p_KEKs[0].version++

                if
                ::  p_KEKs[0].assigned_to == 1 ->
                        db2u1!rot_KEK, p_KEKs[0].id+100
                ::  else -> 
                        db2u2!rot_KEK, p_KEKs[0].id+100
                fi
        ::  USE_CLOCK && rotate_1 > 0 -> 
                p_KEKs[0].version++
                rotate_1--
                commit_1++
        ::  else -> skip
        fi

        if  // Rotation 2
        ::  !USE_CLOCK && timer%ROT_KEK_2 == 0 ->
                p_KEKs[1].version++

                if
                ::  p_KEKs[1].assigned_to == 1 ->
                        db2u1!rot_KEK, p_KEKs[1].id+100
                ::  else -> 
                        db2u2!rot_KEK, p_KEKs[1].id+100
                fi
        ::  USE_CLOCK && rotate_2 > 0 -> 
                p_KEKs[1].version++
                rotate_2-- 
                commit_2++
        ::  else -> skip
        fi

        if  // Rotation 3
        ::  !USE_CLOCK && timer%ROT_KEK_3 == 0 ->
                p_KEKs[2].version++

                if
                ::  p_KEKs[2].assigned_to == 1 ->
                        db2u1!rot_KEK, p_KEKs[2].id+100
                ::  else -> 
                        db2u2!rot_KEK, p_KEKs[2].id+100
                fi
        ::  USE_CLOCK && rotate_3 > 0 -> 
                p_KEKs[2].version++
                rotate_3-- 
                commit_3++
        ::  else -> skip
        fi

        if  // Rotation 4
        ::  !USE_CLOCK && timer%ROT_KEK_4 == 0 ->
                p_KEKs[3].version++

                if
                ::  p_KEKs[3].assigned_to == 1 ->
                        db2u1!rot_KEK, p_KEKs[3].id+100
                ::  else -> 
                        db2u2!rot_KEK, p_KEKs[3].id+100
                fi
        ::  USE_CLOCK && rotate_4 > 0 -> 
                p_KEKs[3].version++
                rotate_4--
                commit_4++
        ::  else -> skip
        fi

        if 
        ::  atomic{ k2db?[msg, kek_id] -> k2db?msg, kek_id } ->
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
                    if
                    ::  !USE_CLOCK -> timer++
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
    int kek_id, tenant_id, idx, i, num_assigned
    
    int tnt_x_kek[NUM_TENANTS*NUM_KEKS]
    
    Select_state:
        
        k2ac?msg, kek_id, tenant_id

        if
        ::  msg == ass_KEK -> goto Assign_KEK
        ::  msg == d_DEK || msg == e_DEK || msg == rot_KEK -> goto Authorize
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
            ::  num_assigned > ASS_MAX -> goto Deny_request
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
            ::  tnt_x_kek[idx] < 1 -> goto Deny_request
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

/**
    Alternative component instead of the timer 
    in the Database component
 */
proctype Clock() {
    
    Main:
    
        timer++

        if  // Cache timer
        ::  timer%CACHE_CLEAR == 0 -> 
                clear_cache = true
        ::  else -> skip
        fi

        if  // Rotation
        ::  timer%ROT_KEK_1 == 0 -> 
                rotate_1++
        ::  else -> skip
        fi

        if  // Rotation
        ::  timer%ROT_KEK_2 == 0 -> 
                rotate_2++
        ::  else -> skip
        fi

        if  // Rotation
        ::  timer%ROT_KEK_3 == 0 -> 
                rotate_3++
        ::  else -> skip
        fi

        if  // Rotation
        ::  timer%ROT_KEK_3 == 0 -> 
                rotate_4++
        ::  else -> skip
        fi

    goto Main
}
