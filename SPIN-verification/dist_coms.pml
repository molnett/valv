#define NUM_DEKS 2
#define NUM_KEKS 3
#define NUM_KEYSTORES 1
#define NUM_USERS 1
#define U2K_MAX 3
#define K2U_MAX 3
#define K2AC_MAX 3
#define AC2K_MAX 3
#define K2DB_MAX 3
#define DB2K_MAX 3
#define DB2U_MAX 5
#define ROT_KEK_1 15000
#define ROT_KEK_2 18000
#define ROT_KEK_3 25000
#define CACHE_CLEAR 4000

typedef Key { /* Unencrypted */
    int id
    int version
}

typedef E_Key { /* Encrypted */
    int id
    int version 
    int ref_id
    int ref_version
}

mtype = { e_DEK, d_DEK, re_DEK, ass_KEK, rot_KEK, deny, ack }

// u: User
// k: Keystore
// ac: Access Control

// { message type, KEY_ID, KEK_ID, E_KEY-ID, E_KEY-VERSION, E_KEY-REF-V, USER-ID }
// KEK_ID shares index to E_KEY-REF-ID in channels to reduce channel width
chan u12k = [U2K_MAX] of { mtype, int, int, int, int, int, int }	// User 1 -> Keystore
chan u22k = [U2K_MAX] of { mtype, int, int, int, int, int, int }	// User 2 -> Keystore
chan k2u1 = [K2U_MAX] of { mtype, int, int, int, int, int }	// Keystore -> User 1
chan k2u2 = [K2U_MAX] of { mtype, int, int, int, int, int }	// Keystore -> User 2

//                  { message type, KEK_ID, USER_ID}
chan k2ac = [K2AC_MAX] of { mtype, int, int }	// Keystore -> Access Control
chan ac2k = [AC2K_MAX] of { mtype }	// Access Control -> Keystore

//                  { message type, KEK_ID}
chan k2db = [K2DB_MAX] of { mtype, int }	// Keystore -> Database
//              { message type, id, version, rotation }
chan db2k = [DB2K_MAX] of { mtype, int, int }	// Database -> Keystore

// This  channel emulates an external component notifying 
// the user when a rotation has taken place 
//                  { message type, kek1, kek2, kek3 }
chan db2u1 = [DB2U_MAX] of { mtype, bool, bool, bool }  // Database -> User 1
chan db2u2 = [DB2U_MAX] of { mtype, bool, bool, bool }  // Database -> User 2

int timer
bool clear_cache

init {

    timer = 0
    clear_cache = false

    atomic {
        run User(1)
        run Keystore()
        run Database()
        run AccessControl()
    }

}

proctype User(int id)
{
    mtype msg
    int temp_key, i, count
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
            ::  atomic{ db2u1?[msg, recrypt_1, recrypt_2, recrypt_3] -> db2u1?msg, recrypt_1, recrypt_2, recrypt_3 } ->
                    goto Recrypt
            ::  else -> skip
            fi
        ::  id == 2 -> 
            if
            ::  atomic{ db2u2?[msg, recrypt_1, recrypt_2, recrypt_3] -> db2u1?msg, recrypt_1, recrypt_2, recrypt_3 } ->
                    goto Recrypt
            ::  else -> skip
            fi
        ::  else -> never_true = true
        fi

        assert(!never_true)

        if 
        ::  id == 1 -> assert(assigned_KEKs[2] == 0)
        ::  id == 2 -> assert(assigned_KEKs[0] == 0)
        fi
        
        do
        ::  goto Encrypt
        ::  goto Decrypt
        ::  goto Request_KEK
        od

    Encrypt:

        do
        ::  u12k!e_DEK, DEKs[0], assigned_KEKs[0], -1, -1, -1, id -> break
        ::  u12k!e_DEK, DEKs[0], assigned_KEKs[1], -1, -1, -1, id -> break
        ::  u12k!e_DEK, DEKs[1], assigned_KEKs[0], -1, -1, -1, id -> break
        ::  u12k!e_DEK, DEKs[1], assigned_KEKs[1], -1, -1, -1, id -> break
        od

        goto Receive
    
    Decrypt:

        if
        ::  encrypted_DEKs[0].id != 0 -> 
                u12k!d_DEK, -1, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id
        ::  encrypted_DEKs[1].id != 0 -> 
                u12k!d_DEK, -1, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id
        ::  else -> goto Select_state 
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
        ::  assigned_KEKs[0] == 0 && id == 1 ->
                u12k!ass_KEK, -1, id, -1, -1, -1, id
        ::  assigned_KEKs[1] == 0 ->
            if
            :: id == 1 -> u12k!ass_KEK, -1, 2, -1, -1, -1, id
            :: id == 2 -> u22k!ass_KEK, -1, 2, -1, -1, -1, id
            fi
        ::  assigned_KEKs[2] == 0 && id == 2 ->
                u22k!ass_KEK, -1, 3, -1, -1, -1, id
        ::  else -> goto Select_state
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
                assigned_KEKs[temp_e_key.ref_id-1] = temp_e_key.ref_id 
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
	int dek_id, kek_id, i, user_id, id, version, caser, count
    bool valid

    Key temp_key
    E_Key temp_e_key

    Key v_KEKs[NUM_KEKS]

    

    Select_state:

        if // Clear Cache
        ::  clear_cache -> 
                i = 0
                for (i in v_KEKs) {
                    v_KEKs[i].id = 0 -> v_KEKs[i].version = 0
                }
            clear_cache = false
        ::  else -> skip
        fi

        goto Receive

    Receive:

        if 
        ::  atomic{ u12k?[msg, dek_id, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, user_id] ->
                u12k?msg, dek_id, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, user_id } ->
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

        k2ac!msg, kek_id, user_id
        ac2k?msg
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        if 
        ::  v_KEKs[kek_id-1].id == 0 ->
                k2db!e_DEK, kek_id
                db2k?msg, id, version
                v_KEKs[kek_id-1].id = id
                v_KEKs[kek_id-1].version = version
        ::  else -> skip
        fi

        k2u1!ass_KEK, -1, v_KEKs[kek_id-1].id, -1, -1, -1

        goto Select_state

    Decrypt:

        valid = true

        k2ac!msg, kek_id, user_id
        ac2k?msg 
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        d_step {
            if 
            ::  v_KEKs[kek_id-1].id == 0 -> caser = 1
            ::  v_KEKs[kek_id-1].id == kek_id -> caser = 2
            ::  else -> caser = 0 -> valid = false
            fi
        }

        if 
        ::  caser == 1 -> 
                k2db!e_DEK, kek_id
                db2k?msg, id, version

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
        ::  caser == 2
            if
            ::  v_KEKs[kek_id-1].version >= temp_e_key.ref_version -> 
                    skip
            ::  else -> 
                    k2db!e_DEK, kek_id
                    db2k?msg, id, version
                    
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
        ::  valid -> skip
        ::  else -> goto Deny_request
        fi

        assert(v_KEKs[kek_id-1].version >= temp_e_key.ref_version)

        k2u1!d_DEK, temp_e_key.id, -1, -1, -1, -1

        goto Select_state

    Encrypt:

        k2ac!msg, kek_id, user_id
        ac2k?msg
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        k2db!e_DEK, kek_id
        db2k?msg, id, version

        if
        ::  msg != deny -> 
                v_KEKs[id-1].id = id
                v_KEKs[id-1].version = version
        ::  else -> goto Deny_request
        fi
        assert(kek_id > 0 && kek_id <= NUM_KEKS)

        if 
        ::  msg == re_DEK -> 
                assert(temp_e_key.ref_version < v_KEKs[kek_id-1].version && temp_e_key.ref_version > v_KEKs[kek_id-1].version-2)
        ::  else -> temp_e_key.id = dek_id
        fi
        
        temp_e_key.version = timer
        temp_e_key.ref_id = v_KEKs[kek_id-1].id
        temp_e_key.ref_version = v_KEKs[kek_id-1].version

        k2u1!e_DEK, -1, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version

        goto Select_state

    Deny_request:
      
        k2u1!deny, -1, -1, -1, -1, -1

        goto Select_state
}

proctype Database() {

    mtype msg
	int dek_id, kek_id, i, user_id
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

        if  // Rotation
        ::  timer%ROT_KEK_1 == 0 -> 
                p_KEKs[0].version++
                db2u1!rot_KEK, 1, 0, 0
                // db2u2!rot_KEK, 1, 0, 0
        ::  else -> skip
        fi

        if  // Rotation
        ::  timer%ROT_KEK_2 == 0 -> 
                p_KEKs[1].version++
                db2u1!rot_KEK, 0, 1, 0
                // db2u2!rot_KEK, 0, 1, 0
        ::  else -> skip
        fi

        if  // Rotation
        ::  timer%ROT_KEK_3 == 0 -> 
                p_KEKs[2].version++
                db2u1!rot_KEK, 0, 0, 1
                // db2u2!rot_KEK, 0, 0, 1
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
                    timer++
                    db2k!msg, p_KEKs[i].id, p_KEKs[i].version
                    goto Main
            ::  else -> skip
            fi
        }

        goto Deny_request

    Deny_request:
        
        db2k!deny, -1, -1

        goto Main

}


/*
    ## Access Control Info ##

    user_x_kek - Relations between users and KEKs

    0 - No relation
    1 - KEK relation exists

    Indexation is a 2d array inside a single array

*/

proctype AccessControl()
{
    mtype msg
    int kek_id, user_id, idx
    
    int usr_x_kek[NUM_USERS*NUM_KEKS]
    
    Select_state:
        
        k2ac?msg, kek_id, user_id

        if
        ::  msg == ass_KEK -> goto Assign_KEK
        ::  msg == d_DEK || msg == e_DEK || msg == rot_KEK -> goto Authenticate_user
        ::  else -> goto Deny_request
        fi

        goto Select_state
    
    Assign_KEK:
        
        idx = (user_id - 1) * NUM_KEKS + (kek_id - 1) 

        if 
        ::  usr_x_kek[idx] < 1 -> 
                usr_x_kek[idx] = 1
        ::  else -> goto Deny_request
        fi

        goto Ack_request

    Authenticate_user:

        idx = (user_id - 1) * NUM_KEKS + (kek_id - 1)

        if
        ::  idx >= 0 && idx < NUM_USERS*NUM_KEKS ->  
            if
            ::  usr_x_kek[idx] < 1 -> goto Deny_request
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