
#define NUM_DEKS 2
#define NUM_KEKS 2
#define NUM_KEYSTORES 1
#define NUM_USERS 1
#define U2K_MAX 3
#define K2U_MAX 3
#define K2AC_MAX 3
#define AC2K_MAX 3



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

mtype = { e_DEK, d_DEK, ass_KEK, deny, ack }

// u: User
// k: Keystore
// ac: Access Control
// { message type, KEY_ID, KEK_ID, E_KEY-ID, E_KEY-VERSION, E_KEY-REF-V, USER-ID }
// KEK_ID shares index to E_KEY-REF-ID in channels to reduce channel width

chan u2k = [U2K_MAX] of { mtype, int, int, int, int, int, int }	// User -> Keystore
chan k2u = [K2U_MAX] of { mtype, int, int, int, int, int }	// Keystore -> User

// { message type, DEK_ID, KEK_ID, USER_ID}
chan k2ac = [K2AC_MAX] of { mtype, int, int, int }	// Keystore -> Access Control
chan ac2k = [AC2K_MAX] of { mtype }	// Access Control -> Keystore


init {

    atomic {
        run User()
        run Keystore()
        run AccessControl()
    }

}


proctype User()
{
    mtype msg
    int temp_key, i, iteration, id = 1
    E_Key temp_e_key
    E_Key encrypted_DEKs[NUM_DEKS]
    int assigned_KEKs[NUM_KEKS], DEKs[NUM_DEKS]

    for (i in DEKs) {
        DEKs[i] = i+1
    }

    for (i in encrypted_DEKs) {
        encrypted_DEKs[i].version = -1
        encrypted_DEKs[i].id = -1
    }

    Select_state: 

        iteration++
        // printf("USER: %d\n", iteration)

        do
        :: goto Receive 
        :: goto Encrypt
        :: goto Decrypt
        :: goto Request_KEK
        od

    Encrypt:

        if 
        ::  len(u2k) < U2K_MAX ->
            do
            ::  u2k!e_DEK, DEKs[0], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  u2k!e_DEK, DEKs[0], assigned_KEKs[1], -1, -1, -1, id -> break
            ::  u2k!e_DEK, DEKs[1], assigned_KEKs[0], -1, -1, -1, id -> break
            ::  u2k!e_DEK, DEKs[1], assigned_KEKs[1], -1, -1, -1, id -> break
            od
        ::  else -> skip
        fi

        goto Select_state

    Receive:
        if 
        ::  len(k2u) > 0 ->
                k2u?msg, temp_key, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version
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
        ::  else -> skip 
        fi
        
        goto Select_state
    
    Decrypt:
        if
        ::  len(u2k) < U2K_MAX ->
                if
                ::  encrypted_DEKs[0].id != -1 -> 
                        u2k!d_DEK, -1, encrypted_DEKs[0].ref_id, encrypted_DEKs[0].id, encrypted_DEKs[0].version, encrypted_DEKs[0].ref_version, id
                ::  encrypted_DEKs[1].id != -1 -> 
                        u2k!d_DEK, -1, encrypted_DEKs[1].ref_id, encrypted_DEKs[1].id, encrypted_DEKs[1].version, encrypted_DEKs[1].ref_version, id
                ::  else -> skip 
                fi
        ::  else -> skip
        fi

        goto Select_state

    Request_KEK:
       
        if
        ::  len(u2k) < U2K_MAX ->
            if
            ::  assigned_KEKs[0] == 0 ->
                    u2k!ass_KEK, -1, 1, -1, -1, -1, id
            ::  assigned_KEKs[1] == 0 ->
                    u2k!ass_KEK, -1, 2, -1, -1, -1, id
            ::  else -> skip
            fi
        ::  else -> skip
        fi

        goto Select_state
}

proctype Keystore()
{
    mtype msg
	int dek_id, kek_id, i, iteration, user_id
    bool decryptable, encryptable

    Key temp_key
    E_Key temp_e_key

    Key KEKs[NUM_KEKS]


    for(i in KEKs) {
        KEKs[i].id = i+1
        KEKs[i].version = 1
    }

    Select_state:
        
        iteration++
        // printf("KEYSTORE: %d\n", iteration)

        do
        ::  goto Receive
        ::  goto Rotate
        od    

    Receive:

        if 
        ::  len(u2k) > 0 ->
                u2k?msg, dek_id, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_version, user_id
                if
                ::  msg == e_DEK -> goto Encrypt
                ::  msg == d_DEK -> goto Decrypt
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  else -> skip
                fi
        :: else -> skip
        fi

        goto Select_state
    
    Assign_KEK: 

        k2ac!msg, -1, kek_id, user_id
        ac2k?msg
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        k2u!ass_KEK, -1, KEKs[kek_id-1].id, -1, -1, -1

        goto Select_state

    Decrypt:

        decryptable = false

        for (i in KEKs) {
            if 
            ::  KEKs[i].id == kek_id && KEKs[i].version >= temp_e_key.ref_version -> 
                    decryptable = true
                    break
            ::  else -> skip
            fi
        }

        if
        ::  !decryptable -> goto Deny_request
        ::  else -> skip
        fi

        assert(KEKs[kek_id-1].version >= temp_e_key.ref_version)

        k2ac!msg, dek_id, kek_id, user_id
        ac2k?msg 
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        k2u!d_DEK, temp_e_key.id, -1, -1, -1, -1

        goto Select_state

    Encrypt:

        encryptable = false

        for (i in KEKs) {
            if 
            ::  KEKs[i].id == kek_id -> 
                    encryptable = true
                    break
            ::  else -> skip
            fi
        }

        if
        ::  !encryptable -> goto Deny_request
        ::  else -> skip
        fi

        assert(kek_id > 0 && kek_id <= NUM_KEKS)

        k2ac!msg, dek_id, kek_id, user_id
        ac2k?msg 
        
        if
        ::  msg == deny -> goto Deny_request
        ::  else -> skip
        fi

        temp_e_key.id = dek_id
        temp_e_key.version = iteration
        temp_e_key.ref_id = KEKs[kek_id-1].id
        temp_e_key.ref_version = KEKs[kek_id-1].version

        k2u!e_DEK, -1, temp_e_key.ref_id, temp_e_key.id, temp_e_key.version,  temp_e_key.ref_version

        goto Select_state

    Rotate: 

        goto Select_state

    Deny_request:
      
        k2u!deny, -1, -1, -1, -1, -1

        goto Select_state
}


/*
    ## Access Control Info ##

    user_x_kek_x_edeks - Relations between users KEKs and encrypted DEKs

    0 - No relation
    1 - KEK relation exists
    2 - KEK and E_DEK relation exists

    Indexation is a 3d array inside a single array

*/

proctype AccessControl()
{
    mtype msg
    int dek_id, kek_id, user_id, idx, iteration
    
    int usr_x_kek_x_edeks[NUM_USERS*NUM_KEKS*NUM_DEKS]
    
    Select_state:

        iteration++


        k2ac?msg, dek_id, kek_id, user_id
        // printf("ACCESS CONTROL: %d\n", iteration)
        // printf("ACCESS CONTROL MSG: %d\n", msg)

        if
        ::  msg == ass_KEK -> goto Assign_KEK
        ::  msg == d_DEK -> goto Decrypt
        ::  msg == e_DEK -> goto Encrypt
        ::  else -> goto Deny_request
        fi

        goto Select_state
    
    Assign_KEK:
        
        idx = (user_id - 1) * (NUM_KEKS*NUM_DEKS) + (kek_id - 1) * NUM_DEKS 

        if 
        ::  usr_x_kek_x_edeks[idx] < 1 -> 
                usr_x_kek_x_edeks[idx] = 1
        ::  else -> goto Deny_request
        fi

        goto Ack_request

    Decrypt:

        idx = (user_id - 1) * (NUM_KEKS*NUM_DEKS) + (kek_id - 1) * NUM_DEKS + dek_id

        if
        ::  idx >= 0 &&  idx < NUM_USERS*NUM_KEKS*NUM_DEKS ->  
            if
            ::  usr_x_kek_x_edeks[idx] < 2 -> goto Deny_request
            ::  else -> skip
            fi
        ::  else -> goto Deny_request
        fi

        goto Ack_request

    Encrypt:

        idx = (user_id - 1) * (NUM_KEKS*NUM_DEKS) + (kek_id - 1) * NUM_DEKS

        if
        ::  idx >= 0 &&  idx < NUM_USERS*NUM_KEKS*NUM_DEKS -> 
            if
            ::  usr_x_kek_x_edeks[idx] < 1 -> goto Deny_request
            ::  else -> skip
            fi
        ::  else -> goto Deny_request
        fi

        idx = idx + dek_id - 1
        usr_x_kek_x_edeks[idx] = 2
        
        goto Ack_request

    Ack_request:

        ac2k!ack

        goto Select_state
    
    Deny_request:

        ac2k!deny

        goto Select_state



}