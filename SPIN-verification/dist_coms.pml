
#define NUM_DEKS 2
#define NUM_KEKS 2
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

mtype = {e_DEK, d_DEK, ass_KEK, verify_usr, deny}

// u: User
// k: Keystore
// ac: Access Control
// { message type, KEY_ID, iteration, KEK_ID, E_KEY-ID, E_KEY-VERSION, E_KEY-REF-ID, E_KEY-REF-V }

chan u2k = [U2K_MAX] of { mtype, int, int, int, int, int, int, int }	// User -> Keystore
chan k2u = [K2U_MAX] of { mtype, int, int, int, int, int, int, int }	// Keystore -> User
chan k2ac = [K2AC_MAX] of { mtype, int, int, int, int, int, int, int }	// Keystore -> Access Control
chan ac2k = [AC2K_MAX] of { mtype, int, int, int, int, int, int, int }	// Access Control -> Keystore


init {

    atomic {
        run User()
        run Keystore()
    }

}

proctype User()
{
    mtype msg
    int temp_key, kek_id, i, iteration = 0
    E_Key temp_e_key
    E_Key encrypted_DEKs[NUM_DEKS]
    int assigned_KEKs[NUM_KEKS], DEKs[NUM_DEKS]

    for (i in DEKs) {
        DEKs[i] = i+1
    }

    for(i in assigned_KEKs) {
        assigned_KEKs[i] = -1
    }


    for (i in encrypted_DEKs) {
        encrypted_DEKs[i].version = -1
        encrypted_DEKs[i].id = -1
    }

    Select_state: 

        iteration++

        do
        :: goto Receive 
        :: goto Encrypt
        :: goto Decrypt
        :: goto Request_KEK
        od

    Encrypt:

        if 
        ::  len(u2k) != U2K_MAX ->
            do
            ::  u2k!e_DEK, DEKs[0], iteration, assigned_KEKs[0], -1, -1, -1, -1 -> break
            ::  u2k!e_DEK, DEKs[0], iteration, assigned_KEKs[1], -1, -1, -1, -1 -> break
            ::  u2k!e_DEK, DEKs[1], iteration, assigned_KEKs[0], -1, -1, -1, -1 -> break
            ::  u2k!e_DEK, DEKs[1], iteration, assigned_KEKs[1], -1, -1, -1, -1 -> break
            od
        ::  else -> skip
        fi

        goto Select_state

    Receive:
        if 
        ::  len(k2u) != 0 ->
                k2u?msg, temp_key, i, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version
                if
                ::  msg == ass_KEK -> 
                        assigned_KEKs[kek_id-1] = kek_id 
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
        ::  len(u2k) != U2K_MAX ->
                if
                ::  encrypted_DEKs[0].id != -1 -> skip
                ::  encrypted_DEKs[1].id != -1 -> skip
                ::  else -> skip 
                fi
        ::  else -> skip
        fi

        goto Select_state

    Request_KEK:

        if
        ::  len(u2k) != U2K_MAX ->
            if
            ::  assigned_KEKs[0] == -1 ->
                    u2k!ass_KEK, -1, -1, 1, -1, -1, -1, -1 
            ::  assigned_KEKs[1] == -1 ->
                    u2k!ass_KEK, -1, -1, 2, -1, -1, -1, -1 
            ::  else -> skip
            fi
        ::  else -> skip
        fi

        goto Select_state
}

proctype Keystore()
{
    mtype msg
	int dek_id, kek_id, i, dek_1, dek_2, iteration = 0
    Key temp_key
    E_Key temp_e_key

    Key KEKs[NUM_KEKS]


    for(i in KEKs) {
        KEKs[i].id = i+1
        KEKs[i].version = 1
    }

    Select_state:
        
        iteration++

        do
        ::  goto Receive
        ::  goto Rotate
        od    

    Receive:
        if 
        ::  len(u2k) != 0 ->
                u2k?msg, dek_id, i, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version
                if
                ::  msg == e_DEK -> goto Encrypt
                ::  msg == d_DEK -> skip
                ::  msg == ass_KEK -> goto Assign_KEK
                ::  else -> skip
                fi
        :: else -> skip
        fi

        goto Select_state

    Assign_KEK: 

        k2u!msg, dek_id, i, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version

        goto Select_state

    Deny_request:
      
        k2u!deny, dek_id, i, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version

        goto Select_state
    
    Decrypt:

        goto Select_state

    Encrypt:
        
        if
        ::  kek_id == -1 -> goto Deny_request
        ::  else -> skip
        fi

        assert(kek_id == 1 || kek_id == 2)

        temp_e_key.id = dek_id
        temp_e_key.version = iteration
        temp_e_key.ref_id = KEKs[kek_id-1].id
        temp_e_key.ref_version = KEKs[kek_id-1].version

        k2u!msg, -1, i, kek_id, temp_e_key.id, temp_e_key.version, temp_e_key.ref_id, temp_e_key.ref_version

        goto Select_state

    Rotate: 

        goto Select_state

}


proctype AccessControl()
{
    mtype msg
}