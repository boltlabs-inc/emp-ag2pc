#include "translation.h"
#include <emp-tool/emp-tool.h>
#include <string.h>

using namespace emp;

int translate_state(State_l state, bool *in, int pos) {
    pos = translate_nonce(state.nonce, in, pos);
    pos = translate_rev_lock(state.rl, in, pos);
    pos = translate_balance(state.balance_cust, in, pos);
    pos = translate_balance(state.balance_merch, in, pos);
    pos = translate_txid(state.txid_merch, in, pos);
    pos = translate_txid(state.txid_escrow, in, pos);
    pos = translate_txid(state.HashPrevOuts_merch, in, pos);
    return translate_txid(state.HashPrevOuts_escrow, in, pos);
}

int translate_nonce(Nonce_l nonce, bool *in, int pos) {
    for(int i = 0; i < 4; ++i) {
        int32_to_bool(&in[pos], nonce.nonce[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_rev_lock(RevLock_l rl, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], rl.revlock[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_balance(Balance_l balance, bool *in, int pos) {
    for(int i = 0; i < 2; ++i) {
        int32_to_bool(&in[pos], balance.balance[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_txid(Txid_l txid, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], txid.txid[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_paytoken(PayToken_l paytoken, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], paytoken.paytoken[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_bitcoinPubKey(BitcoinPublicKey_l pubkey, bool *in, int pos) {
    for(int i = 0; i < 9; ++i) {
        int32_to_bool(&in[pos], pubkey.key[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_commitmentRandomness(CommitmentRandomness_l com_rand, bool *in, int pos) {
    for(int i = 0; i < 4; ++i) {
        int32_to_bool(&in[pos], com_rand.randomness[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_hmacKey(HMACKey_l key, bool *in, int pos) {
    for(int i = 0; i < 16; ++i) {
        int32_to_bool(&in[pos], key.key[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_mask(Mask_l mask, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], mask.mask[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_hmacKeyCom(HMACKeyCommitment_l hmac_key_com, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], hmac_key_com.commitment[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_maskCom(MaskCommitment_l mask_com, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], mask_com.commitment[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_revLockCom(RevLockCommitment_l rev_lock_com, bool *in, int pos) {
    for(int i = 0; i < 8; ++i) {
        int32_to_bool(&in[pos], rev_lock_com.commitment[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_pubKeyHash(PublicKeyHash_l pub_key_hash, bool *in, int pos) {
    for(int i = 0; i < 5; ++i) {
        int32_to_bool(&in[pos], pub_key_hash.hash[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_ecdsaPartialSig(EcdsaPartialSig_l par_sig, bool *in, int pos) {
    string tmp = "";

    tmp = dec_to_bin(par_sig.r);
    for(int i = pos; i < pos+258; ++i)
        in[i] = (strcmp(&tmp[i], "1")==0? true: false);
    tmp = dec_to_bin(par_sig.k_inv);
    for(int i = pos+258; i < pos+258+516; ++i)
        in[i] = (strcmp(&tmp[i], "1")==0? true: false);
	return pos+258+516;
}
