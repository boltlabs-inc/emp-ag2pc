#include "translation.h"
#include <emp-tool/emp-tool.h>
#include <string.h>
#include "sha256.h"

using namespace std;
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

int translate_general(uint32_t*input, int len, bool*in, int pos) {
    for(int i = 0; i < len; ++i) {
        int32_to_bool(&in[pos], input[i], 32);
	    pos = pos + 32;
    }
	return pos;
}

int translate_nonce(Nonce_l nonce, bool *in, int pos) {
    return translate_general(nonce.nonce, 4, in, pos);
}

int translate_rev_lock(RevLock_l rl, bool *in, int pos) {
	return translate_general(rl.revlock, 8, in, pos);
}

int translate_balance(Balance_l balance, bool *in, int pos) {
	return translate_general(balance.balance, 2, in, pos);
}

int translate_txid(Txid_l txid, bool *in, int pos) {
	return translate_general(txid.txid, 8, in, pos);
}

int translate_paytoken(PayToken_l paytoken, bool *in, int pos) {
	return translate_general(paytoken.paytoken, 8, in, pos);
}

int translate_bitcoinPubKey(BitcoinPublicKey_l pubkey, bool *in, int pos) {
	return translate_general(pubkey.key, 9, in, pos);
}

int translate_commitmentRandomness(CommitmentRandomness_l com_rand, bool *in, int pos) {
	return translate_general(com_rand.randomness, 4, in, pos);
}

int translate_hmacKey(HMACKey_l key, bool *in, int pos) {
	return translate_general(key.key, 16, in, pos);
}

int translate_mask(Mask_l mask, bool *in, int pos) {
	return translate_general(mask.mask, 8, in, pos);
}

int translate_hmacKeyCom(HMACKeyCommitment_l hmac_key_com, bool *in, int pos) {
	return translate_general(hmac_key_com.commitment, 8, in, pos);
}

int translate_maskCom(MaskCommitment_l mask_com, bool *in, int pos) {
	return translate_general(mask_com.commitment, 8, in, pos);
}

int translate_revLockCom(RevLockCommitment_l rev_lock_com, bool *in, int pos) {
	return translate_general(rev_lock_com.commitment, 8, in, pos);
}

int translate_pubKeyHash(PublicKeyHash_l pub_key_hash, bool *in, int pos) {
	return translate_general(pub_key_hash.hash, 5, in, pos);
}

int translate_ecdsaPartialSig(EcdsaPartialSig_l par_sig, bool *in, int pos) {
    string tmp = "";
    char one = '1';

    tmp = dec_to_bin(par_sig.r);
    for(int i = pos; i < pos+tmp.length(); ++i)
        in[i] = (tmp[i-pos] == one);
    tmp = dec_to_bin(par_sig.k_inv);
    for(int i = pos+258; i < pos+258+tmp.length(); ++i)
        in[i] = (tmp[i-pos-258] == one);
	return pos+258+516;
}

int translate_initSHA256(bool *in, int pos) {
    for(int i=0; i<64; i++) {
      int32_to_bool(&in[pos], k_clear[i], 32);
      pos = pos + 32;
    }
    for(int i=0; i<8; i++) {
      int32_to_bool(&in[pos], IV_clear[i], 32);
      pos = pos + 32;
    }
    return pos;
}
