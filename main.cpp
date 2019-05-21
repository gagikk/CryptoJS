#include <secp256k1.h>
#include <secp256k1_rangeproof.h>

#include <cryptopp/config.h>
#ifndef CRYPTOPP_NO_GLOBAL_BYTE
namespace CryptoPP
{
    typedef unsigned char byte;
}
#endif

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>



/*
static auto build_confidential_tx = [](const string &A_, const string &B_, asset val, bool generate_range_proof)
{
    auto tx_key_s = fc::ecc::private_key::generate();
    auto tx_key_p = tx_key_s.get_public_key();
    auto T_ = public_key_type(tx_key_p);
    fc::ecc::public_key A = public_key_type(A_);
    fc::ecc::public_key B = public_key_type(B_);

    auto nonce = fc::sha256::hash(tx_key_s.get_secret());
    auto addr_blind = fc::sha256::hash(tx_key_s.get_shared_secret(A));
    auto P = B.add(addr_blind);
    auto P_ = public_key_type(P);

    auto shared_secret = tx_key_s.get_shared_secret(B);
    auto blind_factor = fc::sha256::hash(shared_secret);

    auto data = fc::aes_encrypt(shared_secret, fc::raw::pack(val.amount.value));
    auto commitment = fc::ecc::blind( blind_factor, uint64_t(val.asset_id), val.amount.value);

    optional<vector<char>> commitment_range_proof;
    if(generate_range_proof)
        commitment_range_proof = fc::ecc::range_proof_sign( 0, commitment, blind_factor, nonce,  0, 0, val.amount.value);
    return make_tuple(T_, P_, blind_factor, commitment, data, commitment_range_proof, tx_key_s);
};
*/

#define SK_SZ 32
#define PK_SZ 33
#define SIG_SZ 64
#define PROOF_SZ 5134

using blind_factor_t  = unsigned char[SK_SZ];
using private_key_t   = unsigned char[SK_SZ];
using signature_t     = unsigned char[SIG_SZ];
using public_key_t    = unsigned char[PK_SZ];
using commitment_t    = unsigned char[PK_SZ];
using shared_secret_t = unsigned char[CryptoPP::SHA512::DIGESTSIZE];

static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
static CryptoPP::SHA512   _sha512;
static CryptoPP::SHA256   _sha256;


struct __attribute__((__packed__)) Ret
{
    public_key_t   T;
    public_key_t   P;
    blind_factor_t B;
    commitment_t   C;
    CryptoPP::byte E[CryptoPP::AES::BLOCKSIZE];
    signature_t    S;
    size_t         proof_len;
    unsigned char  commitment_range_proof[PROOF_SZ];
};

extern "C"
{
    int __attribute__((used)) build_confidential_tx(unsigned char *ret, public_key_t A_p, public_key_t B_p, uint64_t value, uint64_t asset, int generate_range_proof);
    uint32_t __attribute__((used, const)) sizeofRet( ) { return sizeof(Ret); }
    int __attribute__((used)) blinding_sum(blind_factor_t ret, blind_factor_t blinding_factors[], uint8_t count, uint8_t non_neg_count);
    void __attribute__((used)) sha256(unsigned char ret[32], unsigned char *data, uint32_t sz);
    void __attribute__((used)) aes_decrypt(CryptoPP::byte *plain_data, CryptoPP::byte *encrypted_data, uint32_t sz, shared_secret_t shared_secret_b);
    int __attribute__((used)) generate_shared_secret(shared_secret_t shared_secret, secp256k1_pubkey pk, private_key_t sk);
}

int generate_shared_secret(shared_secret_t shared_secret, secp256k1_pubkey pk, private_key_t sk)
{
    int          ok = 1;
    size_t       sz = PK_SZ;
    public_key_t _pk;
    ok &= secp256k1_ec_pubkey_tweak_mul(ctx, &pk, sk);
    ok &= secp256k1_ec_pubkey_serialize(ctx, _pk, &sz, &pk, SECP256K1_EC_COMPRESSED);

    _sha512.CalculateDigest(shared_secret, &_pk[1], PK_SZ - 1);

    return ok;
}

void sha256(unsigned char ret[32], unsigned char *data, uint32_t sz)
{
    _sha256.CalculateDigest(ret, data, sz);
}

void aes_decrypt(CryptoPP::byte *plain_data, CryptoPP::byte *encrypted_data, uint32_t sz, shared_secret_t shared_secret_b)
{
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes;
    aes.SetKeyWithIV(shared_secret_b, 32, &shared_secret_b[32]);
    aes.ProcessData(plain_data, encrypted_data, sz);
}

static int blind(commitment_t commitment, blind_factor_t const blind_factor, uint64_t const value)
{
    int                           ok = 1;
    secp256k1_pedersen_commitment _commit;
    ok &= secp256k1_pedersen_commit(ctx, &_commit, blind_factor, value, secp256k1_generator_h);
    ok &= secp256k1_pedersen_commitment_serialize(ctx, commitment, &_commit);
    return ok;
}

static int blind(commitment_t commitment, blind_factor_t const blind_factor, uint64_t const blind_tweak, uint64_t const value)
{
    int ok = 1;
    if(!blind_tweak)
        return 0;

    blind_factor_t _blind_tweak, _blind_factor_tweaked;
    memset(_blind_tweak, 0, sizeof(_blind_tweak));
    memcpy(_blind_tweak, &blind_tweak, sizeof(blind_tweak));

    memcpy(_blind_factor_tweaked, blind_factor, sizeof(_blind_factor_tweaked));
    ok &= secp256k1_ec_privkey_tweak_mul(ctx, _blind_factor_tweaked, _blind_tweak);
    ok &= blind(commitment, _blind_factor_tweaked, value);

    return ok;
}

int blinding_sum(blind_factor_t ret, blind_factor_t blinding_factors[], uint8_t count, uint8_t non_neg_count)
{
    int ok = 1;

    unsigned char *p_blinding_factors[count]; // using VLA, so we limit the count to max 255
    for(uint8_t i = 0; i < count; ++i)
        p_blinding_factors[i] = blinding_factors[i];
    ok &= secp256k1_pedersen_blind_sum(ctx, ret, p_blinding_factors, count, non_neg_count);

    return ok;
}

static int range_proof_sign(unsigned char proof[PROOF_SZ], size_t *proof_len, uint64_t min_value, commitment_t commit, const blind_factor_t commit_blind, const blind_factor_t nonce, int8_t base10_exp, uint8_t min_bits, uint64_t actual_value)
{
    int ok     = 1;
    *proof_len = PROOF_SZ;

    secp256k1_pedersen_commitment _commit;
    ok &= secp256k1_pedersen_commitment_parse(ctx, &_commit, commit);
    ok &= secp256k1_rangeproof_sign(ctx, proof, proof_len,
                                    min_value,
                                    &_commit,
                                    commit_blind,
                                    nonce,
                                    base10_exp,
                                    min_bits,
                                    actual_value,
                                    nullptr, 0, nullptr, 0,
                                    secp256k1_generator_h);
    return ok;
}


int build_confidential_tx(unsigned char *ret, public_key_t A_p, public_key_t B_p, uint64_t value, uint64_t asset, int generate_range_proof)
{
    int ok = 1;
    memset(ret, 0, sizeofRet( ));

    if(!asset)
        return 1;

    secp256k1_pubkey               _tx_key_p, _A_p, _B_p;
    CryptoPP::AutoSeededRandomPool rng;

    size_t sz = PK_SZ;

    private_key_t tx_key_s;
    public_key_t  tx_key_p;

    rng.GenerateBlock(tx_key_s, sizeof(tx_key_s));

    ok &= secp256k1_ec_pubkey_create(ctx, &_tx_key_p, tx_key_s);
    ok &= secp256k1_ec_pubkey_serialize(ctx, tx_key_p, &sz, &_tx_key_p, SECP256K1_EC_COMPRESSED);

    CryptoPP::byte nonce[CryptoPP::SHA256::DIGESTSIZE];
    _sha256.CalculateDigest(nonce, tx_key_s, SK_SZ);


    ok &= secp256k1_ec_pubkey_parse(ctx, &_A_p, A_p, sizeof(public_key_t));
    shared_secret_t shared_secret_a;
    ok &= generate_shared_secret(shared_secret_a, _A_p, tx_key_s);


    blind_factor_t addr_blind;
    _sha256.CalculateDigest(addr_blind, shared_secret_a, sizeof(shared_secret_a));

    secp256k1_pubkey _P_p;
    public_key_t     P_p;

    ok &= secp256k1_ec_pubkey_parse(ctx, &_P_p, B_p, sizeof(public_key_t));
    ok &= secp256k1_ec_pubkey_tweak_add(ctx, &_P_p, addr_blind);
    ok &= secp256k1_ec_pubkey_serialize(ctx, P_p, &sz, &_P_p, SECP256K1_EC_COMPRESSED);

    ok &= secp256k1_ec_pubkey_parse(ctx, &_B_p, B_p, sizeof(public_key_t));
    shared_secret_t shared_secret_b;
    ok &= generate_shared_secret(shared_secret_b, _B_p, tx_key_s);


    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes;
    aes.SetKeyWithIV(shared_secret_b, 32, &shared_secret_b[32]);

    CryptoPP::byte encrypted_data[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::byte plain_data[CryptoPP::AES::BLOCKSIZE];
    memset(plain_data, CryptoPP::AES::BLOCKSIZE - sizeof(value), sizeof(plain_data));
    memcpy(plain_data, &value, sizeof(value));
    aes.ProcessData(encrypted_data, plain_data, sizeof(plain_data));

    blind_factor_t amount_blind;
    _sha256.CalculateDigest(amount_blind, shared_secret_b, sizeof(shared_secret_b));


    commitment_t commitment;
    ok &= blind(commitment, amount_blind, asset, value);

    size_t        proof_len = 0;
    unsigned char commitment_range_proof[PROOF_SZ];
    memset(commitment_range_proof, 0, PROOF_SZ);
    if(generate_range_proof)
        ok &= range_proof_sign(commitment_range_proof, &proof_len, 0, commitment, amount_blind, nonce, 0, 0, value);

    Ret result;
    memcpy(&result.T, tx_key_p, sizeof(public_key_t));
    memcpy(&result.P, P_p, sizeof(public_key_t));
    memcpy(&result.B, amount_blind, sizeof(blind_factor_t));
    memcpy(&result.C, commitment, sizeof(commitment_t));
    memcpy(&result.E, encrypted_data, sizeof(encrypted_data));
    memset(&result.S, 0, sizeof(signature_t));
    result.proof_len = proof_len;
    memcpy(&result.commitment_range_proof, commitment_range_proof, proof_len);

    unsigned char result_sha256[32];
    _sha256.CalculateDigest(result_sha256, (unsigned char *) &result, sizeof(Ret));

    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_sign(ctx, &sig, result_sha256, tx_key_s, nullptr, nullptr);
    secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char *) &result.S, &sig);

    memcpy(ret, &result, sizeof(Ret));
    return (0 == ok);
}
