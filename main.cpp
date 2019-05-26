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


struct blind_factor_
{
    blind_factor_t data;
};

struct private_key_
{
    private_key_t data;
};

struct public_key_
{
    public_key_t data;
};

static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
static CryptoPP::SHA512   _sha512;
static CryptoPP::SHA256   _sha256;


struct __attribute__((__packed__)) _Confidential
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

static int generate_shared_secret(shared_secret_t shared_secret, secp256k1_pubkey pk, private_key_t sk)
{
    int          ok = 1;
    size_t       sz = PK_SZ;
    public_key_t _pk;
    ok &= secp256k1_ec_pubkey_tweak_mul(ctx, &pk, sk);
    ok &= secp256k1_ec_pubkey_serialize(ctx, _pk, &sz, &pk, SECP256K1_EC_COMPRESSED);

    _sha512.CalculateDigest(shared_secret, &_pk[1], PK_SZ - 1);

    return ok;
}

static void sha256(unsigned char ret[32], unsigned char *data, uint32_t sz)
{
    _sha256.CalculateDigest(ret, data, sz);
}

static void aes_decrypt(CryptoPP::byte *plain_data, CryptoPP::byte *encrypted_data, uint32_t sz, shared_secret_t shared_secret_b)
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

static int blinding_sum(blind_factor_t ret, blind_factor_t blinding_factors[], uint8_t count, uint8_t non_neg_count)
{
    int            ok = 1;
    unsigned char *p_blinding_factors[count]; // using VLA, so we limit the count to max 255

    for(uint8_t i = 0; i < count; ++i)
        p_blinding_factors[i] = (unsigned char *) &blinding_factors[i];

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


static int build_confidential_tx(unsigned char *ret, public_key_t A_p, public_key_t B_p, uint64_t value, uint64_t asset, int generate_range_proof)
{
    int ok = 1;
    memset(ret, 0, sizeof(_Confidential));

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
    sha256(nonce, tx_key_s, SK_SZ);


    ok &= secp256k1_ec_pubkey_parse(ctx, &_A_p, A_p, sizeof(public_key_t));
    shared_secret_t shared_secret_a;
    ok &= generate_shared_secret(shared_secret_a, _A_p, tx_key_s);


    blind_factor_t addr_blind;
    sha256(addr_blind, shared_secret_a, sizeof(shared_secret_a));

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
    sha256(amount_blind, shared_secret_b, sizeof(shared_secret_b));


    commitment_t commitment;
    ok &= blind(commitment, amount_blind, asset, value);

    size_t        proof_len = 0;
    unsigned char commitment_range_proof[PROOF_SZ];
    memset(commitment_range_proof, 0, PROOF_SZ);
    if(generate_range_proof)
        ok &= range_proof_sign(commitment_range_proof, &proof_len, 0, commitment, amount_blind, nonce, 0, 0, value);

    _Confidential result;
    memcpy(&result.T, tx_key_p, sizeof(public_key_t));
    memcpy(&result.P, P_p, sizeof(public_key_t));
    memcpy(&result.B, amount_blind, sizeof(blind_factor_t));
    memcpy(&result.C, commitment, sizeof(commitment_t));
    memcpy(&result.E, encrypted_data, sizeof(encrypted_data));
    memset(&result.S, 0, sizeof(signature_t));
    result.proof_len = proof_len;
    memcpy(&result.commitment_range_proof, commitment_range_proof, proof_len);

    unsigned char result_sha256[32];
    sha256(result_sha256, (unsigned char *) &result, sizeof(_Confidential));

    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_sign(ctx, &sig, result_sha256, tx_key_s, nullptr, nullptr);
    secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char *) &result.S, &sig);

    memcpy(ret, &result, sizeof(_Confidential));
    return (0 == ok);
}

static std::vector<unsigned char> from_hex(std::string const &x_str)
{
    CryptoPP::HexDecoder _xdec;
    _xdec.PutMessageEnd((CryptoPP::byte *) x_str.c_str( ), x_str.size( ));

    size_t size = _xdec.MaxRetrievable( );
    if(size)
    {
        std::vector<unsigned char> result(size);
        _xdec.Get(result.data( ), size);
        return result;
    }
    return {};
}

static uint64_t xstr_to_u64(std::string const &x_str)
{
    uint64_t result = 0;
    auto     v      = from_hex(x_str);
    if(v.size( ) == sizeof(uint64_t))
        memcpy(&result, v.data( ), v.size( ));
    return result;
}

template<typename T, size_t N>
std::string to_hex(T const (&data)[N])
{
    CryptoPP::HexEncoder _xenc(nullptr, false);
    _xenc.PutMessageEnd((CryptoPP::byte *) data, N);

    size_t size = _xenc.MaxRetrievable( );
    if(size)
    {
        std::string result(size, '\0');
        _xenc.Get((CryptoPP::byte *) result.data( ), size);
        return result;
    }
    return {};
}

template<typename T>
std::string to_hex(T const &data)
{
    uint8_t _data[sizeof(T)];
    memcpy(_data, &data, sizeof(T));
    return to_hex(_data);
}

struct Beneficiary
{
    bool        confidential_addr;
    public_key_ A;
    public_key_ B;
    uint64_t    amount;
};

struct Fee
{
    std::string base_fee;
    std::string per_out;
    std::string symbol;
};


struct Confidential
{
    std::string tx_key;
    std::string owner;
    std::string blinding_factor;
    std::string commitment;
    std::string data;
    std::string signature;
    std::string range_proof;
};

struct Open
{
    std::string pk;
    std::string amount;
};

struct TX
{
    std::vector<Confidential> confidential;
    std::vector<Open>         open;
    std::vector<std::string>  unlock_keys;
    std::string               blinding_factor;
};

static Confidential serialize_confidential(_Confidential const &c)
{
    Confidential r;
    r.tx_key          = to_hex(c.T);
    r.owner           = to_hex(c.P);
    r.blinding_factor = to_hex(c.B);
    r.commitment      = to_hex(c.C);
    r.data            = to_hex(c.E);
    r.signature       = to_hex(c.S);
    r.range_proof     = to_hex(c.commitment_range_proof).substr(0, 2 * c.proof_len);
    return r;
}


Confidential build_confidential_tx_(std::string A_p, std::string B_p, std::string value, std::string asset, bool generate_range_proof)
{
    _Confidential confidential;
    memset(&confidential, 0, sizeof(_Confidential));

    auto A = from_hex(A_p);
    auto B = from_hex(B_p);

    auto err = build_confidential_tx((unsigned char *) &confidential, A.data( ), B.data( ), xstr_to_u64(value), xstr_to_u64(asset), generate_range_proof);
    if(err)
        return {};

    return serialize_confidential(confidential);
}


TX transfer_from_confidential(
    std::string       x_private_a,
    std::string       x_private_b,
    std::vector<Open> x_inputs,
    std::string       x_to_address,
    std::string       x_to_amount,
    Fee               fee)
{
    int ok = 1;
    TX  result;

    private_key_ owner_private_a, owner_private_b;
    memcpy(owner_private_a.data, from_hex(x_private_a).data( ), sizeof(owner_private_a));
    memcpy(owner_private_b.data, from_hex(x_private_b).data( ), sizeof(owner_private_b));

    auto to_pubkey = [&](const std::string &x_str) {
        secp256k1_pubkey pk;
        auto             v = from_hex(x_str);
        ok &= secp256k1_ec_pubkey_parse(ctx, &pk, v.data( ), v.size( ));
        return pk;
    };

    std::vector<blind_factor_> blinding_factors;

    std::vector<Beneficiary> beneficiaries;
    uint64_t                 total_amount_in = 0;

    uint64_t to_amount = xstr_to_u64(x_to_amount);

    for(auto &&in : x_inputs)
    {
        shared_secret_t shared_secret_b;
        ok &= generate_shared_secret(shared_secret_b, to_pubkey(in.pk), owner_private_b.data);
        blind_factor_ blind_factor_b;
        sha256(blind_factor_b.data, shared_secret_b, sizeof(shared_secret_b));

        blinding_factors.push_back(blind_factor_b);

        shared_secret_t shared_secret_a;
        ok &= generate_shared_secret(shared_secret_a, to_pubkey(in.pk), owner_private_a.data);
        blind_factor_ blind_factor_a;
        sha256(blind_factor_a.data, shared_secret_a, sizeof(shared_secret_a));

        private_key_ unlock_key = owner_private_b;
        ok &= secp256k1_ec_privkey_tweak_add(ctx, unlock_key.data, blind_factor_a.data);
        result.unlock_keys.push_back(to_hex(unlock_key.data));

        total_amount_in += xstr_to_u64(in.amount);
    }

    if(total_amount_in > to_amount + xstr_to_u64(fee.base_fee) + 2 * xstr_to_u64(fee.per_out))
    {
        Beneficiary      self;
        secp256k1_pubkey A, B;
        auto             sz = sizeof(public_key_t);
        ok &= secp256k1_ec_pubkey_create(ctx, &A, owner_private_a.data);
        ok &= secp256k1_ec_pubkey_create(ctx, &B, owner_private_b.data);
        ok &= secp256k1_ec_pubkey_serialize(ctx, self.A.data, &sz, &A, SECP256K1_EC_COMPRESSED);
        ok &= secp256k1_ec_pubkey_serialize(ctx, self.B.data, &sz, &B, SECP256K1_EC_COMPRESSED);
        self.confidential_addr = true;

        auto _change = total_amount_in - to_amount - (xstr_to_u64(fee.base_fee) + 2 * xstr_to_u64(fee.per_out));
        self.amount  = _change;
        beneficiaries.push_back(self);
    }
    else if(total_amount_in == to_amount + xstr_to_u64(fee.base_fee) + xstr_to_u64(fee.per_out))
    {
    }
    else
    {
        return {};
    }
    {
        Beneficiary beneficiary;
        auto        to_address        = from_hex(x_to_address);
        beneficiary.confidential_addr = to_address.size( ) > sizeof(public_key_t);
        memcpy(&beneficiary.A, to_address.data( ), sizeof(public_key_t));
        if(beneficiary.confidential_addr)
            memcpy(&beneficiary.B, to_address.data( ) + sizeof(public_key_t), sizeof(public_key_t));
        else
            memset(&beneficiary.B, 0, sizeof(public_key_t));
        beneficiary.amount = to_amount;
        beneficiaries.push_back(beneficiary);
    }


    auto     inputs_blinds_n = blinding_factors.size( );
    auto     ct_n            = std::count_if(beneficiaries.begin( ), beneficiaries.end( ), [](Beneficiary const &addr) { return addr.confidential_addr; });
    uint64_t symbol          = xstr_to_u64(fee.symbol);

    for(auto item : beneficiaries)
    {
        _Confidential _confidential;
        memset(&_confidential, 0, sizeof(_Confidential));

        if(item.confidential_addr)
        {
            ok &= not build_confidential_tx((unsigned char *) &_confidential, item.A.data, item.B.data, item.amount, symbol, ct_n > 1);
            auto confidential = serialize_confidential(_confidential);
            result.confidential.push_back(confidential);
            blind_factor_ b;
            memcpy(b.data, _confidential.B, sizeof(b));
            blinding_factors.push_back(b);
        }
        else
        {
            Open open;
            open.pk     = to_hex(item.A.data);
            open.amount = to_hex(item.amount);
            result.open.push_back(open);
        }
    }
    /** commitments must be in sorted order */
    std::sort(result.confidential.begin( ), result.confidential.end( ), [&](const Confidential &a, const Confidential &b) {
        return std::strcmp(a.commitment.c_str( ), b.commitment.c_str( )) < 0;
    });

    blind_factor_ blind_tot;
    ok &= blinding_sum(blind_tot.data, (blind_factor_t *) blinding_factors.data( ), blinding_factors.size( ), inputs_blinds_n);


    result.blinding_factor = to_hex(blind_tot.data);

    return result;
}

#ifndef __EMSCRIPTEN__
int main( )
{
    auto              sk_a   = "6babf77576c6cb7d826aadd8e8ede226cdb0ef6e5354bc3727fdd5a037241297";
    auto              sk_b   = "2f34e549de26c62551b842cf41abc823c2251fc7fe2088c226597bf5530a0894";
    std::vector<Open> inputs = {
        {"02731eddfd05bfe197c7a1045a9274365cfe801b2bec8cad62347668a41fbc40be", "00e1f50500000000"},
        {"021369a0e9d3677c722ead0f574960c2ab12a9a2fd9ccfa22e9bae0e27c75f1a7c", "00e1f50500000000"},
        {"020d1df59b6e5851497412b02e860d0307dfe7664bcca39358cd09148faf2b2384", "00e1f50500000000"},
        {"0233c1d0eae54c1271dceb2b68edaded9902290016b147ab39486c854835218634", "00e1f50500000000"},
        {"0397a90439d0003ab1bf8ecf4c8060be74d23e6cc1d9d87a66986201629cfbca7d", "008c864700000000"},
        {"02877e0ca5cade7628d16e4dbe7b7824a1d03d953189cae3ec9ee9f2cd90277ca2", "80c3c90100000000"},
        {"0335df3526253b5a51cecdb26ffa9571b892e43ed6232de99c348aac44ae501ad0", "80f0fa0200000000"},
        {"0260b685d04633c4aed884a653c2cd74c932ae5b28888d4d56464deaa9dee00889", "00e1f50500000000"},
        {"02f943addec9a3e9e974445ad78f1fec6ce0866014de92c5cbb6bc9f82ef7fff01", "00e1f50500000000"},
        {"030cd52118e6ad8a1f47d9006d19b4dfb4bb707eccae996cd29444279a21f2ddaf", "00e1f50500000000"}};

    auto pk = "0374e2394e9d3d09a2e30e18fd377d1affb3051e00cd126d0caebe1f4c668f2f9802677b3403c80cb32b88e58e43cbbba358e5ad3b57e7cce3207d6c3d030c01b4d1";


    auto r = transfer_from_confidential(sk_a, sk_b, inputs, pk, "00e1f50500000000", {"404b4c0000000000", "404b4c0000000000", "0000000000000301"});
    return 0;
}
#else
#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(cryptojs)
{
    value_object<Confidential>("Confidential")
        .field("tx_key", &Confidential::tx_key)
        .field("owner", &Confidential::owner)
        .field("blinding_factor", &Confidential::blinding_factor)
        .field("commitment", &Confidential::commitment)
        .field("data", &Confidential::data)
        .field("signature", &Confidential::signature)
        .field("range_proof", &Confidential::range_proof);

    value_object<Open>("Open")
        .field("pk", &Open::pk)
        .field("amount", &Open::amount);

    value_object<Fee>("Fee")
        .field("base_fee", &Fee::base_fee)
        .field("per_out", &Fee::per_out)
        .field("symbol", &Fee::symbol);

    value_object<TX>("TX")
        .field("blinding_factor", &TX::blinding_factor)
        .field("confidential", &TX::confidential)
        .field("open", &TX::open)
        .field("unlock_keys", &TX::unlock_keys);

    register_vector<TX>("vector<TX>");
    register_vector<Confidential>("vector<Confidential>");
    register_vector<Open>("vector<Open>");
    register_vector<std::string>("vector<string>");

    function("transfer_from_confidential", &transfer_from_confidential);
    function("build_confidential_tx_", &build_confidential_tx_);
};
#endif
