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

#include <sstream>

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
    std::string msg;
    std::string range_proof;
    std::string signature;
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



static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
static CryptoPP::SHA512   _sha512;
static CryptoPP::SHA256   _sha256;

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

Confidential build_confidential_tx(std::string A_p, std::string B_p, std::string value_str, std::string asset_str, std::string msg, bool generate_range_proof)
{
    int ok = 1;

    auto value = std::stoull(value_str);
    auto asset = std::stoull(asset_str);

    if(not asset)
        return {};

    auto to_pubkey = [&](std::string const &pk_str) {
        secp256k1_pubkey pk;
        auto             pk_v = from_hex(pk_str);
        ok &= secp256k1_ec_pubkey_parse(ctx, &pk, pk_v.data( ), sizeof(public_key_t));
        return pk;
    };


    secp256k1_pubkey               _tx_key_p, _A_p = to_pubkey(A_p), _B_p = to_pubkey(B_p);
    CryptoPP::AutoSeededRandomPool rng;

    size_t sz = PK_SZ;

    private_key_t tx_key_s;
    public_key_t  tx_key_p;

    rng.GenerateBlock(tx_key_s, sizeof(tx_key_s));

    ok &= secp256k1_ec_pubkey_create(ctx, &_tx_key_p, tx_key_s);
    ok &= secp256k1_ec_pubkey_serialize(ctx, tx_key_p, &sz, &_tx_key_p, SECP256K1_EC_COMPRESSED);

    CryptoPP::byte nonce[CryptoPP::SHA256::DIGESTSIZE];
    sha256(nonce, tx_key_s, SK_SZ);

    shared_secret_t shared_secret_a;
    ok &= generate_shared_secret(shared_secret_a, _A_p, tx_key_s);


    blind_factor_t addr_blind;
    sha256(addr_blind, shared_secret_a, sizeof(shared_secret_a));

    secp256k1_pubkey _P_p = _B_p;
    public_key_t     P_p;

    ok &= secp256k1_ec_pubkey_tweak_add(ctx, &_P_p, addr_blind);
    ok &= secp256k1_ec_pubkey_serialize(ctx, P_p, &sz, &_P_p, SECP256K1_EC_COMPRESSED);

    shared_secret_t shared_secret_b;
    ok &= generate_shared_secret(shared_secret_b, _B_p, tx_key_s);


    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes;
    aes.SetKeyWithIV(shared_secret_b, 32, &shared_secret_b[32]);

    CryptoPP::byte encrypted_data[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::byte plain_data[CryptoPP::AES::BLOCKSIZE];
    memset(plain_data, CryptoPP::AES::BLOCKSIZE - sizeof(value), sizeof(plain_data));
    memcpy(plain_data, &value, sizeof(value));
    aes.ProcessData(encrypted_data, plain_data, sizeof(plain_data));


    std::string msg_cypher;

    if(not msg.empty( ))
    {
        if(msg.size( ) > 160)
            msg.resize(160);

        auto pad = CryptoPP::AES::BLOCKSIZE - msg.size( ) % CryptoPP::AES::BLOCKSIZE;
        msg.resize(msg.size( ) + pad, pad == CryptoPP::AES::BLOCKSIZE ? 0 : pad);

        msg_cypher.resize('\0', msg.size( ));
        aes.ProcessData((CryptoPP::byte *) &msg_cypher[0], (CryptoPP::byte *) msg.data( ), msg.size( ));
    }


    blind_factor_t amount_blind;
    sha256(amount_blind, shared_secret_b, sizeof(shared_secret_b));

    commitment_t commitment;
    ok &= blind(commitment, amount_blind, asset, value);

    size_t        proof_len = 0;
    unsigned char commitment_range_proof[PROOF_SZ];
    memset(commitment_range_proof, 0, PROOF_SZ);
    if(generate_range_proof)
        ok &= range_proof_sign(commitment_range_proof, &proof_len, 0, commitment, amount_blind, nonce, 0, 0, value);


    Confidential r;
    r.tx_key          = to_hex(tx_key_p);
    r.owner           = to_hex(P_p);
    r.blinding_factor = to_hex(amount_blind);
    r.commitment      = to_hex(commitment);
    r.data            = to_hex(encrypted_data);
    r.range_proof     = to_hex(commitment_range_proof).substr(0, 2 * proof_len);
    CryptoPP::StringSource(msg_cypher, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(r.msg), false));

    std::stringstream ss;
    ss << r.tx_key << r.owner << r.blinding_factor << r.commitment << r.data << r.msg << r.range_proof;
    auto          sss = ss.str( );
    unsigned char result_sha256[32];
    sha256(result_sha256, (unsigned char *) sss.data( ), sss.size( ));

    secp256k1_ecdsa_signature sig;
    signature_t               signature;
    ok &= secp256k1_ecdsa_sign(ctx, &sig, result_sha256, tx_key_s, nullptr, nullptr);
    ok &= secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig);
    r.signature = to_hex(signature);

    return r;
}


TX transfer_from_confidential(
    std::string       x_private_a,
    std::string       x_private_b,
    std::vector<Open> x_inputs,
    std::string       x_to_address,
    std::string       to_amount_str,
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

    uint64_t to_amount = std::stoull(to_amount_str);

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

        total_amount_in += std::stoull(in.amount);
    }

    if(total_amount_in > to_amount + std::stoull(fee.base_fee) + 2 * std::stoull(fee.per_out))
    {
        Beneficiary      self;
        secp256k1_pubkey A, B;
        auto             sz = sizeof(public_key_t);
        ok &= secp256k1_ec_pubkey_create(ctx, &A, owner_private_a.data);
        ok &= secp256k1_ec_pubkey_create(ctx, &B, owner_private_b.data);
        ok &= secp256k1_ec_pubkey_serialize(ctx, self.A.data, &sz, &A, SECP256K1_EC_COMPRESSED);
        ok &= secp256k1_ec_pubkey_serialize(ctx, self.B.data, &sz, &B, SECP256K1_EC_COMPRESSED);
        self.confidential_addr = true;

        auto _change = total_amount_in - to_amount - (std::stoull(fee.base_fee) + 2 * std::stoull(fee.per_out));
        self.amount  = _change;
        beneficiaries.push_back(self);
    }
    else if(total_amount_in == to_amount + std::stoull(fee.base_fee) + std::stoull(fee.per_out))
    {
        // DO NOTHING
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

    auto inputs_blinds_n = blinding_factors.size( );
    auto ct_n            = std::count_if(beneficiaries.begin( ), beneficiaries.end( ), [](Beneficiary const &addr) { return addr.confidential_addr; });

    for(auto item : beneficiaries)
    {
        if(item.confidential_addr)
        {
            auto confidential = build_confidential_tx(to_hex(item.A.data), to_hex(item.B.data), std::to_string(item.amount), fee.symbol, "", ct_n > 1);
            result.confidential.push_back(confidential);

            blind_factor_ b;
            memcpy(b.data, from_hex(confidential.blinding_factor).data( ), sizeof(b));
            blinding_factors.push_back(b);
        }
        else
        {
            Open open;
            open.pk     = to_hex(item.A.data);
            open.amount = std::to_string(item.amount);
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

#ifdef __EMSCRIPTEN__
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
        .field("msg", &Confidential::msg)
        .field("range_proof", &Confidential::range_proof)
        .field("signature", &Confidential::signature);

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
    function("build_confidential_tx", &build_confidential_tx);
};
#endif
