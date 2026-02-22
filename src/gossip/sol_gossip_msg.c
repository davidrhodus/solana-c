/*
 * sol_gossip_msg.c - Gossip protocol message implementation
 */

#include "sol_gossip_msg.h"
#include "../util/sol_alloc.h"
#include "../crypto/sol_sha256.h"
#include "../crypto/sol_ed25519.h"
#include "../txn/sol_transaction.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>

/*
 * FNV-1a hash with seed
 */
static uint64_t
fnv1a_hash(const uint8_t* data, size_t len, uint64_t seed) {
    uint64_t hash = 14695981039346656037ULL ^ seed;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void
sol_bloom_init(sol_bloom_t* bloom) {
    if (!bloom) return;

    memset(bloom->bits, 0, sizeof(bloom->bits));
    bloom->num_bits_set = 0;

    /* Initialize hash seeds with pseudo-random values */
    uint64_t seed = 0x123456789ABCDEF0ULL;
    for (int i = 0; i < SOL_BLOOM_NUM_KEYS; i++) {
        bloom->keys[i] = seed;
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    }
}

void
sol_bloom_add(sol_bloom_t* bloom, const uint8_t* data, size_t len) {
    if (!bloom || !data) return;

    uint32_t num_bits = SOL_BLOOM_BITS_SIZE * 8;

    for (int i = 0; i < SOL_BLOOM_NUM_KEYS; i++) {
        uint64_t hash = fnv1a_hash(data, len, bloom->keys[i]);
        uint32_t bit_idx = hash % num_bits;
        uint32_t byte_idx = bit_idx / 8;
        uint8_t bit_mask = 1 << (bit_idx % 8);

        if (!(bloom->bits[byte_idx] & bit_mask)) {
            bloom->bits[byte_idx] |= bit_mask;
            bloom->num_bits_set++;
        }
    }
}

bool
sol_bloom_contains(const sol_bloom_t* bloom, const uint8_t* data, size_t len) {
    if (!bloom || !data) return false;

    uint32_t num_bits = SOL_BLOOM_BITS_SIZE * 8;

    for (int i = 0; i < SOL_BLOOM_NUM_KEYS; i++) {
        uint64_t hash = fnv1a_hash(data, len, bloom->keys[i]);
        uint32_t bit_idx = hash % num_bits;
        uint32_t byte_idx = bit_idx / 8;
        uint8_t bit_mask = 1 << (bit_idx % 8);

        if (!(bloom->bits[byte_idx] & bit_mask)) {
            return false;
        }
    }

    return true;
}

void
sol_bloom_clear(sol_bloom_t* bloom) {
    if (!bloom) return;
    memset(bloom->bits, 0, sizeof(bloom->bits));
    bloom->num_bits_set = 0;
}

static inline uint64_t
load_le64(const uint8_t* data) {
    return ((uint64_t)data[0]) |
           ((uint64_t)data[1] << 8) |
           ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) |
           ((uint64_t)data[4] << 32) |
           ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) |
           ((uint64_t)data[7] << 56);
}

static inline void
store_le64(uint8_t* data, uint64_t val) {
    data[0] = (uint8_t)(val);
    data[1] = (uint8_t)(val >> 8);
    data[2] = (uint8_t)(val >> 16);
    data[3] = (uint8_t)(val >> 24);
    data[4] = (uint8_t)(val >> 32);
    data[5] = (uint8_t)(val >> 40);
    data[6] = (uint8_t)(val >> 48);
    data[7] = (uint8_t)(val >> 56);
}

void
sol_pull_request_init(sol_pull_request_t* req) {
    if (!req) return;
    memset(req, 0, sizeof(*req));
    sol_bloom_init(&req->filter.filter);
    req->filter.mask = 0;
    req->filter.mask_bits = 0;
}

void
sol_push_msg_init(sol_push_msg_t* msg) {
    if (!msg) return;
    memset(msg, 0, sizeof(*msg));
}

static void
sol_ping_pong_hash(const uint8_t* token, size_t token_len, sol_sha256_t* out) {
    static const uint8_t prefix[] = "SOLANA_PING_PONG";
    const void* parts[] = {prefix, token};
    const size_t lens[] = {sizeof(prefix) - 1u, token_len};
    sol_sha256_multi(parts, lens, 2, out);
}

sol_err_t
sol_ping_create(
    sol_ping_t*          ping,
    const sol_pubkey_t*  from,
    const uint8_t        token[32]
) {
    if (!ping || !from || !token) {
        return SOL_ERR_INVAL;
    }

    sol_pubkey_copy(&ping->from, from);
    memcpy(ping->token.bytes, token, 32);

    /* Note: Signature would be created by the caller with the private key */
    memset(&ping->signature, 0, sizeof(ping->signature));

    return SOL_OK;
}

sol_err_t
sol_pong_create(
    sol_pong_t*         pong,
    const sol_pubkey_t* from,
    const sol_ping_t*   ping
) {
    if (!pong || !from || !ping) {
        return SOL_ERR_INVAL;
    }

    sol_pubkey_copy(&pong->from, from);

    /* Hash the ping token */
    sol_sha256_t sha_hash;
    sol_ping_pong_hash(ping->token.bytes, sizeof(ping->token.bytes), &sha_hash);
    memcpy(pong->hash.bytes, sha_hash.bytes, 32);

    /* Note: Signature would be created by the caller with the private key */
    memset(&pong->signature, 0, sizeof(pong->signature));

    return SOL_OK;
}

void
sol_ping_sign(sol_ping_t* ping, const sol_keypair_t* keypair) {
    if (!ping || !keypair) return;

    /* Sign the token using the keypair */
    sol_ed25519_sign(keypair, ping->token.bytes, 32, &ping->signature);
}

void
sol_pong_sign(sol_pong_t* pong, const sol_keypair_t* keypair) {
    if (!pong || !keypair) return;

    /* Sign the hash using the keypair */
    sol_ed25519_sign(keypair, pong->hash.bytes, 32, &pong->signature);
}

bool
sol_ping_verify(const sol_ping_t* ping) {
    if (!ping) return false;

    /* Verify signature over token using ping->from pubkey */
    return sol_ed25519_verify(
        &ping->from,
        ping->token.bytes,
        32,
        &ping->signature
    );
}

bool
sol_pong_verify(const sol_pong_t* pong, const sol_ping_t* ping) {
    if (!pong || !ping) return false;

    /* Verify the hash matches the ping token */
    sol_sha256_t expected;
    sol_ping_pong_hash(ping->token.bytes, sizeof(ping->token.bytes), &expected);

    if (memcmp(pong->hash.bytes, expected.bytes, 32) != 0) {
        return false;
    }

    /* Verify signature over hash using pong->from pubkey */
    return sol_ed25519_verify(
        &pong->from,
        pong->hash.bytes,
        32,
        &pong->signature
    );
}

/*
 * Encode bloom filter
 */
static sol_err_t
encode_bloom(sol_encoder_t* enc, const sol_bloom_t* bloom) {
    /* Keys: Vec<u64> */
    SOL_ENCODE_TRY(sol_encode_u64(enc, (uint64_t)SOL_BLOOM_NUM_KEYS));
    for (int i = 0; i < SOL_BLOOM_NUM_KEYS; i++) {
        SOL_ENCODE_TRY(sol_encode_u64(enc, bloom->keys[i]));
    }

    /* BitVec<u64> */
    const uint64_t blocks_len = (uint64_t)(SOL_BLOOM_BITS_SIZE / 8);
    SOL_ENCODE_TRY(sol_encode_u32(enc, blocks_len ? 1u : 0u)); /* Option tag */
    if (blocks_len) {
        SOL_ENCODE_TRY(sol_encode_u64(enc, blocks_len));
        for (uint64_t i = 0; i < blocks_len; i++) {
            uint64_t block = load_le64(&bloom->bits[i * 8]);
            SOL_ENCODE_TRY(sol_encode_u64(enc, block));
        }
    }
    SOL_ENCODE_TRY(sol_encode_u64(enc, (uint64_t)SOL_BLOOM_BITS_SIZE * 8u));

    /* num_bits_set */
    SOL_ENCODE_TRY(sol_encode_u64(enc, (uint64_t)bloom->num_bits_set));

    return SOL_OK;
}

/*
 * Decode bloom filter
 */
static sol_err_t
decode_bloom(sol_decoder_t* dec, sol_bloom_t* bloom) {
    if (!bloom) return SOL_ERR_INVAL;
    memset(bloom, 0, sizeof(*bloom));

    /* Keys: Vec<u64> */
    uint64_t keys_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &keys_len));
    for (uint64_t i = 0; i < keys_len; i++) {
        uint64_t key = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &key));
        if (i < SOL_BLOOM_NUM_KEYS) {
            bloom->keys[i] = key;
        }
    }

    /* BitVec<u64> */
    uint32_t opt_tag = 0;
    SOL_DECODE_TRY(sol_decode_u32(dec, &opt_tag));
    if (opt_tag == 1u) {
        uint64_t blocks_len = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &blocks_len));
        const uint64_t max_blocks = (uint64_t)(SOL_BLOOM_BITS_SIZE / 8);
        for (uint64_t i = 0; i < blocks_len; i++) {
            uint64_t block = 0;
            SOL_DECODE_TRY(sol_decode_u64(dec, &block));
            if (i < max_blocks) {
                store_le64(&bloom->bits[i * 8], block);
            }
        }
    } else if (opt_tag != 0u) {
        return SOL_ERR_MALFORMED;
    }

    /* Bit length (ignored) */
    uint64_t bit_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &bit_len));
    (void)bit_len;

    /* num_bits_set */
    uint64_t num_bits_set = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &num_bits_set));
    bloom->num_bits_set = (num_bits_set > UINT32_MAX) ? UINT32_MAX : (uint32_t)num_bits_set;

    return SOL_OK;
}

/*
 * Encode CRDS filter
 */
static sol_err_t
encode_crds_filter(sol_encoder_t* enc, const sol_crds_filter_t* filter) {
    SOL_ENCODE_TRY(encode_bloom(enc, &filter->filter));
    SOL_ENCODE_TRY(sol_encode_u64(enc, filter->mask));
    SOL_ENCODE_TRY(sol_encode_u32(enc, filter->mask_bits));
    return SOL_OK;
}

/*
 * Decode CRDS filter
 */
static sol_err_t
decode_crds_filter(sol_decoder_t* dec, sol_crds_filter_t* filter) {
    SOL_DECODE_TRY(decode_bloom(dec, &filter->filter));
    SOL_DECODE_TRY(sol_decode_u64(dec, &filter->mask));
    SOL_DECODE_TRY(sol_decode_u32(dec, &filter->mask_bits));
    return SOL_OK;
}

/*
 * Encode ping message
 */
static sol_err_t
encode_ping(sol_encoder_t* enc, const sol_ping_t* ping) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &ping->from));
    SOL_ENCODE_TRY(sol_encode_bytes(enc, ping->token.bytes, 32));
    SOL_ENCODE_TRY(sol_signature_encode(enc, &ping->signature));
    return SOL_OK;
}

/*
 * Decode ping message
 */
static sol_err_t
decode_ping(sol_decoder_t* dec, sol_ping_t* ping) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &ping->from));

    const uint8_t* token_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &token_data));
    memcpy(ping->token.bytes, token_data, 32);

    SOL_DECODE_TRY(sol_signature_decode(dec, &ping->signature));
    return SOL_OK;
}

/*
 * Encode pong message
 */
static sol_err_t
encode_pong(sol_encoder_t* enc, const sol_pong_t* pong) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &pong->from));
    SOL_ENCODE_TRY(sol_encode_bytes(enc, pong->hash.bytes, 32));
    SOL_ENCODE_TRY(sol_signature_encode(enc, &pong->signature));
    return SOL_OK;
}

/*
 * Decode pong message
 */
static sol_err_t
decode_pong(sol_decoder_t* dec, sol_pong_t* pong) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &pong->from));

    const uint8_t* hash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &hash_data));
    memcpy(pong->hash.bytes, hash_data, 32);

    SOL_DECODE_TRY(sol_signature_decode(dec, &pong->signature));
    return SOL_OK;
}

#define SOL_CONTACT_INFO_MAX_ADDRS 16

static bool
sockaddr_ip_eq(const sol_sockaddr_t* a, const sol_sockaddr_t* b) {
    if (a->addr.sa.sa_family != b->addr.sa.sa_family) return false;
    if (a->addr.sa.sa_family == AF_INET) {
        return memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr, 4) == 0;
    }
    if (a->addr.sa.sa_family == AF_INET6) {
        return memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr, 16) == 0;
    }
    return false;
}

static void
sockaddr_set_port(sol_sockaddr_t* addr, uint16_t port) {
    if (addr->addr.sa.sa_family == AF_INET) {
        addr->addr.sin.sin_port = htons(port);
    } else if (addr->addr.sa.sa_family == AF_INET6) {
        addr->addr.sin6.sin6_port = htons(port);
    }
}

static sol_err_t
encode_ipaddr(sol_encoder_t* enc, const sol_sockaddr_t* addr) {
    if (addr->addr.sa.sa_family == AF_INET) {
        SOL_ENCODE_TRY(sol_encode_u32(enc, 0u));
        SOL_ENCODE_TRY(sol_encode_bytes(enc, (const uint8_t*)&addr->addr.sin.sin_addr, 4));
        return SOL_OK;
    }
    if (addr->addr.sa.sa_family == AF_INET6) {
        SOL_ENCODE_TRY(sol_encode_u32(enc, 1u));
        SOL_ENCODE_TRY(sol_encode_bytes(enc, (const uint8_t*)&addr->addr.sin6.sin6_addr, 16));
        return SOL_OK;
    }
    return SOL_ERR_INVAL;
}

static sol_err_t
decode_ipaddr(sol_decoder_t* dec, sol_sockaddr_t* addr) {
    uint32_t kind = 0;
    SOL_DECODE_TRY(sol_decode_u32(dec, &kind));

    memset(addr, 0, sizeof(*addr));

    if (kind == 0u) {
        addr->addr.sin.sin_family = AF_INET;
        addr->len = sizeof(struct sockaddr_in);
        const uint8_t* ip_data;
        SOL_DECODE_TRY(sol_decode_bytes(dec, 4, &ip_data));
        memcpy(&addr->addr.sin.sin_addr, ip_data, 4);
        return SOL_OK;
    }
    if (kind == 1u) {
        addr->addr.sin6.sin6_family = AF_INET6;
        addr->len = sizeof(struct sockaddr_in6);
        const uint8_t* ip_data;
        SOL_DECODE_TRY(sol_decode_bytes(dec, 16, &ip_data));
        memcpy(&addr->addr.sin6.sin6_addr, ip_data, 16);
        return SOL_OK;
    }
    return SOL_ERR_MALFORMED;
}

/*
 * Decode SocketAddr (bincode)
 */
static sol_err_t
decode_socketaddr_bincode(sol_decoder_t* dec, sol_sockaddr_t* addr) {
    uint32_t kind = 0;
    SOL_DECODE_TRY(sol_decode_u32(dec, &kind));
    memset(addr, 0, sizeof(*addr));
    if (kind == 0u) {
        addr->addr.sin.sin_family = AF_INET;
        addr->len = sizeof(struct sockaddr_in);
        const uint8_t* ip_data;
        SOL_DECODE_TRY(sol_decode_bytes(dec, 4, &ip_data));
        memcpy(&addr->addr.sin.sin_addr, ip_data, 4);
        uint16_t port = 0;
        SOL_DECODE_TRY(sol_decode_u16(dec, &port));
        addr->addr.sin.sin_port = htons(port);
        return SOL_OK;
    }
    if (kind == 1u) {
        addr->addr.sin6.sin6_family = AF_INET6;
        addr->len = sizeof(struct sockaddr_in6);
        const uint8_t* ip_data;
        SOL_DECODE_TRY(sol_decode_bytes(dec, 16, &ip_data));
        memcpy(&addr->addr.sin6.sin6_addr, ip_data, 16);
        uint16_t port = 0;
        SOL_DECODE_TRY(sol_decode_u16(dec, &port));
        addr->addr.sin6.sin6_port = htons(port);
        SOL_DECODE_TRY(sol_decode_u32(dec, &addr->addr.sin6.sin6_flowinfo));
        SOL_DECODE_TRY(sol_decode_u32(dec, &addr->addr.sin6.sin6_scope_id));
        return SOL_OK;
    }
    return SOL_ERR_MALFORMED;
}

/*
 * Encode contact info
 */
static sol_err_t
encode_contact_info(sol_encoder_t* enc, const sol_contact_info_t* ci) {
    if (!ci) return SOL_ERR_INVAL;

    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &ci->pubkey));
    SOL_ENCODE_TRY(sol_encode_var_u64(enc, ci->wallclock));
    SOL_ENCODE_TRY(sol_encode_u64(enc, ci->outset));
    SOL_ENCODE_TRY(sol_encode_u16(enc, ci->shred_version));

    SOL_ENCODE_TRY(sol_encode_var_u16(enc, ci->version.major));
    SOL_ENCODE_TRY(sol_encode_var_u16(enc, ci->version.minor));
    SOL_ENCODE_TRY(sol_encode_var_u16(enc, ci->version.patch));
    SOL_ENCODE_TRY(sol_encode_u32(enc, ci->version.commit));
    SOL_ENCODE_TRY(sol_encode_u32(enc, ci->version.feature_set));
    SOL_ENCODE_TRY(sol_encode_var_u16(enc, ci->version.client));

    sol_sockaddr_t addrs[SOL_CONTACT_INFO_MAX_ADDRS];
    uint8_t addrs_len = 0;

    typedef struct {
        uint16_t port;
        uint8_t  key;
        uint8_t  index;
    } sol_socket_enc_t;

    sol_socket_enc_t sockets[SOL_MAX_SOCKETS];
    size_t sockets_len = 0;

    for (uint8_t i = 0; i < ci->num_sockets; i++) {
        const sol_sockaddr_t* addr = &ci->sockets[i].addr;
        if (addr->addr.sa.sa_family != AF_INET && addr->addr.sa.sa_family != AF_INET6) {
            continue;
        }
        uint16_t port = sol_sockaddr_port(addr);
        if (port == 0) continue;

        uint8_t idx = 0;
        bool found = false;
        for (uint8_t j = 0; j < addrs_len; j++) {
            if (sockaddr_ip_eq(addr, &addrs[j])) {
                idx = j;
                found = true;
                break;
            }
        }
        if (!found) {
            if (addrs_len >= SOL_CONTACT_INFO_MAX_ADDRS) {
                continue;
            }
            addrs[addrs_len] = *addr;
            sockaddr_set_port(&addrs[addrs_len], 0);
            idx = addrs_len++;
        }

        sockets[sockets_len].port = port;
        sockets[sockets_len].key = ci->sockets[i].tag;
        sockets[sockets_len].index = idx;
        sockets_len++;
    }

    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, addrs_len));
    for (uint8_t i = 0; i < addrs_len; i++) {
        SOL_ENCODE_TRY(encode_ipaddr(enc, &addrs[i]));
    }

    if (sockets_len > 1) {
        for (size_t i = 0; i < sockets_len - 1; i++) {
            for (size_t j = i + 1; j < sockets_len; j++) {
                if (sockets[j].port < sockets[i].port ||
                    (sockets[j].port == sockets[i].port && sockets[j].key < sockets[i].key)) {
                    sol_socket_enc_t tmp = sockets[i];
                    sockets[i] = sockets[j];
                    sockets[j] = tmp;
                }
            }
        }
    }

    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, (uint16_t)sockets_len));
    uint16_t prev_port = 0;
    for (size_t i = 0; i < sockets_len; i++) {
        uint16_t port = sockets[i].port;
        if (port < prev_port) return SOL_ERR_ENCODE;
        uint16_t offset = (uint16_t)(port - prev_port);
        SOL_ENCODE_TRY(sol_encode_u8(enc, sockets[i].key));
        SOL_ENCODE_TRY(sol_encode_u8(enc, sockets[i].index));
        SOL_ENCODE_TRY(sol_encode_var_u16(enc, offset));
        prev_port = port;
    }

    /* Extensions (TLV list). We currently emit none. */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, 0));

    return SOL_OK;
}

/*
 * Decode contact info
 */
static sol_err_t
decode_contact_info(sol_decoder_t* dec, sol_contact_info_t* ci) {
    sol_contact_info_init(ci);

    SOL_DECODE_TRY(sol_pubkey_decode(dec, &ci->pubkey));
    SOL_DECODE_TRY(sol_decode_var_u64(dec, &ci->wallclock));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ci->outset));
    SOL_DECODE_TRY(sol_decode_u16(dec, &ci->shred_version));

    SOL_DECODE_TRY(sol_decode_var_u16(dec, &ci->version.major));
    SOL_DECODE_TRY(sol_decode_var_u16(dec, &ci->version.minor));
    SOL_DECODE_TRY(sol_decode_var_u16(dec, &ci->version.patch));
    SOL_DECODE_TRY(sol_decode_u32(dec, &ci->version.commit));
    SOL_DECODE_TRY(sol_decode_u32(dec, &ci->version.feature_set));
    SOL_DECODE_TRY(sol_decode_var_u16(dec, &ci->version.client));

    uint16_t addrs_len = 0;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &addrs_len));
    if (addrs_len > SOL_CONTACT_INFO_MAX_ADDRS) {
        return SOL_ERR_MALFORMED;
    }

    sol_sockaddr_t addrs[SOL_CONTACT_INFO_MAX_ADDRS];
    for (uint16_t i = 0; i < addrs_len; i++) {
        SOL_DECODE_TRY(decode_ipaddr(dec, &addrs[i]));
    }

    uint16_t sockets_len = 0;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &sockets_len));
    if (sockets_len > SOL_MAX_SOCKETS) {
        return SOL_ERR_MALFORMED;
    }

    uint16_t port = 0;
    for (uint16_t i = 0; i < sockets_len; i++) {
        uint8_t key = 0;
        uint8_t index = 0;
        uint16_t offset = 0;
        SOL_DECODE_TRY(sol_decode_u8(dec, &key));
        SOL_DECODE_TRY(sol_decode_u8(dec, &index));
        SOL_DECODE_TRY(sol_decode_var_u16(dec, &offset));
        if ((uint32_t)port + (uint32_t)offset > 0xFFFFu) {
            return SOL_ERR_MALFORMED;
        }
        port = (uint16_t)(port + offset);

        if (key >= SOL_MAX_SOCKETS || index >= addrs_len) {
            continue;
        }

        sol_sockaddr_t addr = addrs[index];
        sockaddr_set_port(&addr, port);
        (void)sol_contact_info_add_socket(ci, (sol_socket_tag_t)key, &addr);
    }

    /* Decode and discard extensions. */
    uint16_t ext_len = 0;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &ext_len));
    for (uint16_t i = 0; i < ext_len; i++) {
        uint8_t typ = 0;
        SOL_DECODE_TRY(sol_decode_u8(dec, &typ));
        const uint8_t* bytes = NULL;
        size_t bytes_len = 0;
        SOL_DECODE_TRY(sol_decode_bytes_prefixed(dec, &bytes, &bytes_len));
        (void)typ;
        (void)bytes;
        (void)bytes_len;
    }

    return SOL_OK;
}

static sol_err_t
skip_bytes_len(sol_decoder_t* dec, uint64_t len) {
    if (len > SIZE_MAX) return SOL_ERR_MALFORMED;
    if (!sol_decoder_has(dec, (size_t)len)) return SOL_ERR_DECODE;
    dec->pos += (size_t)len;
    return SOL_OK;
}

static sol_err_t
skip_vec_slots(sol_decoder_t* dec, uint64_t len) {
    for (uint64_t i = 0; i < len; i++) {
        uint64_t slot = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &slot));
    }
    return SOL_OK;
}

static sol_err_t
decode_transaction_skip(sol_decoder_t* dec) {
    sol_transaction_t tx;
    sol_err_t err = sol_transaction_decode(dec->data + dec->pos,
                                           dec->len - dec->pos,
                                           &tx);
    if (err != SOL_OK) return err;
    if (!sol_decoder_has(dec, tx.encoded_len)) return SOL_ERR_DECODE;
    dec->pos += tx.encoded_len;
    return SOL_OK;
}

static sol_err_t
decode_bitvec_u8_lsb0_skip(sol_decoder_t* dec) {
    /* BitVec is serialized as BitSlice: (BitPtr, len) */
    uint64_t ptr = 0;
    uint8_t head = 0;
    uint64_t bits = 0;
    uint64_t len = 0;

    SOL_DECODE_TRY(sol_decode_u64(dec, &ptr));
    SOL_DECODE_TRY(sol_decode_u8(dec, &head));
    SOL_DECODE_TRY(sol_decode_u64(dec, &bits));
    SOL_DECODE_TRY(sol_decode_u64(dec, &len));
    (void)ptr;
    (void)head;
    (void)bits;
    (void)len;
    return SOL_OK;
}

/*
 * Decode CRDS vote (skip transaction payload)
 */
static sol_err_t
decode_crds_vote(sol_decoder_t* dec, sol_crds_vote_t* vote) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &vote->from));
    SOL_DECODE_TRY(decode_transaction_skip(dec));
    SOL_DECODE_TRY(sol_decode_u64(dec, &vote->wallclock));
    vote->slot = 0;
    memset(vote->hash.bytes, 0, sizeof(vote->hash.bytes));
    vote->timestamp = 0;
    return SOL_OK;
}

/*
 * Encode CRDS lowest slot (empty slots/stash)
 */
static sol_err_t
encode_lowest_slot(sol_encoder_t* enc, const sol_crds_lowest_slot_t* ls) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &ls->from));
    SOL_ENCODE_TRY(sol_encode_u64(enc, ls->root));
    SOL_ENCODE_TRY(sol_encode_u64(enc, ls->lowest));
    SOL_ENCODE_TRY(sol_encode_u64(enc, 0)); /* slots */
    SOL_ENCODE_TRY(sol_encode_u64(enc, 0)); /* stash */
    SOL_ENCODE_TRY(sol_encode_u64(enc, ls->wallclock));
    return SOL_OK;
}

/*
 * Decode CRDS lowest slot
 */
static sol_err_t
decode_lowest_slot(sol_decoder_t* dec, sol_crds_lowest_slot_t* ls) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &ls->from));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ls->root));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ls->lowest));
    uint64_t slots_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &slots_len));
    SOL_DECODE_TRY(skip_vec_slots(dec, slots_len));
    uint64_t stash_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &stash_len));
    SOL_DECODE_TRY(skip_vec_slots(dec, stash_len));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ls->wallclock));
    return SOL_OK;
}

/*
 * Encode CRDS snapshot hashes (empty incremental)
 */
static sol_err_t
encode_snapshot_hashes(sol_encoder_t* enc, const sol_crds_snapshot_hashes_t* sh) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &sh->from));
    SOL_ENCODE_TRY(sol_encode_u64(enc, sh->full_slot));
    SOL_ENCODE_TRY(sol_encode_bytes(enc, sh->full_hash.bytes, 32));
    SOL_ENCODE_TRY(sol_encode_u64(enc, 0)); /* incremental */
    SOL_ENCODE_TRY(sol_encode_u64(enc, sh->wallclock));
    return SOL_OK;
}

/*
 * Decode legacy snapshot hashes
 */
static sol_err_t
decode_legacy_snapshot_hashes(sol_decoder_t* dec, sol_crds_snapshot_hashes_t* sh) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &sh->from));
    SOL_DECODE_TRY(sol_decode_u64(dec, &sh->full_slot));
    const uint8_t* hash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &hash_data));
    memcpy(sh->full_hash.bytes, hash_data, 32);
    SOL_DECODE_TRY(sol_decode_u64(dec, &sh->wallclock));
    return SOL_OK;
}

/*
 * Decode snapshot hashes
 */
static sol_err_t
decode_snapshot_hashes(sol_decoder_t* dec, sol_crds_snapshot_hashes_t* sh) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &sh->from));
    SOL_DECODE_TRY(sol_decode_u64(dec, &sh->full_slot));
    const uint8_t* hash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &hash_data));
    memcpy(sh->full_hash.bytes, hash_data, 32);

    uint64_t inc_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &inc_len));
    for (uint64_t i = 0; i < inc_len; i++) {
        uint64_t slot = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &slot));
        const uint8_t* inc_hash;
        SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &inc_hash));
    }

    SOL_DECODE_TRY(sol_decode_u64(dec, &sh->wallclock));
    return SOL_OK;
}

/*
 * Encode CRDS version
 */
static sol_err_t
encode_crds_version(sol_encoder_t* enc, const sol_crds_version_t* ver) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &ver->from));
    SOL_ENCODE_TRY(sol_encode_u64(enc, ver->wallclock));
    SOL_ENCODE_TRY(sol_encode_u16(enc, ver->major));
    SOL_ENCODE_TRY(sol_encode_u16(enc, ver->minor));
    SOL_ENCODE_TRY(sol_encode_u16(enc, ver->patch));
    SOL_ENCODE_TRY(sol_encode_u32(enc, ver->commit));
    SOL_ENCODE_TRY(sol_encode_u32(enc, ver->feature_set));
    SOL_ENCODE_TRY(sol_encode_u16(enc, 0)); /* client */
    return SOL_OK;
}

/*
 * Decode CRDS version
 */
static sol_err_t
decode_crds_version(sol_decoder_t* dec, sol_crds_version_t* ver) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &ver->from));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ver->wallclock));
    SOL_DECODE_TRY(sol_decode_u16(dec, &ver->major));
    SOL_DECODE_TRY(sol_decode_u16(dec, &ver->minor));
    SOL_DECODE_TRY(sol_decode_u16(dec, &ver->patch));
    SOL_DECODE_TRY(sol_decode_u32(dec, &ver->commit));
    SOL_DECODE_TRY(sol_decode_u32(dec, &ver->feature_set));
    uint16_t client = 0;
    SOL_DECODE_TRY(sol_decode_u16(dec, &client));
    (void)client;
    return SOL_OK;
}

/*
 * Encode CRDS node instance
 */
static sol_err_t
encode_node_instance(sol_encoder_t* enc, const sol_crds_node_instance_t* ni) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &ni->from));
    SOL_ENCODE_TRY(sol_encode_u64(enc, ni->wallclock));
    SOL_ENCODE_TRY(sol_encode_u64(enc, ni->token));
    return SOL_OK;
}

/*
 * Decode CRDS node instance
 */
static sol_err_t
decode_node_instance(sol_decoder_t* dec, sol_crds_node_instance_t* ni) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &ni->from));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ni->wallclock));
    SOL_DECODE_TRY(sol_decode_u64(dec, &ni->token));
    return SOL_OK;
}

static sol_err_t
decode_legacy_contact_info(sol_decoder_t* dec, sol_contact_info_t* ci) {
    sol_contact_info_init(ci);
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &ci->pubkey));

    sol_sockaddr_t addr;
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_GOSSIP, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_TVU, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_TPU_FORWARDS, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_SERVE_REPAIR, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_TPU, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_TPU_FORWARDS, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_TPU_VOTE, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_RPC, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_RPC_PUBSUB, &addr);
    SOL_DECODE_TRY(decode_socketaddr_bincode(dec, &addr));
    (void)sol_contact_info_add_socket(ci, SOL_SOCKET_TAG_SERVE_REPAIR, &addr);

    SOL_DECODE_TRY(sol_decode_u64(dec, &ci->wallclock));
    SOL_DECODE_TRY(sol_decode_u16(dec, &ci->shred_version));
    ci->outset = ci->wallclock / (1000ULL * 60ULL);
    ci->version = (sol_version_t){0};
    return SOL_OK;
}

static sol_err_t
decode_accounts_hashes_skip(sol_decoder_t* dec) {
    const uint8_t* hash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &hash_data));
    uint64_t cap = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &cap));
    (void)cap;
    return SOL_OK;
}

static sol_err_t
decode_epoch_slots_skip(sol_decoder_t* dec) {
    sol_pubkey_t from;
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &from));
    uint64_t root = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &root));
    SOL_DECODE_TRY(decode_bitvec_u8_lsb0_skip(dec));
    uint64_t stash_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &stash_len));
    SOL_DECODE_TRY(skip_vec_slots(dec, stash_len));
    uint64_t wallclock = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &wallclock));
    (void)from;
    (void)root;
    (void)wallclock;
    return SOL_OK;
}

static sol_err_t
decode_duplicate_shred_skip(sol_decoder_t* dec) {
    sol_pubkey_t from;
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &from));
    uint64_t wallclock = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &wallclock));
    uint64_t slot = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &slot));
    uint64_t shred_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &shred_len));
    SOL_DECODE_TRY(skip_bytes_len(dec, shred_len));
    (void)from;
    (void)wallclock;
    (void)slot;
    return SOL_OK;
}

static sol_err_t
decode_restart_last_voted_skip(sol_decoder_t* dec) {
    sol_pubkey_t from;
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &from));
    uint64_t slots_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &slots_len));
    SOL_DECODE_TRY(skip_vec_slots(dec, slots_len));
    uint64_t wallclock = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &wallclock));
    (void)from;
    (void)wallclock;
    return SOL_OK;
}

static sol_err_t
decode_restart_heaviest_skip(sol_decoder_t* dec) {
    sol_pubkey_t from;
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &from));
    uint64_t last_slot = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &last_slot));
    const uint8_t* hash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, 32, &hash_data));
    uint64_t wallclock = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &wallclock));
    (void)from;
    (void)last_slot;
    (void)wallclock;
    return SOL_OK;
}

enum {
    SOL_CRDS_DATA_LEGACY_CONTACT_INFO = 0,
    SOL_CRDS_DATA_VOTE = 1,
    SOL_CRDS_DATA_LOWEST_SLOT = 2,
    SOL_CRDS_DATA_LEGACY_SNAPSHOT_HASHES = 3,
    SOL_CRDS_DATA_ACCOUNTS_HASHES = 4,
    SOL_CRDS_DATA_EPOCH_SLOTS = 5,
    SOL_CRDS_DATA_LEGACY_VERSION = 6,
    SOL_CRDS_DATA_VERSION = 7,
    SOL_CRDS_DATA_NODE_INSTANCE = 8,
    SOL_CRDS_DATA_DUPLICATE_SHRED = 9,
    SOL_CRDS_DATA_SNAPSHOT_HASHES = 10,
    SOL_CRDS_DATA_CONTACT_INFO = 11,
    SOL_CRDS_DATA_RESTART_LAST_VOTED_FORK_SLOTS = 12,
    SOL_CRDS_DATA_RESTART_HEAVIEST_FORK = 13
};

/*
 * Encode CRDS value (data portion, without signature)
 */
static sol_err_t
encode_crds_value_data(sol_encoder_t* enc, const sol_crds_value_t* value) {
    switch (value->type) {
    case SOL_CRDS_CONTACT_INFO:
        SOL_ENCODE_TRY(sol_encode_u32(enc, SOL_CRDS_DATA_CONTACT_INFO));
        return encode_contact_info(enc, &value->data.contact_info);
    case SOL_CRDS_LOWEST_SLOT:
        SOL_ENCODE_TRY(sol_encode_u32(enc, SOL_CRDS_DATA_LOWEST_SLOT));
        return encode_lowest_slot(enc, &value->data.lowest_slot);
    case SOL_CRDS_SNAPSHOT_HASHES:
        SOL_ENCODE_TRY(sol_encode_u32(enc, SOL_CRDS_DATA_SNAPSHOT_HASHES));
        return encode_snapshot_hashes(enc, &value->data.snapshot_hashes);
    case SOL_CRDS_VERSION:
        SOL_ENCODE_TRY(sol_encode_u32(enc, SOL_CRDS_DATA_VERSION));
        return encode_crds_version(enc, &value->data.version);
    case SOL_CRDS_NODE_INSTANCE:
        SOL_ENCODE_TRY(sol_encode_u32(enc, SOL_CRDS_DATA_NODE_INSTANCE));
        return encode_node_instance(enc, &value->data.node_instance);
    case SOL_CRDS_VOTE:
    case SOL_CRDS_ACCOUNTS_HASHES:
    case SOL_CRDS_EPOCH_SLOTS:
    case SOL_CRDS_DUPLICATE_SHRED:
    case SOL_CRDS_INCREMENTAL_SNAPSHOT:
    case SOL_CRDS_RESTART_LAST_VOTED_FORK:
    case SOL_CRDS_RESTART_HEAVIEST_FORK:
    case SOL_CRDS_TYPE_COUNT:
        return SOL_ERR_UNSUPPORTED;
    }
    return SOL_ERR_UNSUPPORTED;
}

/*
 * Decode CRDS value data
 */
static sol_err_t
decode_crds_value_data(sol_decoder_t* dec, sol_crds_value_t* value) {
    uint32_t kind = 0;
    SOL_DECODE_TRY(sol_decode_u32(dec, &kind));

    switch (kind) {
    case SOL_CRDS_DATA_LEGACY_CONTACT_INFO:
        value->type = SOL_CRDS_CONTACT_INFO;
        return decode_legacy_contact_info(dec, &value->data.contact_info);
    case SOL_CRDS_DATA_VOTE:
        value->type = SOL_CRDS_VOTE;
        return decode_crds_vote(dec, &value->data.vote);
    case SOL_CRDS_DATA_LOWEST_SLOT:
        value->type = SOL_CRDS_LOWEST_SLOT;
        return decode_lowest_slot(dec, &value->data.lowest_slot);
    case SOL_CRDS_DATA_LEGACY_SNAPSHOT_HASHES:
        value->type = SOL_CRDS_SNAPSHOT_HASHES;
        return decode_legacy_snapshot_hashes(dec, &value->data.snapshot_hashes);
    case SOL_CRDS_DATA_ACCOUNTS_HASHES:
        value->type = SOL_CRDS_TYPE_COUNT;
        return decode_accounts_hashes_skip(dec);
    case SOL_CRDS_DATA_EPOCH_SLOTS:
        value->type = SOL_CRDS_TYPE_COUNT;
        return decode_epoch_slots_skip(dec);
    case SOL_CRDS_DATA_LEGACY_VERSION:
        value->type = SOL_CRDS_VERSION;
        return decode_crds_version(dec, &value->data.version);
    case SOL_CRDS_DATA_VERSION:
        value->type = SOL_CRDS_VERSION;
        return decode_crds_version(dec, &value->data.version);
    case SOL_CRDS_DATA_NODE_INSTANCE:
        value->type = SOL_CRDS_NODE_INSTANCE;
        return decode_node_instance(dec, &value->data.node_instance);
    case SOL_CRDS_DATA_DUPLICATE_SHRED:
        value->type = SOL_CRDS_TYPE_COUNT;
        return decode_duplicate_shred_skip(dec);
    case SOL_CRDS_DATA_SNAPSHOT_HASHES:
        value->type = SOL_CRDS_SNAPSHOT_HASHES;
        return decode_snapshot_hashes(dec, &value->data.snapshot_hashes);
    case SOL_CRDS_DATA_CONTACT_INFO:
        value->type = SOL_CRDS_CONTACT_INFO;
        return decode_contact_info(dec, &value->data.contact_info);
    case SOL_CRDS_DATA_RESTART_LAST_VOTED_FORK_SLOTS:
        value->type = SOL_CRDS_TYPE_COUNT;
        return decode_restart_last_voted_skip(dec);
    case SOL_CRDS_DATA_RESTART_HEAVIEST_FORK:
        value->type = SOL_CRDS_TYPE_COUNT;
        return decode_restart_heaviest_skip(dec);
    default:
        return SOL_ERR_UNSUPPORTED;
    }
}

/*
 * Encode complete CRDS value (signature + data)
 */
static sol_err_t
encode_crds_value(sol_encoder_t* enc, const sol_crds_value_t* value) {
    SOL_ENCODE_TRY(sol_signature_encode(enc, &value->signature));
    return encode_crds_value_data(enc, value);
}

/*
 * Decode complete CRDS value
 */
static sol_err_t
decode_crds_value(sol_decoder_t* dec, sol_crds_value_t* value) {
    SOL_DECODE_TRY(sol_signature_decode(dec, &value->signature));
    return decode_crds_value_data(dec, value);
}

/*
 * Encode pull response
 */
static sol_err_t
encode_pull_response(sol_encoder_t* enc, const sol_pull_response_t* resp) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &resp->pubkey));
    SOL_ENCODE_TRY(sol_encode_u64(enc, (uint64_t)resp->values_len));
    for (uint16_t i = 0; i < resp->values_len; i++) {
        SOL_ENCODE_TRY(encode_crds_value(enc, &resp->values[i]));
    }
    return SOL_OK;
}

/*
 * Decode pull response
 */
static sol_err_t
decode_pull_response(sol_decoder_t* dec, sol_pull_response_t* resp, sol_arena_t* arena) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &resp->pubkey));

    uint64_t values_len64 = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &values_len64));

    if (values_len64 > SOL_GOSSIP_MAX_PULL_VALUES || values_len64 > UINT16_MAX) {
        return SOL_ERR_MALFORMED;
    }

    resp->values_len = (uint16_t)values_len64;
    if (resp->values_len > 0) {
        if (arena) {
            resp->values = sol_arena_alloc(arena, resp->values_len * sizeof(sol_crds_value_t));
        } else {
            resp->values = sol_calloc(resp->values_len, sizeof(sol_crds_value_t));
        }
        if (!resp->values) return SOL_ERR_NOMEM;

        for (uint16_t i = 0; i < resp->values_len; i++) {
            SOL_DECODE_TRY(decode_crds_value(dec, &resp->values[i]));
        }
    } else {
        resp->values = NULL;
    }

    return SOL_OK;
}

/*
 * Encode prune message
 */
static sol_err_t
encode_prune(sol_encoder_t* enc, const sol_prune_msg_t* prune) {
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &prune->pubkey));
    SOL_ENCODE_TRY(sol_encode_u64(enc, (uint64_t)prune->prunes_len));
    for (uint16_t i = 0; i < prune->prunes_len; i++) {
        SOL_ENCODE_TRY(sol_pubkey_encode(enc, &prune->prunes[i]));
    }
    SOL_ENCODE_TRY(sol_signature_encode(enc, &prune->signature));
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &prune->destination));
    SOL_ENCODE_TRY(sol_encode_u64(enc, prune->wallclock));
    return SOL_OK;
}

/*
 * Decode prune message
 */
static sol_err_t
decode_prune(sol_decoder_t* dec, sol_prune_msg_t* prune, sol_arena_t* arena) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &prune->pubkey));

    uint64_t prunes_len64 = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &prunes_len64));

    if (prunes_len64 > SOL_GOSSIP_MAX_PRUNE_ORIGINS || prunes_len64 > UINT16_MAX) {
        return SOL_ERR_MALFORMED;
    }

    prune->prunes_len = (uint16_t)prunes_len64;
    if (prune->prunes_len > 0) {
        if (arena) {
            prune->prunes = sol_arena_alloc(arena, prune->prunes_len * sizeof(sol_pubkey_t));
        } else {
            prune->prunes = sol_calloc(prune->prunes_len, sizeof(sol_pubkey_t));
        }
        if (!prune->prunes) return SOL_ERR_NOMEM;

        for (uint16_t i = 0; i < prune->prunes_len; i++) {
            SOL_DECODE_TRY(sol_pubkey_decode(dec, &prune->prunes[i]));
        }
    } else {
        prune->prunes = NULL;
    }

    SOL_DECODE_TRY(sol_signature_decode(dec, &prune->signature));
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &prune->destination));
    SOL_DECODE_TRY(sol_decode_u64(dec, &prune->wallclock));

    return SOL_OK;
}

sol_err_t
sol_gossip_msg_encode(sol_encoder_t* enc, const sol_gossip_msg_t* msg) {
    if (!enc || !msg) {
        return SOL_ERR_INVAL;
    }

    /* Encode message type as u32 */
    SOL_ENCODE_TRY(sol_encode_u32(enc, (uint32_t)msg->type));

    switch (msg->type) {
    case SOL_GOSSIP_MSG_PING:
        return encode_ping(enc, &msg->data.ping);

    case SOL_GOSSIP_MSG_PONG:
        return encode_pong(enc, &msg->data.pong);

    case SOL_GOSSIP_MSG_PULL_REQUEST:
        SOL_ENCODE_TRY(encode_crds_filter(enc, &msg->data.pull_request.filter));
        /* Encode self_value */
        SOL_ENCODE_TRY(encode_crds_value(enc, &msg->data.pull_request.self_value));
        return SOL_OK;

    case SOL_GOSSIP_MSG_PULL_RESPONSE:
        return encode_pull_response(enc, &msg->data.pull_response);

    case SOL_GOSSIP_MSG_PUSH:
        SOL_ENCODE_TRY(sol_pubkey_encode(enc, &msg->data.push.pubkey));
        SOL_ENCODE_TRY(sol_encode_u64(enc, (uint64_t)msg->data.push.values_len));
        /* Encode values array */
        for (uint16_t i = 0; i < msg->data.push.values_len; i++) {
            SOL_ENCODE_TRY(encode_crds_value(enc, &msg->data.push.values[i]));
        }
        return SOL_OK;

    case SOL_GOSSIP_MSG_PRUNE:
        return encode_prune(enc, &msg->data.prune);

    default:
        return SOL_ERR_UNSUPPORTED;
    }
}

sol_err_t
sol_gossip_msg_decode(
    sol_decoder_t*    dec,
    sol_gossip_msg_t* msg,
    sol_arena_t*      arena
) {
    if (!dec || !msg) {
        return SOL_ERR_INVAL;
    }

    /* Decode message type */
    uint32_t type;
    SOL_DECODE_TRY(sol_decode_u32(dec, &type));
    msg->type = (sol_gossip_msg_type_t)type;

    switch (msg->type) {
    case SOL_GOSSIP_MSG_PING:
        return decode_ping(dec, &msg->data.ping);

    case SOL_GOSSIP_MSG_PONG:
        return decode_pong(dec, &msg->data.pong);

    case SOL_GOSSIP_MSG_PULL_REQUEST: {
        SOL_DECODE_TRY(decode_crds_filter(dec, &msg->data.pull_request.filter));
        /* Decode self_value */
        SOL_DECODE_TRY(decode_crds_value(dec, &msg->data.pull_request.self_value));
        return SOL_OK;
    }

    case SOL_GOSSIP_MSG_PULL_RESPONSE:
        return decode_pull_response(dec, &msg->data.pull_response, arena);

    case SOL_GOSSIP_MSG_PUSH: {
        SOL_DECODE_TRY(sol_pubkey_decode(dec, &msg->data.push.pubkey));
        uint64_t values_len64 = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &values_len64));

        if (values_len64 > SOL_GOSSIP_MAX_PUSH_VALUES || values_len64 > UINT16_MAX) {
            return SOL_ERR_MALFORMED;
        }

        msg->data.push.values_len = (uint16_t)values_len64;
        if (msg->data.push.values_len > 0) {
            if (arena) {
                msg->data.push.values = sol_arena_alloc(arena,
                    msg->data.push.values_len * sizeof(sol_crds_value_t));
            } else {
                msg->data.push.values = sol_calloc(msg->data.push.values_len,
                                                  sizeof(sol_crds_value_t));
            }
            if (!msg->data.push.values) return SOL_ERR_NOMEM;

            for (uint16_t i = 0; i < msg->data.push.values_len; i++) {
                SOL_DECODE_TRY(decode_crds_value(dec, &msg->data.push.values[i]));
            }
        } else {
            msg->data.push.values = NULL;
        }
        return SOL_OK;
    }

    case SOL_GOSSIP_MSG_PRUNE:
        return decode_prune(dec, &msg->data.prune, arena);

    default:
        return SOL_ERR_UNSUPPORTED;
    }
}

void
sol_gossip_msg_free(sol_gossip_msg_t* msg) {
    if (!msg) return;

    switch (msg->type) {
    case SOL_GOSSIP_MSG_PULL_RESPONSE:
        if (msg->data.pull_response.values) {
            sol_free(msg->data.pull_response.values);
            msg->data.pull_response.values = NULL;
        }
        break;

    case SOL_GOSSIP_MSG_PUSH:
        if (msg->data.push.values) {
            sol_free(msg->data.push.values);
            msg->data.push.values = NULL;
        }
        break;

    case SOL_GOSSIP_MSG_PRUNE:
        if (msg->data.prune.prunes) {
            sol_free(msg->data.prune.prunes);
            msg->data.prune.prunes = NULL;
        }
        break;

    case SOL_GOSSIP_MSG_PULL_REQUEST:
    case SOL_GOSSIP_MSG_PING:
    case SOL_GOSSIP_MSG_PONG:
        /* No heap allocations to free */
        break;
    }
}
