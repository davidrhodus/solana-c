/*
 * sol_account.c - Account Operations Implementation
 */

#include "sol_account.h"
#include "../util/sol_alloc.h"
#include "../crypto/sol_sha256.h"
#include <string.h>

sol_account_t*
sol_account_alloc(void) {
    return (sol_account_t*)sol_calloc(1, sizeof(sol_account_t));
}

static inline void
sol_account_free_struct(sol_account_t* account) {
    if (!account) return;
    sol_free(account);
}

/*
 * Well-known program IDs
 * Note: SOL_SYSTEM_PROGRAM_ID and SOL_NATIVE_LOADER_ID are defined in sol_types.c
 */
const sol_pubkey_t SOL_BPF_LOADER_ID = {
    .bytes = {
        0x42, 0x50, 0x46, 0x4c, 0x6f, 0x61, 0x64, 0x65,  /* BPFLoade */
        0x72, 0x32, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,  /* r2111111 */
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,  /* 11111111 */
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31   /* 11111111 */
    }
};

void
sol_account_init(sol_account_t* account) {
    if (!account) return;
    memset(account, 0, sizeof(sol_account_t));
}

sol_account_t*
sol_account_new(uint64_t lamports, size_t data_len, const sol_pubkey_t* owner) {
    sol_account_t* account = sol_account_alloc();
    if (!account) return NULL;

    account->meta.lamports = lamports;
    account->meta.data_len = data_len;

    if (data_len > 0) {
        account->data = sol_calloc(1, data_len);
        if (!account->data) {
            sol_account_free_struct(account);
            return NULL;
        }
    }

    if (owner) {
        account->meta.owner = *owner;
    }

    return account;
}

sol_account_t*
sol_account_clone(const sol_account_t* account) {
    if (!account) return NULL;

    sol_account_t* clone = sol_account_alloc();
    if (!clone) return NULL;

    clone->meta = account->meta;

    if (account->meta.data_len > 0 && account->data) {
        clone->data = sol_alloc(account->meta.data_len);
        if (!clone->data) {
            sol_account_free_struct(clone);
            return NULL;
        }
        memcpy(clone->data, account->data, account->meta.data_len);
    }

    return clone;
}

void
sol_account_destroy(sol_account_t* account) {
    if (!account) return;

    if (account->data && !account->data_borrowed) {
        sol_free(account->data);
    }
    sol_account_free_struct(account);
}

void
sol_account_cleanup(sol_account_t* account) {
    if (!account) return;

    if (account->data && !account->data_borrowed) {
        sol_free(account->data);
    }
    account->data = NULL;
    account->meta.data_len = 0;
    account->data_borrowed = false;
}

sol_err_t
sol_account_resize(sol_account_t* account, size_t new_len) {
    if (!account) return SOL_ERR_INVAL;
    if (new_len > SOL_ACCOUNT_MAX_DATA_SIZE) return SOL_ERR_TOO_LARGE;

    if (new_len == account->meta.data_len) {
        /* Detach borrowed (view) buffers on resize even if the size is unchanged.
         * Callers typically resize before mutating account data. */
        if (new_len > 0 && account->data && account->data_borrowed) {
            uint8_t* new_data = sol_alloc(new_len);
            if (!new_data) return SOL_ERR_NOMEM;
            memcpy(new_data, account->data, new_len);
            account->data = new_data;
            account->data_borrowed = false;
        }
        return SOL_OK;
    }

    if (new_len == 0) {
        if (account->data && !account->data_borrowed) {
            sol_free(account->data);
        }
        account->data = NULL;
        account->meta.data_len = 0;
        account->data_borrowed = false;
        return SOL_OK;
    }

    if (account->data_borrowed) {
        /* Copy-on-write: can't realloc a borrowed/view buffer. */
        uint8_t* new_data = sol_calloc(1, new_len);
        if (!new_data) return SOL_ERR_NOMEM;

        if (account->data && account->meta.data_len > 0) {
            size_t to_copy = account->meta.data_len;
            if (to_copy > new_len) to_copy = new_len;
            memcpy(new_data, account->data, to_copy);
        }

        account->data = new_data;
        account->meta.data_len = new_len;
        account->data_borrowed = false;
        return SOL_OK;
    } else {
        /* Reallocate owned buffer */
        uint8_t* new_data = sol_realloc(account->data, new_len);
        if (!new_data) return SOL_ERR_NOMEM;

        /* Zero the new portion if growing */
        if (new_len > account->meta.data_len) {
            memset(new_data + account->meta.data_len, 0,
                   new_len - account->meta.data_len);
        }

        account->data = new_data;
        account->meta.data_len = new_len;
    }

    return SOL_OK;
}

sol_err_t
sol_account_set_data(sol_account_t* account, const uint8_t* data, size_t len) {
    if (!account) return SOL_ERR_INVAL;

    /* Copy-on-write: `resize` may be a no-op for equal sizes, so detach here
     * before copying into the buffer. */
    if (len > 0 && data && account->data && account->data_borrowed) {
        uint8_t* new_data = sol_alloc(len);
        if (!new_data) return SOL_ERR_NOMEM;
        memcpy(new_data, data, len);
        account->data = new_data;
        account->meta.data_len = len;
        account->data_borrowed = false;
        return SOL_OK;
    }

    sol_err_t err = sol_account_resize(account, len);
    if (err != SOL_OK) return err;

    if (len > 0 && data) {
        memcpy(account->data, data, len);
    }

    return SOL_OK;
}

bool
sol_account_is_native_program(const sol_pubkey_t* pubkey) {
    if (!pubkey) return false;

    return sol_pubkey_eq(pubkey, &SOL_SYSTEM_PROGRAM_ID) ||
           sol_pubkey_eq(pubkey, &SOL_NATIVE_LOADER_ID);
}

bool
sol_account_is_rent_exempt(const sol_account_t* account,
                           uint64_t rent_per_byte_year,
                           uint64_t exemption_threshold) {
    if (!account) return false;

    uint64_t min_balance = sol_account_rent_exempt_minimum(
        account->meta.data_len, rent_per_byte_year, exemption_threshold);

    return account->meta.lamports >= min_balance;
}

uint64_t
sol_account_rent_exempt_minimum(size_t data_len, uint64_t rent_per_byte_year,
                                uint64_t exemption_threshold) {
    /* Account metadata size (128 bytes base) */
    size_t account_size = 128 + data_len;

    /* Minimum balance = (account_size * rent_per_byte_year * exemption_years) */
    uint64_t rent = (uint64_t)account_size * rent_per_byte_year;

    /* Apply exemption multiplier (typically 2x for 2 years) */
    return rent * exemption_threshold;
}

sol_err_t
sol_account_serialize(const sol_account_t* account, uint8_t* buf,
                      size_t buf_len, size_t* bytes_written) {
    if (!account || !buf || !bytes_written) return SOL_ERR_INVAL;

    size_t offset = 0;

    /* Lamports (8 bytes) */
    if (offset + 8 > buf_len) return SOL_ERR_OVERFLOW;
    memcpy(buf + offset, &account->meta.lamports, 8);
    offset += 8;

    /* Data length (8 bytes) */
    if (offset + 8 > buf_len) return SOL_ERR_OVERFLOW;
    uint64_t data_len = account->meta.data_len;
    memcpy(buf + offset, &data_len, 8);
    offset += 8;

    /* Data */
    if (offset + account->meta.data_len > buf_len) return SOL_ERR_OVERFLOW;
    if (account->meta.data_len > 0 && account->data) {
        memcpy(buf + offset, account->data, account->meta.data_len);
    }
    offset += account->meta.data_len;

    /* Owner (32 bytes) */
    if (offset + 32 > buf_len) return SOL_ERR_OVERFLOW;
    memcpy(buf + offset, account->meta.owner.bytes, 32);
    offset += 32;

    /* Executable (1 byte) */
    if (offset + 1 > buf_len) return SOL_ERR_OVERFLOW;
    buf[offset++] = account->meta.executable ? 1 : 0;

    /* Rent epoch (8 bytes) */
    if (offset + 8 > buf_len) return SOL_ERR_OVERFLOW;
    memcpy(buf + offset, &account->meta.rent_epoch, 8);
    offset += 8;

    *bytes_written = offset;
    return SOL_OK;
}

sol_err_t
sol_account_deserialize(sol_account_t* account, const uint8_t* data,
                        size_t len, size_t* bytes_consumed) {
    if (!account || !data || !bytes_consumed) return SOL_ERR_INVAL;

    size_t offset = 0;

    /* Lamports */
    if (offset + 8 > len) return SOL_ERR_TRUNCATED;
    memcpy(&account->meta.lamports, data + offset, 8);
    offset += 8;

    /* Data length */
    if (offset + 8 > len) return SOL_ERR_TRUNCATED;
    uint64_t data_len;
    memcpy(&data_len, data + offset, 8);
    offset += 8;

    if (data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return SOL_ERR_TOO_LARGE;

    /* Data */
    if (offset + data_len > len) return SOL_ERR_TRUNCATED;

    sol_err_t err = sol_account_resize(account, (size_t)data_len);
    if (err != SOL_OK) return err;

    if (data_len > 0) {
        memcpy(account->data, data + offset, data_len);
    }
    offset += data_len;

    /* Owner */
    if (offset + 32 > len) return SOL_ERR_TRUNCATED;
    memcpy(account->meta.owner.bytes, data + offset, 32);
    offset += 32;

    /* Executable */
    if (offset + 1 > len) return SOL_ERR_TRUNCATED;
    account->meta.executable = data[offset++] != 0;

    /* Rent epoch */
    if (offset + 8 > len) return SOL_ERR_TRUNCATED;
    memcpy(&account->meta.rent_epoch, data + offset, 8);
    offset += 8;

    *bytes_consumed = offset;
    return SOL_OK;
}

void
sol_account_hash(const sol_pubkey_t* pubkey, const sol_account_t* account,
                 sol_hash_t* out_hash) {
    if (!pubkey || !account || !out_hash) return;

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);

    /* Hash pubkey */
    sol_sha256_update(&ctx, pubkey->bytes, 32);

    /* Hash lamports */
    sol_sha256_update(&ctx, &account->meta.lamports, 8);

    /* Hash data */
    uint64_t data_len = account->meta.data_len;
    sol_sha256_update(&ctx, &data_len, 8);
    if (account->meta.data_len > 0 && account->data) {
        sol_sha256_update(&ctx, account->data, account->meta.data_len);
    }

    /* Hash owner */
    sol_sha256_update(&ctx, account->meta.owner.bytes, 32);

    /* Hash executable flag */
    uint8_t exec = account->meta.executable ? 1 : 0;
    sol_sha256_update(&ctx, &exec, 1);

    /* Hash rent epoch */
    sol_sha256_update(&ctx, &account->meta.rent_epoch, 8);

    sol_sha256_final_bytes(&ctx, out_hash->bytes);
}
