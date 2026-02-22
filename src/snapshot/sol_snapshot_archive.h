/*
 * sol_snapshot_archive.h - Snapshot Archive Extraction
 *
 * Handles extraction of Solana snapshot archives (tar.zst format).
 *
 * Supports:
 * - Zstandard (zstd) decompression
 * - tar archive extraction
 * - Progress reporting
 */

#ifndef SOL_SNAPSHOT_ARCHIVE_H
#define SOL_SNAPSHOT_ARCHIVE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_snapshot.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Archive extraction progress callback
 *
 * @param ctx               User context
 * @param bytes_extracted   Bytes extracted so far
 * @param total_bytes       Total bytes (0 if unknown)
 * @param current_file      Current file being extracted (may be NULL)
 */
typedef void (*sol_archive_progress_fn)(
    void*           ctx,
    uint64_t        bytes_extracted,
    uint64_t        total_bytes,
    const char*     current_file
);

/*
 * Optional callback to receive extracted files in-memory.
 *
 * When configured via sol_archive_extract_opts_t.stream_prefix and
 * stream_file_callback, matching regular files are not written to disk.
 * Instead, the extractor allocates a buffer, fills it with the file contents,
 * and invokes this callback. Ownership of `data` transfers to the callback on
 * SOL_OK (the callback must free it with sol_free). On error, the extractor
 * frees `data` and aborts extraction.
 */
typedef sol_err_t (*sol_archive_stream_file_cb)(
    void*           ctx,
    const char*     rel_path,
    uint8_t*        data,
    size_t          len
);

/*
 * Optional callback to receive extracted file contents in chunks.
 *
 * When configured via sol_archive_extract_opts_t.stream_prefix and
 * stream_chunk_callback, matching regular files are not written to disk.
 * Instead, the extractor invokes this callback repeatedly with chunks of the
 * file data. The buffer passed via `data` is only valid for the duration of
 * the callback and must not be retained.
 *
 * For empty files, the extractor invokes the callback once with
 * data=NULL, len=0, file_size=0, file_offset=0, is_last=true.
 */
typedef sol_err_t (*sol_archive_stream_chunk_cb)(
    void*           ctx,
    const char*     rel_path,
    const uint8_t*  data,
    size_t          len,
    uint64_t        file_size,
    uint64_t        file_offset,
    bool            is_last
);

/*
 * Archive extraction options
 */
typedef struct {
    const char*             output_dir;         /* Directory to extract to */
    sol_archive_progress_fn progress_callback;  /* Progress callback (optional) */
    void*                   progress_ctx;       /* Callback context */
    bool                    verify;             /* Verify after extraction */
    bool                    preserve_paths;     /* Preserve directory structure */
    uint64_t                max_memory;         /* Max memory for decompression (0=default) */

    /* Optional in-memory streaming for matching regular files. */
    const char*                stream_prefix;         /* e.g. "accounts/" */
    sol_archive_stream_file_cb stream_file_callback;  /* Receives ownership of file buffer */
    sol_archive_stream_chunk_cb stream_chunk_callback; /* Receives file data in chunks */
    void*                      stream_file_ctx;       /* Callback context */
    uint64_t                   stream_max_file_size;  /* 0 = no limit */

    /* If true, do not write non-matching entries to disk. Requires zstd
     * streaming path (SOL_HAS_ZSTD). */
    bool                        skip_unmatched;
} sol_archive_extract_opts_t;

#define SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT {      \
    .output_dir = NULL,                         \
    .progress_callback = NULL,                  \
    .progress_ctx = NULL,                       \
    .verify = false,                            \
    .preserve_paths = true,                     \
    .max_memory = 0,                            \
    .stream_prefix = NULL,                      \
    .stream_file_callback = NULL,               \
    .stream_chunk_callback = NULL,              \
    .stream_file_ctx = NULL,                    \
    .stream_max_file_size = 0,                  \
    .skip_unmatched = false,                    \
}

/*
 * Extract a snapshot archive
 *
 * Supports tar.zst, tar.gz, tar.bz2, tar.lz4, and uncompressed tar files.
 * The compression format is detected from magic bytes.
 *
 * @param archive_path  Path to archive file
 * @param opts          Extraction options (NULL for defaults)
 * @return              SOL_OK on success, error otherwise
 */
sol_err_t sol_snapshot_archive_extract(
    const char*                         archive_path,
    const sol_archive_extract_opts_t*   opts
);

/*
 * Check if an archive can be extracted
 *
 * Verifies the archive format and that required tools/libraries are available.
 *
 * @param archive_path  Path to archive file
 * @return              SOL_OK if extractable
 */
sol_err_t sol_snapshot_archive_check(const char* archive_path);

/*
 * Get uncompressed size of archive
 *
 * Returns an estimate of the uncompressed size, useful for
 * checking disk space before extraction.
 *
 * @param archive_path  Path to archive file
 * @param out_size      Output uncompressed size
 * @return              SOL_OK on success
 */
sol_err_t sol_snapshot_archive_get_size(
    const char*     archive_path,
    uint64_t*       out_size
);

/*
 * Detect compression type from file
 *
 * Reads magic bytes to detect compression format.
 *
 * @param archive_path  Path to archive file
 * @return              Compression type
 */
sol_snapshot_compression_t sol_snapshot_archive_detect_compression(
    const char*     archive_path
);

/*
 * Create a temporary directory for extraction
 *
 * Creates a unique temporary directory that will be cleaned up on error.
 *
 * @param base_dir      Base directory (NULL for system temp)
 * @param prefix        Directory name prefix
 * @param out_path      Output path buffer
 * @param max_len       Buffer size
 * @return              SOL_OK on success
 */
sol_err_t sol_snapshot_archive_mktemp(
    const char*     base_dir,
    const char*     prefix,
    char*           out_path,
    size_t          max_len
);

/*
 * Remove a directory recursively
 *
 * Used for cleanup on extraction failure.
 *
 * @param path          Directory to remove
 * @return              SOL_OK on success
 */
sol_err_t sol_snapshot_archive_rmdir(const char* path);

/*
 * Check if zstd library is available
 */
bool sol_snapshot_has_zstd(void);

/*
 * Check if lz4 library is available
 */
bool sol_snapshot_has_lz4(void);

#ifdef __cplusplus
}
#endif

#endif /* SOL_SNAPSHOT_ARCHIVE_H */
