/* Shim replacement for Firedancer's fd_ballet_base.h */
#ifndef HEADER_fd_src_ballet_fd_ballet_base_h
#define HEADER_fd_src_ballet_fd_ballet_base_h

#include "../../fd_bn254_compat.h"

/* FD_ALIGN settings (same as fd_ballet_base.h) */
#if FD_HAS_AVX512
#undef FD_ALIGN
#define FD_ALIGN (64UL)
#elif FD_HAS_AVX
#undef FD_ALIGN
#define FD_ALIGN (32UL)
#elif FD_HAS_INT128
#undef FD_ALIGN
#define FD_ALIGN (16UL)
#else
#undef FD_ALIGN
#define FD_ALIGN (8UL)
#endif

#endif /* HEADER_fd_src_ballet_fd_ballet_base_h */
