/*
 * memDBG - x86-64 assembler (Keystone wrapper).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Provides server-side assembly of x86-64 instructions using the Keystone
 * engine. Clients send assembly source text and receive encoded machine code.
 */

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/pal/pal_network.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(MEMDBG_HAS_KEYSTONE)
#include <keystone/keystone.h>
#endif

int memdbg_asm_encode(int fd, const uint8_t *body, uint32_t body_len) {
  if (body_len < sizeof(memdbg_asm_encode_request_t)) {
    uint32_t err = 0xF0000002u;
    pal_socket_write_all(fd, &err, 4);
    return 1;
  }

  const memdbg_asm_encode_request_t *req =
      (const memdbg_asm_encode_request_t *)body;
  uint32_t text_len = body_len - (uint32_t)sizeof(*req);
  if (text_len == 0) {
    uint32_t err = 0xF0000002u;
    pal_socket_write_all(fd, &err, 4);
    return 1;
  }

  char *source = (char *)malloc((size_t)text_len + 1);
  if (!source) {
    uint32_t err = 0xF0000003u;
    pal_socket_write_all(fd, &err, 4);
    return 1;
  }
  memcpy(source, body + sizeof(*req), text_len);
  source[text_len] = '\0';

#if defined(MEMDBG_HAS_KEYSTONE)
  ks_engine *ks = NULL;
  ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
  if (err != KS_ERR_OK || !ks) {
    free(source);
    uint32_t code = (uint32_t)err;
    pal_socket_write_all(fd, &code, 4);
    const char *msg = ks_strerror(err);
    uint32_t mlen = msg ? (uint32_t)strlen(msg) : 0;
    pal_socket_write_all(fd, &mlen, 4);
    if (mlen) pal_socket_write_all(fd, msg, (int)mlen);
    return 1;
  }

  if (req->syntax != 0)
    ks_option(ks, KS_OPT_SYNTAX, (size_t)req->syntax);

  unsigned char *enc = NULL;
  size_t enc_size = 0, insn_count = 0;
  int rc = ks_asm(ks, source, req->origin, &enc, &enc_size, &insn_count);
  free(source);

  if (rc != KS_ERR_OK) {
    ks_err e = ks_errno(ks);
    if (enc) ks_free(enc);
    ks_close(ks);
    uint32_t code = (uint32_t)e;
    pal_socket_write_all(fd, &code, 4);
    const char *msg = ks_strerror(e);
    uint32_t mlen = msg ? (uint32_t)strlen(msg) : 0;
    pal_socket_write_all(fd, &mlen, 4);
    if (mlen) pal_socket_write_all(fd, msg, (int)mlen);
    return 1;
  }

  uint32_t ok = 0;
  pal_socket_write_all(fd, &ok, 4);
  uint32_t bc = (uint32_t)enc_size;
  uint32_t ic = (uint32_t)insn_count;
  pal_socket_write_all(fd, &bc, 4);
  pal_socket_write_all(fd, &ic, 4);
  if (enc_size) pal_socket_write_all(fd, enc, (int)enc_size);

  ks_free(enc);
  ks_close(ks);
#else
  free(source);
  uint32_t code = 0xF0000002u;
  pal_socket_write_all(fd, &code, 4);
  const char *msg = "Keystone not available";
  uint32_t mlen = (uint32_t)strlen(msg);
  pal_socket_write_all(fd, &mlen, 4);
  pal_socket_write_all(fd, msg, (int)mlen);
#endif
  return 0;
}
