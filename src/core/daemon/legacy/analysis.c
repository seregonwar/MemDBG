/*
 * memDBG - ps5debug compat: disasm, xrefs, remote call, and ELF load bridges.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * These bridges use socketpair(2) to capture the native MemDBG response,
 * then translate it to the legacy ps5debug wire format before forwarding
 * to the real client socket.
 */

#include "internal.h"

#include "memdbg/debug/memdbg_disasm.h"
#include "memdbg/pal/pal_time.h"

#include <sys/socket.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/* Create a socket pair and return both fds.  Returns 0 on success. */
static int legacy_spawn_pair(socket_t *writer, socket_t *reader) {
  int sp[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) return -1;
  *writer = sp[0];
  *reader = sp[1];
  return 0;
}

/* Read exactly N bytes from a socket into a malloc'd buffer.
 * Returns pointer (caller must free) or NULL on error. */
static uint8_t *legacy_read_exact_alloc(socket_t fd, uint32_t n) {
  if (n == 0U || n > (64U << 20)) return NULL;
  uint8_t *buf = (uint8_t *)malloc(n);
  if (buf == NULL) return NULL;
  if (pal_socket_read_exact(fd, buf, n) < 0) { free(buf); return NULL; }
  return buf;
}

/* Read a native response header + payload from a socketpair reader.
 * On success sets *status and *payload / *plen (caller frees payload).
 * Returns 0 on success, -1 on error. */
static int legacy_read_native_response(socket_t reader,
                                       memdbg_status_t *status,
                                       uint8_t **payload,
                                       uint32_t *plen) {
  memdbg_response_header_t rhdr;
  if (pal_socket_read_exact(reader, &rhdr, sizeof(rhdr)) < 0)
    return -1;

  *status = (memdbg_status_t)rhdr.status;
  *plen   = rhdr.length;

  if (rhdr.length > 0U) {
    *payload = legacy_read_exact_alloc(reader, rhdr.length);
    if (*payload == NULL) return -1;
  } else {
    *payload = NULL;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/*  Disassembler bridge                                                */
/* ------------------------------------------------------------------ */

memdbg_status_t legacy_handle_disasm(socket_t fd,
                                     const void *body,
                                     uint32_t body_len) {
  if (body == NULL || body_len < sizeof(legacy_disasm_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const legacy_disasm_request_t *lr =
      (const legacy_disasm_request_t *)body;
  uint32_t code_len = body_len - (uint32_t)sizeof(*lr);

  /* Build native memdbg_disasm_request_t + inline code. */
  uint32_t nbody_len = (uint32_t)sizeof(memdbg_disasm_request_t) + code_len;
  uint8_t *nbody = (uint8_t *)malloc(nbody_len > 0U ? nbody_len : 1U);
  if (nbody == NULL) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0
                           ? MEMDBG_OK : MEMDBG_ERR_NET;

  memdbg_disasm_request_t *nr = (memdbg_disasm_request_t *)nbody;
  memset(nr, 0, sizeof(*nr));
  nr->pid       = lr->pid;
  nr->address   = lr->address;
  nr->count_max = lr->max_count;
  nr->length    = code_len;
  if (code_len > 0U)
    memcpy(nbody + sizeof(*nr), (const uint8_t *)body + sizeof(*lr), code_len);

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  if (legacy_spawn_pair(&writer, &reader) < 0) {
    free(nbody);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  /* Call native disassembler — it writes CMD_SUCCESS + count + entries. */
  (void)memdbg_disasm_multiple(writer, nbody, nbody_len);
  free(nbody);
  (void)pal_socket_close(writer);

  /* Read native response: status(4B) + count(4B) + count * entry. */
  uint32_t nstatus = 0U;
  uint32_t count   = 0U;
  if (pal_socket_read_exact(reader, &nstatus, 4) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0U) { /* native CMD_SUCCESS is 0 */
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, nstatus) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (pal_socket_read_exact(reader, &count, 4) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (count > 131072U) { /* sanity cap */
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  uint32_t entries_size = count * (uint32_t)sizeof(memdbg_disasm_entry_t);
  uint8_t *entries = legacy_read_exact_alloc(reader, entries_size);
  (void)pal_socket_close(reader);

  if (entries == NULL && count > 0U)
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  /* Translate and send: legacy status(4B) + count(4B) + entries.
   * struct memdbg_disasm_entry_t and legacy_disasm_entry_t are identical. */
  uint32_t resp_size = 4U + 4U + entries_size;
  uint8_t *resp = (uint8_t *)malloc(resp_size > 0U ? resp_size : 1U);
  if (resp == NULL) { free(entries); return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }

  uint32_t s32 = LEGACY_CMD_SUCCESS;
  memcpy(resp, &s32, 4);
  memcpy(resp + 4, &count, 4);
  if (entries_size > 0U)
    memcpy(resp + 8, entries, entries_size);

  int rc = legacy_send_blob(fd, resp, resp_size);
  free(resp);
  free(entries);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ------------------------------------------------------------------ */
/*  Cross-reference bridge                                             */
/* ------------------------------------------------------------------ */

memdbg_status_t legacy_handle_xrefs(socket_t fd,
                                    const void *body,
                                    uint32_t body_len) {
  if (body == NULL || body_len < sizeof(legacy_xrefs_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const legacy_xrefs_request_t *lr =
      (const legacy_xrefs_request_t *)body;

  /* Build native memdbg_xrefs_to_request_t body. */
  memdbg_xrefs_to_request_t nreq;
  memset(&nreq, 0, sizeof(nreq));
  nreq.pid            = lr->pid;
  nreq.scan_address   = lr->scan_address;
  nreq.scan_length    = lr->scan_length;
  nreq.target_address = lr->target_address;

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  if (legacy_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)memdbg_xrefs_multiple(writer, (const uint8_t *)&nreq,
                               (uint32_t)sizeof(nreq));
  (void)pal_socket_close(writer);

  /* Read native response: status(4B) + count(8B) + count * addr(8B). */
  uint32_t nstatus = 0U;
  uint64_t count   = 0ULL;
  if (pal_socket_read_exact(reader, &nstatus, 4) < 0 ||
      pal_socket_read_exact(reader, &count, 8) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0U || count > 32768ULL) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, nstatus != 0U ? nstatus : LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  uint32_t addrs_size = (uint32_t)(count * 8ULL);
  uint8_t *addrs = legacy_read_exact_alloc(reader, addrs_size);
  (void)pal_socket_close(reader);

  if (addrs == NULL && count > 0ULL)
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  /* Send legacy response: status(4B) + count(8B) + addresses. */
  uint32_t resp_size = 4U + 8U + addrs_size;
  uint8_t *resp = (uint8_t *)malloc(resp_size > 0U ? resp_size : 1U);
  if (resp == NULL) { free(addrs); return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }

  uint32_t s32 = LEGACY_CMD_SUCCESS;
  memcpy(resp, &s32, 4);
  memcpy(resp + 4, &count, 8);
  if (addrs_size > 0U) memcpy(resp + 12, addrs, addrs_size);

  int rc = legacy_send_blob(fd, resp, resp_size);
  free(resp);
  free(addrs);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ------------------------------------------------------------------ */
/*  Remote function call bridge (process_call)                         */
/* ------------------------------------------------------------------ */

memdbg_status_t legacy_handle_proc_call(socket_t fd,
                                        const void *body,
                                        uint32_t body_len) {
  if (body == NULL || body_len < sizeof(legacy_proc_call_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const legacy_proc_call_request_t *lr =
      (const legacy_proc_call_request_t *)body;

  /* Build native request. */
  memdbg_process_call_request_t nreq;
  memset(&nreq, 0, sizeof(nreq));
  nreq.pid              = lr->pid;
  nreq.function_address = lr->function_address;
  memcpy(nreq.args, lr->args, sizeof(nreq.args));

  memdbg_packet_header_t fake_hdr;
  memset(&fake_hdr, 0, sizeof(fake_hdr));
  fake_hdr.magic    = MEMDBG_PACKET_MAGIC;
  fake_hdr.version  = MEMDBG_PROTOCOL_VERSION;
  fake_hdr.command  = MEMDBG_CMD_PROCESS_CALL;
  fake_hdr.length   = (uint32_t)sizeof(nreq);

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  if (legacy_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  /* Call native handler — uses send_response() callback that writes
   * a memdbg_response_header_t followed by payload to the writer fd. */
  (void)handle_process_call(writer, &fake_hdr, &nreq,
                            (uint32_t)sizeof(nreq),
                            send_response, memdbg_sleep_ms);
  (void)pal_socket_close(writer);

  memdbg_status_t nstatus = MEMDBG_OK;
  uint8_t *payload = NULL;
  uint32_t plen    = 0U;
  int ok = legacy_read_native_response(reader, &nstatus, &payload, &plen);
  (void)pal_socket_close(reader);

  if (ok < 0) {
    free(payload);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != MEMDBG_OK || plen < sizeof(memdbg_process_call_response_t)) {
    memdbg_status_t ret = legacy_send_memdbg_status(fd, nstatus);
    free(payload);
    return ret == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  const memdbg_process_call_response_t *nr =
      (const memdbg_process_call_response_t *)payload;

  /* Legacy response: status(4B) + rax(8B). */
  uint8_t resp[12];
  uint32_t s32 = LEGACY_CMD_SUCCESS;
  memcpy(resp, &s32, 4);
  memcpy(resp + 4, &nr->rax, 8);

  int rc = legacy_send_blob(fd, resp, sizeof(resp));
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ------------------------------------------------------------------ */
/*  ELF load bridge                                                    */
/* ------------------------------------------------------------------ */

memdbg_status_t legacy_handle_proc_elf_load(socket_t fd,
                                            const void *body,
                                            uint32_t body_len) {
  if (body == NULL || body_len < sizeof(legacy_proc_elf_load_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const legacy_proc_elf_load_request_t *lr =
      (const legacy_proc_elf_load_request_t *)body;

  if (lr->image_size == 0U || lr->image_size > (64ULL << 20))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  uint32_t elf_offset = (uint32_t)sizeof(*lr);
  if (body_len < elf_offset + lr->image_size)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  /* Build native memdbg_process_elf_load_request_t + inline ELF. */
  uint32_t nbody_len =
      (uint32_t)(sizeof(memdbg_process_elf_load_request_t) + lr->image_size);
  uint8_t *nbody = (uint8_t *)malloc(nbody_len > 0U ? nbody_len : 1U);
  if (nbody == NULL)
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  memdbg_process_elf_load_request_t *nr =
      (memdbg_process_elf_load_request_t *)nbody;
  memset(nr, 0, sizeof(*nr));
  nr->pid        = lr->pid;
  nr->flags      = lr->flags;
  nr->image_size = (uint64_t)lr->image_size;
  /* target_region and match_flags default to 0 (allocate new) */
  memcpy(nbody + sizeof(*nr),
         (const uint8_t *)body + elf_offset,
         lr->image_size);

  memdbg_packet_header_t fake_hdr;
  memset(&fake_hdr, 0, sizeof(fake_hdr));
  fake_hdr.magic   = MEMDBG_PACKET_MAGIC;
  fake_hdr.version = MEMDBG_PROTOCOL_VERSION;
  fake_hdr.command = MEMDBG_CMD_PROCESS_ELF_LOAD;
  fake_hdr.length  = nbody_len;

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  if (legacy_spawn_pair(&writer, &reader) < 0) {
    free(nbody);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  (void)handle_process_elf_load(writer, &fake_hdr, nbody, nbody_len);
  free(nbody);
  (void)pal_socket_close(writer);

  memdbg_status_t nstatus = MEMDBG_OK;
  uint8_t *payload = NULL;
  uint32_t plen    = 0U;
  int ok = legacy_read_native_response(reader, &nstatus, &payload, &plen);
  (void)pal_socket_close(reader);

  if (ok < 0) {
    free(payload);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != MEMDBG_OK ||
      plen < sizeof(memdbg_process_elf_load_response_t)) {
    memdbg_status_t ret = legacy_send_memdbg_status(fd, nstatus);
    free(payload);
    return ret == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  const memdbg_process_elf_load_response_t *er =
      (const memdbg_process_elf_load_response_t *)payload;

  /* Legacy response: status(4B) + entry_address(8B) + load_base(8B). */
  uint8_t resp[20];
  uint32_t s32 = LEGACY_CMD_SUCCESS;
  memcpy(resp, &s32, 4);
  memcpy(resp + 4,  &er->entry_address, 8);
  memcpy(resp + 12, &er->load_base, 8);

  int rc = legacy_send_blob(fd, resp, sizeof(resp));
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}
