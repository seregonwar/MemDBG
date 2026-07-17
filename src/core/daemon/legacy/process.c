/*
 * memDBG - ps5debug compat: process, memory, and metadata handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"

memdbg_status_t legacy_handle_version(socket_t fd) {
  static const char version[] = "1.3";
  return legacy_send_sized_string(fd, version, (uint32_t)(sizeof(version) - 1U)) == 0
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_branding(socket_t fd) {
  static const char brand[] = "MemDBG ps5debug-compat\0MDBG-1";
  return legacy_send_sized_string(fd, brand, (uint32_t)(sizeof(brand) - 1U)) == 0
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_platform_id_cmd(socket_t fd) {
  uint16_t platform = (uint16_t)legacy_platform_id();
  return legacy_send_blob(fd, &platform, sizeof(platform)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_fw_version(socket_t fd) {
  uint16_t fw_version = 0U;
  return legacy_send_blob(fd, &fw_version, sizeof(fw_version)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_process_list(socket_t fd) {
  memdbg_process_list_t list;
  memset(&list, 0, sizeof(list));
  memdbg_status_t st = memdbg_process_list(&list);
  if (st != MEMDBG_OK || list.count == 0U || list.count > UINT32_MAX) {
    memdbg_process_list_free(&list);
    return legacy_send_memdbg_status(fd, st == MEMDBG_OK ? MEMDBG_ERR_NOT_FOUND : st) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
  uint32_t count = (uint32_t)list.count;
  legacy_proc_list_entry_t *entries = (legacy_proc_list_entry_t *)calloc(count, sizeof(*entries));
  if (entries == NULL) { memdbg_process_list_free(&list); return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  for (uint32_t i = 0U; i < count; ++i) {
    legacy_copy_fixed(entries[i].name, sizeof(entries[i].name), list.entries[i].name);
    entries[i].pid = list.entries[i].pid;
  }
  int rc = (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
            legacy_send_blob(fd, &count, sizeof(count)) == 0 &&
            legacy_send_blob(fd, entries, (size_t)count * sizeof(*entries)) == 0) ? 0 : -1;
  free(entries); memdbg_process_list_free(&list);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_process_maps(socket_t fd, const void *body, uint32_t body_len) {
  const legacy_proc_info_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req)))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_proc_info_packet_t *)body;
  memdbg_map_list_t list; memset(&list, 0, sizeof(list));
  memdbg_status_t st = memdbg_process_maps((int)req->pid, &list);
  if (st != MEMDBG_OK || list.count == 0U || list.count > UINT32_MAX) {
    memdbg_process_maps_free(&list);
    return legacy_send_memdbg_status(fd, st == MEMDBG_OK ? MEMDBG_ERR_NOT_FOUND : st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
  uint32_t count = (uint32_t)list.count;
  legacy_proc_maps_entry_t *entries = (legacy_proc_maps_entry_t *)calloc(count, sizeof(*entries));
  if (entries == NULL) { memdbg_process_maps_free(&list); return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  for (uint32_t i = 0U; i < count; ++i) {
    legacy_copy_fixed(entries[i].name, sizeof(entries[i].name), list.entries[i].name);
    entries[i].start = list.entries[i].start; entries[i].end = list.entries[i].end;
    entries[i].offset = 0U; entries[i].protection = (uint16_t)(list.entries[i].protection & 0xFFFFU);
  }
  int rc = (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
            legacy_send_blob(fd, &count, sizeof(count)) == 0 &&
            legacy_send_blob(fd, entries, (size_t)count * sizeof(*entries)) == 0) ? 0 : -1;
  free(entries); memdbg_process_maps_free(&list);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_process_info(socket_t fd, const void *body, uint32_t body_len) {
  const legacy_proc_info_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req)))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_proc_info_packet_t *)body;
  memdbg_process_info_response_t info; memset(&info, 0, sizeof(info));
  memdbg_status_t st = memdbg_process_info((int)req->pid, &info);
  if (st != MEMDBG_OK)
    return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  legacy_proc_info_response_t out; memset(&out, 0, sizeof(out));
  out.pid = (uint32_t)info.pid;
  legacy_copy_fixed(out.name, sizeof(out.name), info.name);
  legacy_copy_fixed(out.path, sizeof(out.path), info.path);
  legacy_copy_fixed(out.title_id, sizeof(out.title_id), info.title_id);
  legacy_copy_fixed(out.content_id, sizeof(out.content_id), info.content_id);
  return (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 && legacy_send_blob(fd, &out, sizeof(out)) == 0)
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_memory_read(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len) {
  const legacy_memory_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req)))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_memory_packet_t *)body;
  if (!legacy_rw_allowed(cfg, req->length))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint8_t *buffer = (uint8_t *)malloc(LEGACY_RW_CHUNK);
  if (buffer == NULL) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) { free(buffer); return MEMDBG_ERR_NET; }
  uint64_t addr = req->address; uint32_t rem = req->length;
  while (rem != 0U) {
    uint32_t chunk = rem > LEGACY_RW_CHUNK ? LEGACY_RW_CHUNK : rem;
    size_t got = 0U; memset(buffer, 0, chunk);
    (void)memdbg_memory_read((int)req->pid, addr, buffer, chunk, &got);
    if (got < chunk) memset(buffer + got, 0, (size_t)chunk - got);
    if (legacy_send_blob(fd, buffer, chunk) != 0) { free(buffer); return MEMDBG_ERR_NET; }
    addr += chunk; rem -= chunk;
  }
  free(buffer); return MEMDBG_OK;
}

memdbg_status_t legacy_handle_memory_write(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len) {
  const legacy_memory_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req)))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_memory_packet_t *)body;
  if (!legacy_rw_allowed(cfg, req->length))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint8_t *buffer = (uint8_t *)malloc(LEGACY_RW_CHUNK);
  if (buffer == NULL) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) { free(buffer); return MEMDBG_ERR_NET; }
  uint64_t addr = req->address; uint32_t rem = req->length; bool failed = false;
  while (rem != 0U) {
    uint32_t chunk = rem > LEGACY_RW_CHUNK ? LEGACY_RW_CHUNK : rem;
    if (pal_socket_read_exact(fd, buffer, chunk) < 0) { free(buffer); return MEMDBG_ERR_NET; }
    size_t written = 0U;
    if (memdbg_memory_write((int)req->pid, addr, buffer, chunk, &written) != MEMDBG_OK || written != chunk) failed = true;
    addr += chunk; rem -= chunk;
  }
  free(buffer);
  return legacy_send_status(fd, failed ? LEGACY_CMD_ERROR : LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_write_multi(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len) {
  const legacy_proc_write_multi_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req)))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_proc_write_multi_packet_t *)body;
  if (req->count > LEGACY_WRITE_MULTI_MAX_COUNT)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint8_t *buffer = (uint8_t *)malloc(LEGACY_RW_CHUNK);
  if (buffer == NULL) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  bool want_status = (req->flags & LEGACY_WRITE_MULTI_STATUS) != 0U;
  uint8_t *status_bytes = (want_status && req->count != 0U) ? (uint8_t *)calloc(req->count, sizeof(*status_bytes)) : NULL;
  if (want_status && req->count != 0U && status_bytes == NULL) { free(buffer); return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) { free(status_bytes); free(buffer); return MEMDBG_ERR_NET; }
  for (uint32_t i = 0U; i < req->count; ++i) {
    legacy_proc_write_multi_entry_t entry; bool failed = false;
    if (pal_socket_read_exact(fd, &entry, sizeof(entry)) < 0) { free(status_bytes); free(buffer); return MEMDBG_ERR_NET; }
    if (entry.length > LEGACY_WRITE_MULTI_MAX_ENTRY || !legacy_rw_allowed(cfg, entry.length)) { free(status_bytes); free(buffer); return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
    uint64_t addr = entry.address; uint32_t rem = entry.length;
    while (rem != 0U) {
      uint32_t chunk = rem > LEGACY_RW_CHUNK ? LEGACY_RW_CHUNK : rem;
      if (pal_socket_read_exact(fd, buffer, chunk) < 0) { free(status_bytes); free(buffer); return MEMDBG_ERR_NET; }
      size_t written = 0U;
      if (memdbg_memory_write((int)req->pid, addr, buffer, chunk, &written) != MEMDBG_OK || written != chunk) failed = true;
      addr += chunk; rem -= chunk;
    }
    if (status_bytes != NULL) status_bytes[i] = failed ? 1U : 0U;
  }
  if (status_bytes != NULL && legacy_send_blob(fd, status_bytes, req->count) != 0) { free(status_bytes); free(buffer); return MEMDBG_ERR_NET; }
  free(status_bytes); free(buffer);
  return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_process_alloc(socket_t fd, const void *body, uint32_t body_len, bool hinted) {
  uint32_t pid, length; uint64_t hint = 0U;
  if (hinted) {
    const legacy_proc_alloc_hinted_packet_t *r;
    if (!legacy_has_body(body, body_len, sizeof(*r))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
    r = (const legacy_proc_alloc_hinted_packet_t *)body; pid = r->pid; length = r->length; hint = r->hint;
  } else {
    const legacy_proc_alloc_packet_t *r;
    if (!legacy_has_body(body, body_len, sizeof(*r))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
    r = (const legacy_proc_alloc_packet_t *)body; pid = r->pid; length = r->length;
  }
  if (pid == 0U || length == 0U) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint64_t addr = 0U;
  memdbg_status_t st = pal_memory_alloc((int)pid, hint, length, MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE | MEMDBG_MAP_PROT_EXEC, hinted ? 1U : 0U, &addr);
  legacy_proc_alloc_response_t out; memset(&out, 0, sizeof(out)); out.address = addr;
  return (legacy_send_memdbg_status(fd, st) == 0 && ((st == MEMDBG_OK || hinted) ? legacy_send_blob(fd, &out, sizeof(out)) == 0 : true)) ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_process_free(socket_t fd, const void *body, uint32_t body_len) {
  const legacy_proc_free_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_proc_free_packet_t *)body;
  if (req->pid == 0U || req->address == 0U || req->length == 0U) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  memdbg_status_t st = pal_memory_free((int)req->pid, req->address, req->length);
  return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_process_protect(socket_t fd, const void *body, uint32_t body_len) {
  const legacy_proc_protect_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_proc_protect_packet_t *)body;
  if (req->pid == 0U || req->address == 0U || req->length == 0U || (req->protection & ~(MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE | MEMDBG_MAP_PROT_EXEC)) != 0U)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  memdbg_status_t st = pal_memory_protect((int)req->pid, req->address, req->length, req->protection, NULL);
  return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_first_map(socket_t fd, const void *body, uint32_t body_len) {
  const legacy_proc_info_packet_t *req;
  if (!legacy_has_body(body, body_len, sizeof(*req))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  req = (const legacy_proc_info_packet_t *)body;
  memdbg_map_list_t list; memset(&list, 0, sizeof(list));
  memdbg_status_t st = memdbg_process_maps((int)req->pid, &list);
  if (st != MEMDBG_OK || list.count == 0U) { memdbg_process_maps_free(&list); return legacy_send_memdbg_status(fd, st == MEMDBG_OK ? MEMDBG_ERR_NOT_FOUND : st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  int64_t first = (int64_t)list.entries[0].start;
  memdbg_process_maps_free(&list);
  return (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 && legacy_send_blob(fd, &first, sizeof(first)) == 0) ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_install(socket_t fd) {
  uint64_t rpc_stub = 0U;
  return (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 && legacy_send_blob(fd, &rpc_stub, sizeof(rpc_stub)) == 0) ? MEMDBG_OK : MEMDBG_ERR_NET;
}
