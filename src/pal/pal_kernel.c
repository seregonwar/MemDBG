/*
 * memDBG - PAL: kernel memory primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_kernel.h"
#include "memdbg/pal/pal_kernel_fast.h"

#include <string.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#define MEMDBG_PAL_KERNEL_PS4 1
#include <errno.h>
#include <ps4/kernel.h>
#elif defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_PAL_KERNEL_PS5 1
#include <errno.h>
#include <ps5/kernel.h>
#endif

#if defined(MEMDBG_PAL_KERNEL_PS4) || defined(MEMDBG_PAL_KERNEL_PS5)
static memdbg_status_t kernel_errno_status(void) {
  switch (errno) {
  case EACCES:
  case EPERM:
    return MEMDBG_ERR_PERMISSION;
  case EFAULT:
  case EINVAL:
    return MEMDBG_ERR_PARAM;
  case ENOENT:
  case ESRCH:
    return MEMDBG_ERR_NOT_FOUND;
  default:
    return MEMDBG_ERR_IO;
  }
}
#endif

bool pal_kernel_supported(void) {
#if defined(MEMDBG_PAL_KERNEL_PS4) || defined(MEMDBG_PAL_KERNEL_PS5)
  return true;
#else
  return false;
#endif
}

memdbg_status_t pal_kernel_base(uint64_t *text_base, uint64_t *data_base) {
  if (text_base == NULL || data_base == NULL) return MEMDBG_ERR_PARAM;
#if defined(MEMDBG_PAL_KERNEL_PS5)
  *text_base = (uint64_t)(uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
  *data_base = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE;
  return MEMDBG_OK;
#elif defined(MEMDBG_PAL_KERNEL_PS4)
  *text_base = (uint64_t)(uintptr_t)KERNEL_ADDRESS_IMAGE_BASE;
  *data_base = (uint64_t)(uintptr_t)KERNEL_ADDRESS_IMAGE_BASE;
  return MEMDBG_OK;
#else
  *text_base = 0U;
  *data_base = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}

memdbg_status_t pal_kernel_read(uint64_t address, void *buffer, size_t length) {
  if (address == 0U || (buffer == NULL && length != 0U))
    return MEMDBG_ERR_PARAM;
  if (length == 0U) return MEMDBG_OK;

#if defined(MEMDBG_PAL_KERNEL_PS4) || defined(MEMDBG_PAL_KERNEL_PS5)
  errno = 0;
  int rc;
#if defined(MEMDBG_PAL_KERNEL_PS5)
  /* kernel_copyout is the safe SDK path; the fast rwpipe path can
     kernel-panic on arbitrary addresses, so only use it internally. */
  rc = kernel_copyout((intptr_t)address, buffer, length);
#else
  rc = kernel_copyout((intptr_t)address, buffer, length);
#endif
  if (rc != 0)
    return kernel_errno_status();
  return MEMDBG_OK;
#else
  (void)buffer;
  (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}

memdbg_status_t pal_kernel_write(uint64_t address, const void *buffer,
                                 size_t length) {
  if (address == 0U || (buffer == NULL && length != 0U))
    return MEMDBG_ERR_PARAM;
  if (length == 0U) return MEMDBG_OK;

#if defined(MEMDBG_PAL_KERNEL_PS4) || defined(MEMDBG_PAL_KERNEL_PS5)
  errno = 0;
  int rc;
#if defined(MEMDBG_PAL_KERNEL_PS5)
  /* kernel_copyin is the safe SDK path; see pal_kernel_read note. */
  rc = kernel_copyin(buffer, (intptr_t)address, length);
#else
  rc = kernel_copyin(buffer, (intptr_t)address, length);
#endif
  if (rc != 0)
    return kernel_errno_status();
  return MEMDBG_OK;
#else
  (void)buffer;
  (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}
