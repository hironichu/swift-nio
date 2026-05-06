//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if defined(_WIN32)

#include "CNIOWindows.h"

#include <assert.h>
#include <errno.h>
#include <mswsock.h>
#include <winbase.h>

int CNIOWindows_sendmmsg(SOCKET s, CNIOWindows_mmsghdr *msgvec, unsigned int vlen,
                         int flags) {
  // Windows has no sendmmsg syscall. Emulate by calling WSASendMsg in a loop.
  // This mirrors what Linux sendmmsg does: send as many messages as possible,
  // stopping on the first error (if no messages were sent, return -1).
  if (vlen == 0) return 0;

  static LPFN_WSASENDMSG pfnWSASendMsg = NULL;
  if (pfnWSASendMsg == NULL) {
    GUID guid = WSAID_WSASENDMSG;
    DWORD cbBytesReturned = 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &pfnWSASendMsg, sizeof(pfnWSASendMsg),
                 &cbBytesReturned, NULL, NULL) == SOCKET_ERROR) {
      return SOCKET_ERROR;
    }
  }

  for (unsigned int i = 0; i < vlen; i++) {
    DWORD bytesSent = 0;
    LPWSAMSG msg = (LPWSAMSG)&msgvec[i].msg_hdr;
    if (pfnWSASendMsg(s, msg, (DWORD)flags, &bytesSent, NULL, NULL) == SOCKET_ERROR) {
      // Return the count of messages sent so far, or SOCKET_ERROR if none.
      return (i == 0) ? SOCKET_ERROR : (int)i;
    }
    msgvec[i].msg_len = (unsigned int)bytesSent;
  }
  return (int)vlen;
}

int CNIOWindows_recvmmsg(SOCKET s, CNIOWindows_mmsghdr *msgvec,
                         unsigned int vlen, int flags,
                         struct timespec *timeout) {
  // Windows has no recvmmsg syscall. Emulate by calling WSARecvMsg in a loop.
  // Semantics mirror Linux recvmmsg: receive as many messages as possible,
  // stopping on the first error. Returns the count of messages received, or
  // SOCKET_ERROR (with WSAGetLastError() set) if the very first receive fails.
  if (vlen == 0) return 0;

  static LPFN_WSARECVMSG pfnWSARecvMsg = NULL;
  if (pfnWSARecvMsg == NULL) {
    GUID guid = WSAID_WSARECVMSG;
    DWORD cbBytesReturned = 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &pfnWSARecvMsg, sizeof(pfnWSARecvMsg),
                 &cbBytesReturned, NULL, NULL) == SOCKET_ERROR) {
      return SOCKET_ERROR;
    }
  }

  for (unsigned int i = 0; i < vlen; i++) {
    DWORD dwBytesReceived = 0;
    LPWSAMSG msg = (LPWSAMSG)&msgvec[i].msg_hdr;
    if (pfnWSARecvMsg(s, msg, &dwBytesReceived, NULL, NULL) == SOCKET_ERROR) {
      // On any error after partial success, return what we received so far.
      // On first-message failure, return SOCKET_ERROR so the caller can
      // inspect WSAGetLastError() (e.g. WSAEWOULDBLOCK → .wouldBlock).
      return (i == 0) ? SOCKET_ERROR : (int)i;
    }
    msgvec[i].msg_len = (unsigned int)dwBytesReceived;
  }
  return (int)vlen;
}

const void *CNIOWindows_CMSG_DATA(const WSACMSGHDR *pcmsg) {
  return WSA_CMSG_DATA(pcmsg);
}

void *CNIOWindows_CMSG_DATA_MUTABLE(LPWSACMSGHDR pcmsg) {
  return WSA_CMSG_DATA(pcmsg);
}

WSACMSGHDR *CNIOWindows_CMSG_FIRSTHDR(const WSAMSG *msg) {
  return WSA_CMSG_FIRSTHDR(msg);
}

WSACMSGHDR *CNIOWindows_CMSG_NXTHDR(const WSAMSG *msg, LPWSACMSGHDR cmsg) {
  return WSA_CMSG_NXTHDR(msg, cmsg);
}

size_t CNIOWindows_CMSG_LEN(size_t length) {
  return WSA_CMSG_LEN(length);
}

size_t CNIOWindows_CMSG_SPACE(size_t length) {
  return WSA_CMSG_SPACE(length);
}

int CNIOWindows_errno(void) {
    return errno;
}

DWORD CNIOWindows_FormatGetLastError(DWORD errorCode, LPSTR errorMsg) {
  return FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    errorCode,
    0, // Default language
    errorMsg,
    0,
    NULL
  );
}

#endif
