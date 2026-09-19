// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
extern bool g_trace_internal_pki;
u64 AllocateTraceContextId();
void InitializePkiTrace(bool force = false);
// Metadata only. Never pass buffer contents, hostnames or credentials here.
void TracePki(const sm::MitmProcessInfo &client, u64 context_id,
              const char *event, const char *format, ...)
    __attribute__((format(printf, 4, 5)));
}
