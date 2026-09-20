// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
u64 AllocateTraceContextId();
void InitializePkiTrace(bool enabled);
// Read-only counters for this process resource group; never changes limits.
void TraceResourceSnapshot(const char *stage);
// Metadata only. Never pass buffer contents, hostnames or credentials here.
void TracePki(bool enabled, const sm::MitmProcessInfo &client, u64 context_id,
              const char *event, const char *format, ...)
    __attribute__((format(printf, 5, 6)));
}
