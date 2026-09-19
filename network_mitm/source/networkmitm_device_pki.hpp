// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stratosphere.hpp>
namespace ams::ssl::sf::impl {
void InitializeDevicePkiPolicy();
bool ShouldReplaceDevicePki(const sm::MitmProcessInfo &client, u32 type);
Result CreateDevicePki(Service *context, const sm::MitmProcessInfo &client,
                       u64 context_id, u64 *out_id);
}
