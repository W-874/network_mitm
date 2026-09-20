// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stratosphere.hpp>
#include "networkmitm_pki_policy.hpp"
namespace ams::ssl::sf::impl {
extern bool g_targeted_device_pki_mode;
void InitializeDevicePkiPolicy();
bool ShouldTargetProgram(ncm::ProgramId program_id);
bool ShouldMitmProgram(ncm::ProgramId program_id, bool system_service);
nextendo::pki::ClientOptions GetClientPkiOptions(ncm::ProgramId program_id);
bool ShouldTraceOrdinaryProgram(ncm::ProgramId program_id);
Result RegisterSystemClientPki(Service *context, const sm::MitmProcessInfo &client,
                              u64 context_id, nextendo::pki::ClientOptions options,
                              u32 type, u64 *out_id);
}
