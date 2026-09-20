// SPDX-License-Identifier: GPL-2.0-only
#include "networkmitm_device_pki.hpp"
#include "networkmitm_synthetic_pki.hpp"
#include "networkmitm_pki_trace.hpp"
#include "networkmitm_ssl_types.hpp"
#include "networkmitm_utils.hpp"
#include "shim/ssl_shim.h"
#include <cstdlib>
#include <cstring>

namespace ams::ssl::sf::impl {
bool g_targeted_device_pki_mode = true;
namespace {
nextendo::pki::RoutingPolicy g_routing;
static_assert(static_cast<u32>(ams::ssl::sf::CertificateFormat::Der) == 2);

bool ReadBool(const char *key, bool default_value) {
    u8 value = 0;
    u64 size = 0;
    const auto rc = ::setsysGetSettingsItemValue("network_mitm", key, &value, sizeof(value), &size);
    return R_SUCCEEDED(rc) && size == sizeof(value) ? value != 0 : default_value;
}

bool ReadPrograms(const char *key, nextendo::pki::Policy &policy) {
    char ids[512]{};
    u64 size = 0;
    const auto rc = ::setsysGetSettingsItemValue("network_mitm", key, ids, sizeof(ids), &size);
    policy.programs = {};
    policy.count = 0;
    // Reject a full buffer (possible truncation) and the entire invalid list.
    return R_SUCCEEDED(rc) && size < sizeof(ids) && nextendo::pki::ParsePrograms(policy, ids, size);
}

struct SslBackend {
    Service *context;
    const sm::MitmProcessInfo &client;
    u64 context_id;
    bool trace;
    static constexpr u32 NoMemory = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    static constexpr u32 InvalidSize = MAKERESULT(Module_Libnx, LibnxError_BadInput);
    unsigned char *Allocate(size_t size) { return static_cast<unsigned char *>(std::malloc(size)); }
    void Free(unsigned char *data) { std::free(data); }
    void Log(const char *stage, u32 rc) {
        TracePki(trace, client, context_id, stage, "result=0x%08X origin=%s", rc,
                 std::strcmp(stage, "fallback_allocate") == 0 ||
                 std::strcmp(stage, "fallback_validate_lengths") == 0 ? "local" : "ssl_ipc");
    }
    u32 ForwardOriginal(u32 type, u64 &id) {
        TracePki(trace, client, context_id, "RegisterInternalPki", "phase=begin type=%u", type);
        return sslContextForSystemRegisterInternalPki_sfMitm(context, type, &id);
    }
    void LogOriginal(u32 type, u32 rc, u64 id) {
        if (rc == 0) {
            TracePki(trace, client, context_id, "RegisterInternalPki", "type=%u forward_result=0x%08X pki_id=%llu",
                     type, rc, static_cast<unsigned long long>(id));
        } else {
            TracePki(trace, client, context_id, "RegisterInternalPki", "type=%u forward_result=0x%08X", type, rc);
        }
    }
    u32 Generate(const nextendo::pki::KeyAndCertParams &params,
                 void *cert, size_t cert_capacity, void *key, size_t key_capacity,
                 u32 &cert_size, u32 &key_size) {
        return sslContextForSystemGeneratePrivateKeyAndCert_sfMitm(context, 1, &params, sizeof(params),
            cert, cert_capacity, key, key_capacity, &cert_size, &key_size);
    }
    u32 Import(const void *cert, size_t cert_size, const void *key, size_t key_size, u64 &id) {
        return sslContextForSystemImportClientCertKeyPki_sfMitm(context,
            static_cast<u32>(ams::ssl::sf::CertificateFormat::Der), cert, cert_size, key, key_size, &id);
    }
};
}

void InitializeDevicePkiPolicy() {
    g_routing.targeted = ReadBool("targeted_device_pki_mode", true);
    g_targeted_device_pki_mode = g_routing.targeted;
    g_routing.trace_requested = ReadBool("trace_internal_pki", false);
    g_routing.fallback_programs.enabled = ReadBool("enable_device_cert_fallback", false);
    const bool mitm_valid = ReadPrograms("mitm_program_ids", g_routing.mitm_programs);
    const bool fallback_valid = ReadPrograms("device_cert_fallback_program_ids", g_routing.fallback_programs);
    InitializePkiTrace(g_routing.trace_requested || g_routing.fallback_programs.enabled);
    const sm::MitmProcessInfo self{};
    TracePki(true, self, 0, "DevicePkiPolicy",
        "targeted=%u mitm_valid=%u mitm_count=%llu fallback_enabled=%u fallback_valid=%u fallback_count=%llu trigger=0x0000167B",
        static_cast<unsigned>(g_routing.targeted), static_cast<unsigned>(mitm_valid),
        static_cast<unsigned long long>(g_routing.mitm_programs.count),
        static_cast<unsigned>(g_routing.fallback_programs.enabled), static_cast<unsigned>(fallback_valid),
        static_cast<unsigned long long>(g_routing.fallback_programs.count));
}

bool ShouldTargetProgram(ncm::ProgramId program_id) {
    return g_routing.Targets(static_cast<u64>(program_id));
}

bool ShouldMitmProgram(ncm::ProgramId program_id, bool system_service) {
    return g_routing.ShouldMitm(static_cast<u64>(program_id), system_service,
                               ncm::IsApplicationId(program_id), g_should_mitm_all);
}

nextendo::pki::ClientOptions GetClientPkiOptions(ncm::ProgramId program_id) {
    if (!ShouldTargetProgram(program_id)) return {};
    return g_routing.Options(static_cast<u64>(program_id));
}

Result RegisterSystemClientPki(Service *context, const sm::MitmProcessInfo &client,
                              u64 context_id, nextendo::pki::ClientOptions options,
                              u32 type, u64 *out_id) {
    if (options.trace) TraceResourceSnapshot("before_pki");
    SslBackend backend{context, client, context_id, options.trace};
    u64 real_id = 0;
    const Result rc = nextendo::pki::RegisterAfterOriginalFailure(backend, options.fallback, type, real_id);
    if (R_SUCCEEDED(rc)) *out_id = real_id;
    TracePki(options.trace, client, context_id, "RegisterInternalPki", "phase=complete result=0x%08X", rc.GetValue());
    if (R_SUCCEEDED(rc)) {
        TracePki(options.trace, client, context_id, "ClientPki", "pki_id=%llu", static_cast<unsigned long long>(real_id));
    }
    if (options.trace) TraceResourceSnapshot("after_pki");
    return rc;
}
}
