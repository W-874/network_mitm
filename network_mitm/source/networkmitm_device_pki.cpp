// SPDX-License-Identifier: GPL-2.0-only
#include "networkmitm_device_pki.hpp"
#include "networkmitm_pki_policy.hpp"
#include "networkmitm_synthetic_pki.hpp"
#include "networkmitm_pki_trace.hpp"
#include "networkmitm_ssl_types.hpp"
#include "shim/ssl_shim.h"
#include <cstdlib>
#include <cstring>

namespace ams::ssl::sf::impl {
namespace {
nextendo::pki::Policy g_device_policy;
static_assert(static_cast<u32>(ams::ssl::sf::CertificateFormat::Der) == 2);
struct SslBackend {
    Service *context;
    const sm::MitmProcessInfo &client;
    u64 context_id;
    static constexpr u32 NoMemory = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    static constexpr u32 InvalidSize = MAKERESULT(Module_Libnx, LibnxError_BadInput);
    unsigned char *Allocate(size_t size) { return static_cast<unsigned char *>(std::malloc(size)); }
    void Free(unsigned char *data) { std::free(data); }
    void Log(const char *stage, u32 rc) {
        TracePki(client, context_id, stage, "result=0x%08X origin=%s", rc,
                 std::strcmp(stage, "fallback_allocate") == 0 ||
                 std::strcmp(stage, "fallback_validate_lengths") == 0 ? "local" : "ssl_ipc");
    }
    u32 Generate(const nextendo::pki::KeyAndCertParams &params,
                 void *cert, size_t cert_capacity, void *key, size_t key_capacity,
                 u32 &cert_size, u32 &key_size) {
        return sslContextGeneratePrivateKeyAndCert_sfMitm(context, 1, &params, sizeof(params),
            cert, cert_capacity, key, key_capacity, &cert_size, &key_size);
    }
    u32 Import(const void *cert, size_t cert_size, const void *key, size_t key_size, u64 &id) {
        return sslContextImportClientCertKeyPki_sfMitm(context,
            static_cast<u32>(ams::ssl::sf::CertificateFormat::Der), cert, cert_size, key, key_size, &id);
    }
};
}

void InitializeDevicePkiPolicy() {
    u8 enabled = 0;
    u64 enabled_size = 0;
    const auto enabled_rc = ::setsysGetSettingsItemValue("network_mitm", "enable_device_cert_fallback",
        &enabled, sizeof(enabled), &enabled_size);
    g_device_policy.enabled = R_SUCCEEDED(enabled_rc) && enabled_size == sizeof(enabled) && enabled != 0;
    char ids[512]{};
    u64 size = 0;
    const auto ids_rc = ::setsysGetSettingsItemValue("network_mitm", "device_cert_fallback_program_ids",
        ids, sizeof(ids), &size);
    // A full buffer may be truncated: reject, never accept a valid prefix.
    const bool valid = R_SUCCEEDED(ids_rc) && size < sizeof(ids) && nextendo::pki::ParsePrograms(g_device_policy, ids, size);
    if (!valid) {
        g_device_policy.programs = {};
        g_device_policy.count = 0;
    }
    InitializePkiTrace(g_device_policy.enabled);
    const sm::MitmProcessInfo self{};
    TracePki(self, 0, "DevicePkiPolicy", "enabled=%u allowlist_valid=%u program_count=%llu",
        static_cast<unsigned>(g_device_policy.enabled), static_cast<unsigned>(valid),
        static_cast<unsigned long long>(g_device_policy.count));
}


bool ShouldReplaceDevicePki(const sm::MitmProcessInfo &client, u32 type) {
    return g_device_policy.Allows(static_cast<u64>(client.program_id), type);
}

Result CreateDevicePki(Service *context, const sm::MitmProcessInfo &client,
                       u64 context_id, u64 *out_id) {
    SslBackend backend{context, client, context_id};
    u64 real_id = 0;
    const Result rc = nextendo::pki::CreateSyntheticClientPki(backend, real_id);
    if (R_SUCCEEDED(rc)) {
        *out_id = real_id;
        TracePki(client, context_id, "RegisterInternalPki", "path=synthetic result=0x%08X pki_id=%llu",
                 rc.GetValue(), static_cast<unsigned long long>(real_id));
    } else {
        TracePki(client, context_id, "RegisterInternalPki", "path=synthetic result=0x%08X no_prodinfo_retry=1", rc.GetValue());
    }
    return rc;
}
}
