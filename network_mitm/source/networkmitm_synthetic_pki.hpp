// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace nextendo::pki {
struct KeyAndCertParams {
    std::uint32_t version;
    std::int32_t key_bits;
    std::uint64_t public_exponent;
    char common_name[64];
    std::uint32_t common_name_len;
    std::uint32_t reserved;
};
static_assert(sizeof(KeyAndCertParams) == 0x58);
static_assert(offsetof(KeyAndCertParams, version) == 0);
static_assert(offsetof(KeyAndCertParams, key_bits) == 4);
static_assert(offsetof(KeyAndCertParams, public_exponent) == 8);
static_assert(offsetof(KeyAndCertParams, common_name) == 0x10);
static_assert(offsetof(KeyAndCertParams, common_name_len) == 0x50);
constexpr std::size_t DerCapacity = 4096;

inline void ClearSecret(void *data, std::size_t size) {
    volatile unsigned char *p = static_cast<volatile unsigned char *>(data);
    while (size--) *p++ = 0;
}

// Transport/allocator boundary also permits host fault-injection tests. There is
// deliberately no RegisterInternalPki operation in this replacement path.
template<class Backend>
std::uint32_t CreateSyntheticClientPki(Backend &backend, std::uint64_t &out_id) {
    auto *storage = backend.Allocate(2 * DerCapacity);
    if (!storage) {
        backend.Log("fallback_allocate", Backend::NoMemory);
        return Backend::NoMemory;
    }
    struct Cleanup {
        Backend &backend;
        unsigned char *storage;
        ~Cleanup() {
            ClearSecret(storage, 2 * DerCapacity);
            backend.Free(storage);
        }
    } cleanup{backend, storage};
    std::memset(storage, 0, 2 * DerCapacity);
    KeyAndCertParams params{};
    params.version = 1;
    params.key_bits = 2048;
    params.public_exponent = 65537;
    constexpr char CommonName[] = "Nextendo Temporary Client";
    std::memcpy(params.common_name, CommonName, sizeof(CommonName));
    params.common_name_len = sizeof(CommonName) - 1;
    std::uint32_t cert_size = 0, key_size = 0;
    std::uint32_t rc = backend.Generate(params, storage, DerCapacity,
        storage + DerCapacity, DerCapacity, cert_size, key_size);
    backend.Log("fallback_generate", rc);
    if (rc != 0) return rc;
    if (cert_size == 0 || key_size == 0 || cert_size > DerCapacity || key_size > DerCapacity) {
        backend.Log("fallback_validate_lengths", Backend::InvalidSize);
        return Backend::InvalidSize;
    }
    std::uint64_t real_id = 0;
    rc = backend.Import(storage, cert_size, storage + DerCapacity, key_size, real_id);
    backend.Log("fallback_import", rc);
    if (rc == 0) out_id = real_id;
    return rc;
}

constexpr std::uint32_t ObservedDevicePkiError = 0x0000167B;

// Only the system-context wrapper calls this. A failed original registration
// may have changed context state: import errors are returned, never hidden.
template<class Backend>
std::uint32_t RegisterAfterOriginalFailure(Backend &backend, bool fallback_enabled,
                                         std::uint32_t type, std::uint64_t &out_id) {
    std::uint64_t original_id = 0;
    const std::uint32_t rc = backend.ForwardOriginal(type, original_id);
    backend.LogOriginal(type, rc, original_id);
    if (rc == 0) {
        out_id = original_id;
        return rc;
    }
    if (!fallback_enabled || type != 1 || rc != ObservedDevicePkiError) return rc;
    return CreateSyntheticClientPki(backend, out_id);
}

}
