// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <cstdint>

namespace nextendo::diagnostic {
// The ordinary ssl diagnostic must always make exactly one original command-8
// call and return its Result unchanged. It intentionally has no access to the
// synthetic-PKI generator/importer used by the separate NIM ssl:s path.
template <class Backend>
std::uint32_t ForwardOrdinaryRegisterInternalPki(Backend &backend,
                                                 std::uint32_t type,
                                                 std::uint64_t *out_id) {
    // Pass the caller's output storage directly to preserve all original IPC
    // output semantics, including any unusual failure-path behavior.
    const std::uint32_t result = backend.ForwardOriginal(type, out_id);
    backend.LogOriginal(type, result);
    return result;
}
} // namespace nextendo::diagnostic
