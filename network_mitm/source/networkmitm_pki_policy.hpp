// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace nextendo::pki {
// This experiment is intentionally restricted to the observed NIM, Account, and NPNS clients.
// Keep these values in the policy layer so malformed settings cannot widen the
// MITM/fallback client set at runtime.
constexpr std::uint64_t NimProgramId = 0x0100000000000025ULL;
constexpr std::uint64_t AccountProgramId = 0x010000000000001EULL;
constexpr std::uint64_t NpnsProgramId = 0x010000000000002FULL;

// Account-link diagnostics are deliberately a fixed, reviewed set. These IDs
// are not parsed from configuration: a setting must never turn ordinary ssl
// into a general program-ID interception facility.
constexpr std::array<std::uint64_t, 4> AccountLinkDiagnosticProgramIds{{
    0x0100000000001000ULL, // qlaunch
    0x0100000000001011ULL, // LibAppletAuth
    0x0100000000001042ULL, // systemWeb
    0x0100000000001043ULL, // openWeb
}};

enum class ServiceRoute : std::uint8_t {
    OrdinarySsl,
    SystemSsl,
};

constexpr bool IsAccountLinkDiagnosticProgram(std::uint64_t program) {
    for (const auto candidate : AccountLinkDiagnosticProgramIds)
        if (candidate == program) return true;
    return false;
}

constexpr bool AccountLinkDiagnosticCandidatesAreUnique() {
    for (std::size_t i = 0; i < AccountLinkDiagnosticProgramIds.size(); ++i)
        for (std::size_t j = i + 1; j < AccountLinkDiagnosticProgramIds.size(); ++j)
            if (AccountLinkDiagnosticProgramIds[i] == AccountLinkDiagnosticProgramIds[j]) return false;
    return true;
}
static_assert(AccountLinkDiagnosticCandidatesAreUnique());

constexpr std::size_t MaxPrograms = 3;

struct Policy {
    bool enabled = false;
    std::array<std::uint64_t, MaxPrograms> programs{};
    std::size_t count = 0;

    bool Contains(std::uint64_t program) const {
        // Defense in depth: only NIM, Account, and NPNS are allowed targets.
        if (program != NimProgramId && program != AccountProgramId && program != NpnsProgramId) return false;
        for (std::size_t i = 0; i < count; ++i)
            if (programs[i] == program) return true;
        return false;
    }

    bool Allows(std::uint64_t program, std::uint32_t type) const {
        return enabled && type == 1 && Contains(program);
    }
};

struct ClientOptions {
    bool trace = false;
    bool fallback = false;
};

struct RoutingPolicy {
    // Missing configuration must not reactivate v1's broad MITM behavior.
    bool targeted = true;
    bool trace_requested = false;
    // Disabled by default. When enabled, only the fixed ordinary-ssl set above
    // is observed, for one account-link diagnostic run.
    bool account_link_diagnostic = false;
    Policy mitm_programs;
    Policy fallback_programs;

    bool Targets(std::uint64_t program) const { return mitm_programs.Contains(program); }

    bool ShouldMitm(std::uint64_t program, ServiceRoute service,
                    bool application, bool legacy_mitm_all) const {
        (void)application;
        (void)legacy_mitm_all;
        if (!targeted) return false;
        // This release registers only ssl:s. Ordinary ssl must remain native even
        // if a stale diagnostic setting is present.
        if (service == ServiceRoute::SystemSsl) return Targets(program);
        return false;
    }

    ClientOptions Options(std::uint64_t program) const {
        if (!targeted || !Targets(program)) return {};
        const bool fallback = fallback_programs.Allows(program, 1);
        // Error metadata is retained when fallback is enabled, even if tracing
        // was explicitly off. This cannot expand the selected client set.
        return {trace_requested || fallback, fallback};
    }

    bool ShouldTraceOrdinary(std::uint64_t program) const {
        (void)program;
        return false;
    }
};

// Exact NIM, Account, and/or NPNS Program IDs, with optional ASCII spaces.
// Accepts: empty, single ID, two IDs, or all three space-separated.
// Rejects any other ID, lists with commas/semicolons, or malformed input.
inline bool ParsePrograms(Policy &policy, const char *data, std::size_t size) {
    policy.programs = {};
    policy.count = 0;
    if (!data || size == 0) return true;
    if (data[size - 1] == '\0') --size;

    std::size_t pos = 0;
    auto spaces = [&] { while (pos < size && data[pos] == ' ') ++pos; };

    spaces();
    if (pos == size) return true;

    // Parse up to MaxPrograms IDs
    while (pos < size && policy.count < MaxPrograms) {
        if (size - pos < 16) {
            policy.count = 0;
            return false;
        }

        std::uint64_t value = 0;
        for (unsigned i = 0; i < 16; ++i) {
            const char c = data[pos++];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else {
                policy.count = 0;
                return false;
            }
            value = (value << 4) | digit;
        }

        // Only NIM, Account, and NPNS are allowed
        if (value != NimProgramId && value != AccountProgramId && value != NpnsProgramId) {
            policy.count = 0;
            return false;
        }

        // Check for duplicates
        for (std::size_t i = 0; i < policy.count; ++i) {
            if (policy.programs[i] == value) {
                policy.count = 0;
                return false;
            }
        }

        policy.programs[policy.count++] = value;

        spaces();
        if (pos == size) break;

        // If there's more content after spaces, it must be another hex ID
        if (pos < size && policy.count >= MaxPrograms) {
            policy.count = 0;
            return false;
        }
    }

    // Ensure no trailing content
    if (pos != size) {
        policy.count = 0;
        return false;
    }
    return true;
}
}
