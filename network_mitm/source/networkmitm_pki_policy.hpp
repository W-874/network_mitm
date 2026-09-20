// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace nextendo::pki {
constexpr std::size_t MaxPrograms = 16;
struct Policy {
    bool enabled = false;
    std::array<std::uint64_t, MaxPrograms> programs{};
    std::size_t count = 0;
    bool Contains(std::uint64_t program) const {
        if (program == 0) return false;
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
    Policy mitm_programs;
    Policy fallback_programs;
    bool Targets(std::uint64_t program) const { return mitm_programs.Contains(program); }
    bool ShouldMitm(std::uint64_t program, bool system_service, bool application,
                    bool legacy_mitm_all) const {
        (void)application;
        (void)legacy_mitm_all;
        // This resource-bounded build has no legacy broad-interception mode.
        return targeted && system_service && Targets(program);
    }
    ClientOptions Options(std::uint64_t program) const {
        if (!targeted || !Targets(program)) return {};
        const bool fallback = fallback_programs.Allows(program, 1);
        // Error metadata is retained when fallback is enabled, even if tracing
        // was explicitly off. This cannot expand the selected client set.
        return {trace_requested || fallback, fallback};
    }
};

// Exact 16-digit hex IDs separated by commas, optional ASCII spaces.
// Reject the whole list on malformed, truncated, duplicate or excessive input.
inline bool ParsePrograms(Policy &policy, const char *data, std::size_t size) {
    policy.programs = {};
    policy.count = 0;
    if (!data || size == 0) return true;
    if (data[size - 1] == '\0') --size;
    std::array<std::uint64_t, MaxPrograms> parsed{};
    std::size_t count = 0, pos = 0;
    auto spaces = [&] { while (pos < size && data[pos] == ' ') ++pos; };
    spaces();
    if (pos == size) return true;
    while (pos < size) {
        if (count == MaxPrograms || size - pos < 16) return false;
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 16; ++i) {
            const char c = data[pos++];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            value = (value << 4) | digit;
        }
        if (value == 0) return false;
        for (std::size_t i = 0; i < count; ++i)
            if (parsed[i] == value) return false;
        parsed[count++] = value;
        spaces();
        if (pos == size) break;
        if (data[pos++] != ',') return false;
        spaces();
        if (pos == size) return false;
    }
    policy.programs = parsed;
    policy.count = count;
    return true;
}
}
