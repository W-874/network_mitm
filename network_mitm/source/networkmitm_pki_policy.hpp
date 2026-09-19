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
    bool Allows(std::uint64_t program, std::uint32_t type) const {
        if (!enabled || type != 1 || program == 0) return false;
        for (std::size_t i = 0; i < count; ++i)
            if (programs[i] == program) return true;
        return false;
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
