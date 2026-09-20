// SPDX-License-Identifier: GPL-2.0-only
#include "networkmitm_pki_policy.hpp"
#include "networkmitm_synthetic_pki.hpp"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
using namespace nextendo::pki;

void TestPolicy() {
    Policy p;
    assert(!p.Allows(0x0100000000001234ULL, 1));
    p.enabled = true;
    assert(ParsePrograms(p, nullptr, 0));
    assert(!p.Allows(0x0100000000001234ULL, 1));
    auto parse = [&](const std::string &s) { return ParsePrograms(p, s.data(), s.size()); };
    assert(parse(" 0100000000001234, 010000000000ABCD "));
    assert(p.count == 2);
    assert(p.Allows(0x0100000000001234ULL, 1));
    assert(p.Allows(0x010000000000ABCDULL, 1));
    assert(!p.Allows(0x0100000000001234ULL, 0));
    assert(!p.Allows(0x0100000000001234ULL, 2));
    assert(!p.Allows(0x0100000000001234ULL, 0xFFFFFFFF));
    assert(!p.Allows(0x0100000000009999ULL, 1));
    p.enabled = false;
    assert(!p.Allows(0x0100000000001234ULL, 1));
    p.enabled = true;
    for (const auto *bad : {"*", "0x0100000000001234", "010000000000123", "01000000000012345",
            "0000000000000000", "0100000000001234,", ",0100000000001234",
            "0100000000001234,0100000000001234", "0100000000001234;010000000000abcd",
            "0100000000001234,010000000000ZZZZ"}) {
        assert(parse("0100000000001234"));
        assert(!parse(bad));
        assert(p.count == 0); // no valid prefix survives an invalid suffix
        assert(!p.Allows(0x0100000000001234ULL, 1));
    }
    std::string many;
    for (unsigned i=1; i<=16; ++i) {
        char id[17]; std::snprintf(id, sizeof(id), "%016X", i);
        if (i>1) many += ',';
        many += id;
    }
    assert(parse(many) && p.count == 16);
    assert(!parse(many + ",0000000000000011") && p.count == 0);
    const char terminated[] = "0100000000001234";
    assert(ParsePrograms(p, terminated, sizeof(terminated)));
    std::string embedded = std::string(terminated) + '\0' + ",0100000000004321";
    assert(!parse(embedded));
    // Exhaust malformed lengths/bytes without leaking a previous selection.
    for (unsigned n=0; n<1024; ++n) {
        std::string fuzz(n, static_cast<char>(n & 255));
        parse(fuzz);
        assert(p.count <= MaxPrograms);
    }
}

struct FakeBackend {
    static constexpr std::uint32_t NoMemory = 0xA001;
    static constexpr std::uint32_t InvalidSize = 0xA002;
    bool allocation_failure = false;
    std::uint32_t original_result = 0;
    std::uint64_t original_id = 0x777788889999AAAAULL;
    unsigned originals = 0;
    std::vector<std::string> calls;
    std::uint32_t ForwardOriginal(std::uint32_t, std::uint64_t &id) {
        ++originals; calls.emplace_back("original"); id = original_id;
        return original_result;
    }
    void LogOriginal(std::uint32_t, std::uint32_t rc, std::uint64_t) {
        stages.emplace_back("original"); results.push_back(rc);
    }
    std::uint32_t generate_result = 0, import_result = 0;
    std::uint32_t cert_length = 987, key_length = 1234;
    std::uint64_t real_id = 0xFEDCBA9876543210ULL;
    unsigned allocations = 0, generates = 0, imports = 0, frees = 0;
    std::vector<std::string> stages;
    std::vector<std::uint32_t> results;
    unsigned char *Allocate(std::size_t size) {
        ++allocations;
        assert(size == 2 * DerCapacity);
        return allocation_failure ? nullptr : static_cast<unsigned char *>(std::malloc(size));
    }
    void Free(unsigned char *data) {
        ++frees;
        for (std::size_t i=0; i<2*DerCapacity; ++i) assert(data[i] == 0);
        std::free(data);
    }
    void Log(const char *stage, std::uint32_t result) { stages.emplace_back(stage); results.push_back(result); }
    std::uint32_t Generate(const KeyAndCertParams &p, void *cert, std::size_t cs,
                          void *key, std::size_t ks, std::uint32_t &co, std::uint32_t &ko) {
        ++generates; calls.emplace_back("generate");
        assert(cs == DerCapacity && ks == DerCapacity);
        assert(p.version == 1 && p.key_bits == 2048 && p.public_exponent == 65537);
        assert(std::strcmp(p.common_name, "Nextendo Temporary Client") == 0);
        assert(p.common_name_len == std::strlen(p.common_name) && p.reserved == 0);
        std::memset(cert, 0x42, cs);
        std::memset(key, 0xA5, ks); // simulated key bytes must be wiped even on failure
        co = cert_length; ko = key_length;
        return generate_result;
    }
    std::uint32_t Import(const void *cert, std::size_t cs, const void *key, std::size_t ks, std::uint64_t &id) {
        ++imports; calls.emplace_back("import");
        assert(generates == 1 && cs == cert_length && ks == key_length);
        assert(static_cast<const unsigned char *>(cert)[0] == 0x42);
        assert(static_cast<const unsigned char *>(key)[0] == 0xA5);
        id = real_id;
        return import_result;
    }
};

void TestSynthetic() {
    constexpr std::uint64_t Unchanged = 0x123456;
    {
        FakeBackend b; std::uint64_t id = Unchanged;
        assert(CreateSyntheticClientPki(b, id) == 0 && id == b.real_id);
        assert(b.allocations == 1 && b.generates == 1 && b.imports == 1 && b.frees == 1);
        assert((b.stages == std::vector<std::string>{"fallback_generate", "fallback_import"}));
    }
    {
        FakeBackend b; b.allocation_failure = true; std::uint64_t id = Unchanged;
        assert(CreateSyntheticClientPki(b, id) == FakeBackend::NoMemory && id == Unchanged);
        assert(b.generates == 0 && b.imports == 0 && b.frees == 0);
        assert(b.stages.back() == "fallback_allocate");
    }
    for (const auto rc : {0x1234U, 0xFEEDU, 0xE401U}) {
        FakeBackend b; b.generate_result = rc; std::uint64_t id = Unchanged;
        assert(CreateSyntheticClientPki(b, id) == rc && id == Unchanged);
        assert(b.imports == 0 && b.frees == 1 && b.results.back() == rc);
        FakeBackend c; c.import_result = rc;
        assert(CreateSyntheticClientPki(c, id) == rc && id == Unchanged);
        assert(c.imports == 1 && c.frees == 1 && c.results.back() == rc);
    }
    for (auto size : {0U, 4097U, 0xFFFFFFFFU}) {
        for (bool cert : {false, true}) {
            FakeBackend b; (cert ? b.cert_length : b.key_length) = size;
            std::uint64_t id = Unchanged;
            assert(CreateSyntheticClientPki(b, id) == FakeBackend::InvalidSize && id == Unchanged);
            assert(b.imports == 0 && b.frees == 1 && b.stages.back() == "fallback_validate_lengths");
        }
    }
    FakeBackend b; b.cert_length = b.key_length = DerCapacity;
    std::uint64_t id;
    assert(CreateSyntheticClientPki(b, id) == 0);
}
void TestRouting() {
    constexpr std::uint64_t Nim = 0x0100000000000025ULL;
    constexpr std::uint64_t Am = 0x0100000000000023ULL;
    constexpr std::uint64_t Game = 0x0100123456789000ULL;
    RoutingPolicy p;
    assert(p.targeted);
    for (auto program : {Nim, Am, Game}) {
        for (bool system : {false, true}) {
            for (bool legacy_all : {false, true})
                assert(!p.ShouldMitm(program, system, program == Game, legacy_all));
        }
    }
    const char nim[] = "0100000000000025";
    assert(ParsePrograms(p.mitm_programs, nim, sizeof(nim)));
    p.trace_requested = true;
    p.fallback_programs.enabled = true;
    assert(ParsePrograms(p.fallback_programs, nim, sizeof(nim)));
    for (bool system : {false, true}) {
        for (bool legacy_all : {false, true}) {
            assert(p.ShouldMitm(Nim, system, false, legacy_all) == system);
            for (auto program : std::array<std::uint64_t, 4>{Am, Game, 0x010000000000000FULL, 0x0100000000000033ULL}) {
                assert(!p.ShouldMitm(program, system, program == Game, legacy_all));
                const auto options = p.Options(program);
                assert(!options.trace && !options.fallback);
            }
        }
    }
    assert(p.Options(Nim).trace && p.Options(Nim).fallback);
    p.trace_requested = false;
    assert(p.Options(Nim).trace && p.Options(Nim).fallback); // only selected fallback forces logging
    p.fallback_programs.enabled = false;
    assert(!p.Options(Nim).trace && !p.Options(Nim).fallback);
    p.fallback_programs.enabled = true;
    const char only_am[] = "0100000000000023";
    assert(ParsePrograms(p.fallback_programs, only_am, sizeof(only_am)));
    assert(!p.Options(Nim).fallback && !p.Options(Am).fallback); // both lists required
    p.targeted = false;
    assert(!p.ShouldMitm(Nim, true, false, false));
    assert(!p.ShouldMitm(Nim, true, false, true));
    assert(!p.ShouldMitm(Game, false, true, false));
    assert(!p.ShouldMitm(Game, true, true, false));
    assert(!p.Options(Nim).trace && !p.Options(Nim).fallback);
    // An additional program can be explicitly configured without changing code.
    p.targeted = true;
    const char two[] = "0100000000000025,0100000000000023";
    assert(ParsePrograms(p.mitm_programs, two, sizeof(two)));
    assert(p.ShouldMitm(Am, true, false, false));
    assert(p.Options(Am).fallback);
}

void TestObservedErrorTrigger() {
    constexpr std::uint64_t Unchanged = 0x98765;
    for (auto original_rc : {0U, 0x167BU, 0x187BU, 0x10801U, 0xE401U}) {
        for (auto type : {0U, 1U, 2U, 0xFFFFFFFFU}) {
            for (bool enabled : {false, true}) {
                FakeBackend b; b.original_result = original_rc;
                std::uint64_t id = Unchanged;
                const auto rc = RegisterAfterOriginalFailure(b, enabled, type, id);
                const bool selected = enabled && type == 1 && original_rc == ObservedDevicePkiError;
                assert(b.originals == 1);
                if (selected) {
                    assert(rc == 0 && id == b.real_id && b.frees == 1);
                    assert((b.calls == std::vector<std::string>{"original", "generate", "import"}));
                } else {
                    assert(rc == original_rc);
                    assert(id == (rc == 0 ? b.original_id : Unchanged));
                    assert(b.allocations == 0 && b.generates == 0 && b.imports == 0);
                }
            }
        }
    }
    for (unsigned failure = 0; failure < 4; ++failure) {
        FakeBackend b; b.original_result = ObservedDevicePkiError;
        std::uint32_t expected;
        if (failure == 0) { b.allocation_failure = true; expected = FakeBackend::NoMemory; }
        else if (failure == 1) { b.generate_result = 0xABCD; expected = b.generate_result; }
        else if (failure == 2) { b.import_result = 0xCDEF; expected = b.import_result; }
        else { b.key_length = 0; expected = FakeBackend::InvalidSize; }
        std::uint64_t id = Unchanged;
        assert(RegisterAfterOriginalFailure(b, true, 1, id) == expected);
        assert(id == Unchanged && b.originals == 1); // no fake output and no retry
        assert(b.frees == (b.allocation_failure ? 0U : 1U));
    }
}
int main() {
    TestPolicy(); TestSynthetic(); TestRouting(); TestObservedErrorTrigger();
    std::cout << "PASS: ssl:s-only routing, legacy broad mode rejected, per-client options, exact 0x167B trigger, original-success preservation, error propagation, allocation/length failures, key wiping\n";
}
