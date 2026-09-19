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
        ++generates;
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
        ++imports;
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
int main() {
    TestPolicy(); TestSynthetic();
    std::cout << "PASS: allowlist, strict routing, generate/import, exact error propagation, allocation failure, length validation, key wiping\n";
}
