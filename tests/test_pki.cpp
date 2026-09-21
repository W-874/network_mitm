// SPDX-License-Identifier: GPL-2.0-only
#include "networkmitm_pki_policy.hpp"
#include "networkmitm_account_link_diagnostic.hpp"
#include "networkmitm_synthetic_pki.hpp"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
using namespace nextendo::pki;

void TestPolicy() {
    constexpr std::uint64_t Nim = NimProgramId;
    constexpr std::uint64_t Account = AccountProgramId;
    constexpr std::uint64_t Am = 0x0100000000000023ULL;
    Policy p;
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));
    p.enabled = true;
    assert(ParsePrograms(p, nullptr, 0));
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));

    auto parse = [&](const std::string &s) { return ParsePrograms(p, s.data(), s.size()); };

    // Test NIM only
    assert(parse(" 0100000000000025 "));
    assert(p.count == 1);
    assert(p.Allows(Nim, 1));
    assert(!p.Allows(Nim, 0));
    assert(!p.Allows(Nim, 2));
    assert(!p.Allows(Nim, 0xFFFFFFFF));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Am, 1));

    // Test Account only
    assert(parse(" 010000000000001E "));
    assert(p.count == 1);
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Account, 0));
    assert(!p.Allows(Account, 2));
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Am, 1));

    // Test both NIM and Account (NIM first)
    assert(parse("0100000000000025 010000000000001E"));
    assert(p.count == 2);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Am, 1));

    // Test both Account and NIM (Account first)
    assert(parse("010000000000001E 0100000000000025"));
    assert(p.count == 2);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Am, 1));

    // Test duplicates rejected
    assert(!parse("0100000000000025 0100000000000025"));
    assert(p.count == 0);
    assert(!parse("010000000000001E 010000000000001E"));
    assert(p.count == 0);

    // Defense in depth: even a directly constructed policy cannot target AM.
    p.count = 1;
    p.programs[0] = Am;
    assert(!p.Allows(Am, 1));

    // Test with both valid IDs but AM directly constructed
    p.count = 2;
    p.programs[0] = Nim;
    p.programs[1] = Am;
    assert(p.Allows(Nim, 1));
    assert(!p.Allows(Am, 1));

    p.enabled = false;
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));
    p.enabled = true;

    // Test rejection cases
    for (const auto *bad : {"*", "0x0100000000000025", "010000000000002", "01000000000000255",
            "0000000000000000", "0100000000000025,", ",0100000000000025",
            "0100000000000025,0100000000000025", "0100000000000025,0100000000000023",
            "0100000000000025;0100000000000023", "01000000000000ZZ", "0100000000000023",
            "0100000000000025,010000000000001E", "0100000000000025;010000000000001E",
            "0100000000000025 010000000000001E 0100000000000023",
            "010000000000001E 0100000000000023"}) {
        assert(parse("0100000000000025"));
        assert(!parse(bad));
        assert(p.count == 0); // no valid prefix survives an invalid suffix
        assert(!p.Allows(Nim, 1));
        assert(!p.Allows(Account, 1));
    }

    const char terminated[] = "0100000000000025";
    assert(ParsePrograms(p, terminated, sizeof(terminated)));
    std::string embedded = std::string(terminated) + '\0' + ",0100000000000023";
    assert(!parse(embedded));

    // Exhaust malformed lengths/bytes without leaking a previous selection.
    for (unsigned n=0; n<1024; ++n) {
        std::string fuzz(n, static_cast<char>(n & 255));
        parse(fuzz);
        assert(p.count <= MaxPrograms && !p.Allows(Am, 1));
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
    std::uint32_t ForwardOriginal(std::uint32_t type, std::uint64_t *id) {
        return ForwardOriginal(type, *id);
    }
    void LogOriginal(std::uint32_t, std::uint32_t rc, std::uint64_t) {
        stages.emplace_back("original"); results.push_back(rc);
    }
    void LogOriginal(std::uint32_t type, std::uint32_t rc) {
        LogOriginal(type, rc, 0);
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
    FakeBackend backend;
    std::uint64_t id = 0xAABBCCDD;
    assert(RegisterAfterOriginalFailure(backend, false, 1, id) == 0);
    assert(id == backend.original_id && backend.originals == 1 && backend.allocations == 0);
    backend.original_result = ObservedDevicePkiError;
    id = 0xAABBCCDD;
    assert(RegisterAfterOriginalFailure(backend, false, 1, id) == ObservedDevicePkiError);
    assert(id == 0xAABBCCDD && backend.originals == 2 && backend.allocations == 0);
    id = 0xAABBCCDD;
    assert(RegisterAfterOriginalFailure(backend, true, 1, id) == 0);
    assert(id == backend.real_id && backend.originals == 3 && backend.frees == 1);
    assert((backend.calls == std::vector<std::string>{"original", "original", "original", "generate", "import"}));
    backend.original_result = 0xABCD;
    id = 0xAABBCCDD;
    assert(RegisterAfterOriginalFailure(backend, true, 1, id) == 0xABCD);
    assert(id == 0xAABBCCDD && backend.originals == 4 && backend.generates == 1);
    backend.original_result = ObservedDevicePkiError;
    id = 0xAABBCCDD;
    assert(RegisterAfterOriginalFailure(backend, true, 0, id) == ObservedDevicePkiError);
    assert(id == 0xAABBCCDD && backend.generates == 1);
    id = 0xAABBCCDD;
    assert(RegisterAfterOriginalFailure(backend, true, 2, id) == ObservedDevicePkiError);
    assert(id == 0xAABBCCDD && backend.generates == 1);
}

void TestRouting() {
    constexpr std::uint64_t Nim = NimProgramId;
    constexpr std::uint64_t Account = AccountProgramId;
    constexpr std::uint64_t Am = 0x0100000000000023ULL;
    constexpr std::uint64_t Game = 0x0100AABBCCDDEEFFULL;
    RoutingPolicy p;
    assert(p.targeted && !p.trace_requested && !p.account_link_diagnostic);
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Game, ServiceRoute::OrdinarySsl, true, false));
    assert(!p.Options(Nim).trace && !p.Options(Nim).fallback);
    assert(!p.Options(Account).trace && !p.Options(Account).fallback);

    const char nim[] = "0100000000000025";
    assert(ParsePrograms(p.mitm_programs, nim, sizeof(nim)));
    assert(p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Nim, ServiceRoute::OrdinarySsl, false, false));
    assert(!p.ShouldMitm(Game, ServiceRoute::OrdinarySsl, true, false));
    assert(!p.ShouldMitm(Game, ServiceRoute::SystemSsl, true, false));
    assert(!p.Options(Nim).trace && !p.Options(Nim).fallback);

    const char account[] = "010000000000001E";
    p.mitm_programs.programs = {};
    p.mitm_programs.count = 0;
    assert(ParsePrograms(p.mitm_programs, account, sizeof(account)));
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::OrdinarySsl, false, false));
    assert(!p.Options(Account).trace && !p.Options(Account).fallback);

    const char both[] = "0100000000000025 010000000000001E";
    p.mitm_programs.programs = {};
    p.mitm_programs.count = 0;
    assert(ParsePrograms(p.mitm_programs, both, sizeof(both)));
    assert(p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Nim, ServiceRoute::OrdinarySsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::OrdinarySsl, false, false));

    p.trace_requested = true;
    assert(p.Options(Nim).trace && !p.Options(Nim).fallback);
    assert(p.Options(Account).trace && !p.Options(Account).fallback);
    const char only_nim_fallback[] = "0100000000000025";
    assert(ParsePrograms(p.fallback_programs, only_nim_fallback, sizeof(only_nim_fallback)));
    p.fallback_programs.enabled = true;
    assert(p.Options(Nim).trace && p.Options(Nim).fallback);
    assert(p.Options(Account).trace && !p.Options(Account).fallback);

    const char only_account_fallback[] = "010000000000001E";
    p.fallback_programs.programs = {};
    p.fallback_programs.count = 0;
    assert(ParsePrograms(p.fallback_programs, only_account_fallback, sizeof(only_account_fallback)));
    assert(!p.Options(Nim).fallback);
    assert(p.Options(Account).trace && p.Options(Account).fallback);

    p.fallback_programs.programs = {};
    p.fallback_programs.count = 0;
    const char both_fallback[] = "0100000000000025 010000000000001E";
    assert(ParsePrograms(p.fallback_programs, both_fallback, sizeof(both_fallback)));
    assert(p.Options(Nim).fallback);
    assert(p.Options(Account).fallback);

    p.trace_requested = false;
    assert(p.Options(Nim).trace && p.Options(Nim).fallback);
    assert(p.Options(Account).trace && p.Options(Account).fallback);

    const char only_am[] = "0100000000000023";
    assert(!ParsePrograms(p.mitm_programs, only_am, sizeof(only_am)));
    assert(!p.Options(Nim).fallback && !p.Options(Am).fallback);

    p.targeted = false;
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, true));
    assert(!p.ShouldMitm(Game, ServiceRoute::OrdinarySsl, true, false));
    assert(!p.ShouldMitm(Game, ServiceRoute::SystemSsl, true, false));
    assert(!p.Options(Nim).trace && !p.Options(Nim).fallback);
    assert(!p.Options(Account).trace && !p.Options(Account).fallback);

    p.targeted = true;
    p.mitm_programs.programs = {};
    p.mitm_programs.count = 0;
    assert(ParsePrograms(p.mitm_programs, both, sizeof(both)));
    const char two[] = "0100000000000025,0100000000000023";
    assert(!ParsePrograms(p.mitm_programs, two, sizeof(two)));
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Am, ServiceRoute::SystemSsl, false, false));
    assert(!p.Options(Nim).fallback && !p.Options(Account).fallback && !p.Options(Am).fallback);
}

void TestAccountLinkDiagnosticRoutingAndForwarding() {
    constexpr std::uint64_t Nim = NimProgramId;
    constexpr std::uint64_t Account = AccountProgramId;
    RoutingPolicy p;
    const char both[] = "0100000000000025 010000000000001E";
    assert(ParsePrograms(p.mitm_programs, both, sizeof(both)));
    p.account_link_diagnostic = true;
    for (const auto candidate : AccountLinkDiagnosticProgramIds) {
        assert(IsAccountLinkDiagnosticProgram(candidate));
        assert(p.ShouldMitm(candidate, ServiceRoute::OrdinarySsl, false, false));
        assert(!p.ShouldMitm(candidate, ServiceRoute::SystemSsl, false, false));
        assert(p.ShouldTraceOrdinary(candidate));
    }
    assert(!p.ShouldMitm(Nim, ServiceRoute::OrdinarySsl, false, false));
    assert(p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, true));
    assert(p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, true));
    assert(!p.ShouldTraceOrdinary(Nim));
    assert(!p.ShouldTraceOrdinary(Account));
    assert(!p.ShouldMitm(0x0100000000000023ULL, ServiceRoute::OrdinarySsl, false, true));
    p.account_link_diagnostic = false;
    for (const auto candidate : AccountLinkDiagnosticProgramIds)
        assert(!p.ShouldMitm(candidate, ServiceRoute::OrdinarySsl, false, true));

    FakeBackend failure;
    failure.original_result = ObservedDevicePkiError;
    std::uint64_t id = 0xAABBCCDD;
    assert(nextendo::diagnostic::ForwardOrdinaryRegisterInternalPki(failure, 1, &id) == ObservedDevicePkiError);
    assert(id == failure.original_id && failure.originals == 1 && failure.allocations == 0 &&
           failure.generates == 0 && failure.imports == 0);
    FakeBackend success;
    id = 0;
    assert(nextendo::diagnostic::ForwardOrdinaryRegisterInternalPki(success, 2, &id) == 0);
    assert(id == success.original_id && success.originals == 1 && success.allocations == 0 &&
           success.generates == 0 && success.imports == 0);
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
        assert(id == Unchanged && b.originals == 1);
        assert(b.frees == (b.allocation_failure ? 0U : 1U));
    }
}

int main() {
    TestPolicy(); TestSynthetic(); TestRouting(); TestAccountLinkDiagnosticRoutingAndForwarding(); TestObservedErrorTrigger();
    std::cout << "PASS: hard service/program routing, fixed ordinary candidates, ordinary command-8 raw forwarding, NIM and Account ssl:s fallback with allowlist capacity 2, legacy broad mode rejected, exact 0x167B trigger, error propagation, allocation/length failures, key wiping\n";
}
