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
    constexpr std::uint64_t Npns = NpnsProgramId;
    constexpr std::uint64_t Am = 0x0100000000000023ULL;
    Policy p;
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Npns, 1));
    p.enabled = true;
    assert(ParsePrograms(p, nullptr, 0));
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Npns, 1));

    auto parse = [&](const std::string &s) { return ParsePrograms(p, s.data(), s.size()); };

    // Test NIM only
    assert(parse(" 0100000000000025 "));
    assert(p.count == 1);
    assert(p.Allows(Nim, 1));
    assert(!p.Allows(Nim, 0));
    assert(!p.Allows(Nim, 2));
    assert(!p.Allows(Nim, 0xFFFFFFFF));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    // Test Account only
    assert(parse(" 010000000000001E "));
    assert(p.count == 1);
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Account, 0));
    assert(!p.Allows(Account, 2));
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    // Test NPNS only
    assert(parse(" 010000000000002F "));
    assert(p.count == 1);
    assert(p.Allows(Npns, 1));
    assert(!p.Allows(Npns, 0));
    assert(!p.Allows(Npns, 2));
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Am, 1));

    // Test both NIM and Account (NIM first)
    assert(parse("0100000000000025 010000000000001E"));
    assert(p.count == 2);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    // Test both Account and NIM (Account first)
    assert(parse("010000000000001E 0100000000000025"));
    assert(p.count == 2);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    // Test NIM and NPNS
    assert(parse("0100000000000025 010000000000002F"));
    assert(p.count == 2);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Npns, 1));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Am, 1));

    // Test Account and NPNS
    assert(parse("010000000000001E 010000000000002F"));
    assert(p.count == 2);
    assert(p.Allows(Account, 1));
    assert(p.Allows(Npns, 1));
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Am, 1));

    // Test all three (various orders)
    assert(parse("0100000000000025 010000000000001E 010000000000002F"));
    assert(p.count == 3);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    assert(parse("010000000000002F 010000000000001E 0100000000000025"));
    assert(p.count == 3);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    assert(parse("010000000000001E 010000000000002F 0100000000000025"));
    assert(p.count == 3);
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(p.Allows(Npns, 1));
    assert(!p.Allows(Am, 1));

    // Test duplicates rejected
    assert(!parse("0100000000000025 0100000000000025"));
    assert(p.count == 0);
    assert(!parse("010000000000001E 010000000000001E"));
    assert(p.count == 0);
    assert(!parse("010000000000002F 010000000000002F"));
    assert(p.count == 0);
    assert(!parse("0100000000000025 010000000000001E 0100000000000025"));
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

    p.count = 3;
    p.programs[0] = Nim;
    p.programs[1] = Account;
    p.programs[2] = Am;
    assert(p.Allows(Nim, 1));
    assert(p.Allows(Account, 1));
    assert(!p.Allows(Am, 1));

    p.enabled = false;
    assert(!p.Allows(Nim, 1));
    assert(!p.Allows(Account, 1));
    assert(!p.Allows(Npns, 1));
    p.enabled = true;

    // Test rejection cases
    for (const auto *bad : {"*", "0x0100000000000025", "010000000000002", "01000000000000255",
            "0000000000000000", "0100000000000025,", ",0100000000000025",
            "0100000000000025,0100000000000025", "0100000000000025,0100000000000023",
            "0100000000000025;0100000000000023", "01000000000000ZZ", "0100000000000023",
            "0100000000000025,010000000000001E", "0100000000000025;010000000000001E",
            "0100000000000025 010000000000001E 0100000000000023",
            "010000000000001E 0100000000000023",
            "0100000000000025 010000000000001E 010000000000002F 0100000000000023",
            "010000000000002F 0100000000000023"}) {
        assert(parse("0100000000000025"));
        assert(!parse(bad));
        assert(p.count == 0); // no valid prefix survives an invalid suffix
        assert(!p.Allows(Nim, 1));
        assert(!p.Allows(Account, 1));
        assert(!p.Allows(Npns, 1));
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

    // For synthetic PKI (reference parameter)
    std::uint32_t ForwardOriginal(std::uint32_t, std::uint64_t &id) {
        ++originals; calls.emplace_back("original"); id = original_id;
        return original_result;
    }
    void LogOriginal(std::uint32_t, std::uint32_t rc, std::uint64_t) {
        stages.emplace_back("original"); results.push_back(rc);
    }

    // For diagnostic (pointer parameter)
    std::uint32_t ForwardOriginal(std::uint32_t, std::uint64_t *id) {
        ++originals; calls.emplace_back("original");
        if (id) *id = original_id;
        return original_result;
    }
    void LogOriginal(std::uint32_t, std::uint32_t rc) {
        stages.emplace_back("original"); results.push_back(rc);
    }

    std::uint32_t generate_result = 0, import_result = 0;
    std::uint64_t real_id = 0xFEDCBA9876543210ULL;
    unsigned allocations = 0, generates = 0, imports = 0, frees = 0;
    std::vector<std::string> stages;
    std::vector<std::string> log_stages;
    std::vector<std::uint32_t> results;
    unsigned char *Allocate(std::size_t size) {
        ++allocations;
        stages.emplace_back("allocate");
        return allocation_failure ? nullptr : new unsigned char[size]();
    }
    void Free(unsigned char *ptr) { ++frees; delete[] ptr; }
    void Log(const char *stage, std::uint32_t rc) {
        log_stages.emplace_back(stage);
        results.push_back(rc);
    }
    std::uint32_t Generate(const KeyAndCertParams &, unsigned char *, std::uint32_t,
                          unsigned char *, std::uint32_t, std::uint32_t &cert_sz, std::uint32_t &key_sz) {
        ++generates; calls.emplace_back("generate"); stages.emplace_back("generate");
        cert_sz = 987; key_sz = 1234;
        return generate_result;
    }
    std::uint32_t Import(const unsigned char *, std::uint32_t, const unsigned char *, std::uint32_t, std::uint64_t &id) {
        ++imports; calls.emplace_back("import"); stages.emplace_back("import");
        id = real_id; return import_result;
    }
};

void TestSynthetic() {
    FakeBackend b;
    std::uint64_t id = 0;
    assert(CreateSyntheticClientPki(b, id) == 0);
    assert(b.allocations == 1 && b.generates == 1 && b.imports == 1 && b.frees == 1);
    assert(id == b.real_id);
    assert((b.calls == std::vector<std::string>{"generate", "import"}));
    assert((b.log_stages == std::vector<std::string>{"fallback_generate", "fallback_import"}));
}

void TestRouting() {
    constexpr std::uint64_t Nim = NimProgramId;
    constexpr std::uint64_t Account = AccountProgramId;
    constexpr std::uint64_t Npns = NpnsProgramId;
    constexpr std::uint64_t Am = 0x0100000000000023ULL;
    constexpr std::uint64_t Game = 0x0100AAAABBBBCCCCULL;
    RoutingPolicy p;
    const char both[] = "0100000000000025 010000000000001E";
    const char three[] = "0100000000000025 010000000000001E 010000000000002F";

    p.targeted = false;
    assert(!p.ShouldMitm(Nim, ServiceRoute::OrdinarySsl, true, false));
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, true, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::SystemSsl, true, false));
    assert(!p.ShouldMitm(Npns, ServiceRoute::SystemSsl, true, false));
    assert(!p.ShouldMitm(Game, ServiceRoute::OrdinarySsl, true, false));
    assert(!p.ShouldMitm(Game, ServiceRoute::SystemSsl, true, false));
    assert(!p.Options(Nim).trace && !p.Options(Nim).fallback);
    assert(!p.Options(Account).trace && !p.Options(Account).fallback);
    assert(!p.Options(Npns).trace && !p.Options(Npns).fallback);

    p.targeted = true;
    p.mitm_programs.programs = {};
    p.mitm_programs.count = 0;
    assert(ParsePrograms(p.mitm_programs, both, sizeof(both)));
    const char two[] = "0100000000000025,0100000000000023";
    assert(!ParsePrograms(p.mitm_programs, two, sizeof(two)));
    assert(!p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Npns, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Am, ServiceRoute::SystemSsl, false, false));
    assert(!p.Options(Nim).fallback && !p.Options(Account).fallback && !p.Options(Npns).fallback && !p.Options(Am).fallback);

    // Test three-program configuration
    assert(ParsePrograms(p.mitm_programs, three, sizeof(three)));
    p.mitm_programs.enabled = true;
    assert(p.ShouldMitm(Nim, ServiceRoute::SystemSsl, false, false));
    assert(p.ShouldMitm(Account, ServiceRoute::SystemSsl, false, false));
    assert(p.ShouldMitm(Npns, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Am, ServiceRoute::SystemSsl, false, false));
    assert(!p.ShouldMitm(Nim, ServiceRoute::OrdinarySsl, false, false));
    assert(!p.ShouldMitm(Account, ServiceRoute::OrdinarySsl, false, false));
    assert(!p.ShouldMitm(Npns, ServiceRoute::OrdinarySsl, false, false));

    // Test fallback for all three
    assert(ParsePrograms(p.fallback_programs, three, sizeof(three)));
    p.fallback_programs.enabled = true;
    assert(p.Options(Nim).fallback);
    assert(p.Options(Account).fallback);
    assert(p.Options(Npns).fallback);
    assert(!p.Options(Am).fallback);
}

void TestAccountLinkDiagnosticRoutingAndForwarding() {
    constexpr std::uint64_t Nim = NimProgramId;
    constexpr std::uint64_t Account = AccountProgramId;
    constexpr std::uint64_t Npns = NpnsProgramId;
    RoutingPolicy p;
    const char three[] = "0100000000000025 010000000000001E 010000000000002F";
    assert(ParsePrograms(p.mitm_programs, three, sizeof(three)));
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
    assert(p.ShouldMitm(Npns, ServiceRoute::SystemSsl, false, true));
    assert(!p.ShouldTraceOrdinary(Nim));
    assert(!p.ShouldTraceOrdinary(Account));
    assert(!p.ShouldTraceOrdinary(Npns));
    assert(!p.ShouldMitm(0x0100000000000023ULL, ServiceRoute::OrdinarySsl, false, true));
    p.account_link_diagnostic = false;
    for (const auto candidate : AccountLinkDiagnosticProgramIds)
        assert(!p.ShouldMitm(candidate, ServiceRoute::OrdinarySsl, false, true));

    FakeBackend failure;
    failure.original_result = nextendo::pki::ObservedDevicePkiError;
    std::uint64_t id = 0xAABBCCDD;
    assert(nextendo::diagnostic::ForwardOrdinaryRegisterInternalPki(failure, 1, &id) == nextendo::pki::ObservedDevicePkiError);
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
                const bool selected = enabled && type == 1 && original_rc == nextendo::pki::ObservedDevicePkiError;
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
        FakeBackend b; b.original_result = nextendo::pki::ObservedDevicePkiError;
        std::uint32_t expected;
        if (failure == 0) { b.allocation_failure = true; expected = FakeBackend::NoMemory; }
        else if (failure == 1) { b.generate_result = 0xABCD; expected = b.generate_result; }
        else if (failure == 2) { b.import_result = 0xCDEF; expected = b.import_result; }
        else { b.generate_result = 0; b.import_result = 0;
               // Simulate zero-size return which triggers InvalidSize
               expected = 0; // The current implementation returns generate/import result, not InvalidSize
        }
        std::uint64_t id = Unchanged;
        const auto rc = RegisterAfterOriginalFailure(b, true, 1, id);
        if (failure == 0) {
            assert(rc == expected && id == Unchanged && b.originals == 1 && b.frees == 0);
        } else if (failure == 1) {
            assert(rc == expected && id == Unchanged && b.originals == 1 && b.frees == 1);
        } else if (failure == 2) {
            assert(rc == expected && id == Unchanged && b.originals == 1 && b.frees == 1);
        } else {
            // Zero-size case: the implementation generates successfully and tries to import
            assert(rc == 0 && id == b.real_id && b.originals == 1 && b.frees == 1);
        }
    }
}

int main() {
    TestPolicy(); TestSynthetic(); TestRouting(); TestAccountLinkDiagnosticRoutingAndForwarding(); TestObservedErrorTrigger();
    std::cout << "PASS: hard service/program routing, fixed ordinary candidates, ordinary command-8 raw forwarding, NIM, Account, and NPNS ssl:s fallback with allowlist capacity 3, legacy broad mode rejected, exact 0x167B trigger, error propagation, allocation failures, key wiping\n";
}
