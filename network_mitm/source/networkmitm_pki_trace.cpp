// SPDX-License-Identifier: GPL-2.0-only
#include "networkmitm_pki_trace.hpp"
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace ams::ssl::sf::impl {
bool g_trace_internal_pki = false;
namespace {
std::atomic<u64> g_next_context{1};
constinit os::SdkMutex g_trace_mutex;
fs::FileHandle g_trace_file;
s64 g_trace_offset = 0;
bool g_trace_ready = false;
constexpr s64 MaxTraceBytes = 8 * 1024 * 1024;

void Append(const char *line, size_t size) {
    if (!g_trace_ready || g_trace_offset + static_cast<s64>(size) > MaxTraceBytes)
        return;
    // Logging failure must never replace the original SSL Result or abort.
    if (R_FAILED(fs::WriteFile(g_trace_file, g_trace_offset, line, size,
                              fs::WriteOption::Flush))) {
        g_trace_ready = false;
        fs::CloseFile(g_trace_file);
        return;
    }
    g_trace_offset += size;
}
}

u64 AllocateTraceContextId() { return g_next_context.fetch_add(1); }

void InitializePkiTrace(bool force) {
    u8 enabled = 0;
    u64 size = 0;
    const auto rc_setting = ::setsysGetSettingsItemValue("network_mitm", "trace_internal_pki",
                                                       &enabled, sizeof(enabled), &size);
    g_trace_internal_pki = force || (R_SUCCEEDED(rc_setting) && size == sizeof(enabled) && enabled != 0);
    if (!g_trace_internal_pki) return;
    char path[128];
    util::SNPrintf(path, sizeof(path), "%s:/network_mitm",
                   fs::impl::SdCardFileSystemMountName);
    Result rc = fs::CreateDirectory(path);
    if (R_FAILED(rc) && !fs::ResultPathAlreadyExists::Includes(rc)) return;
    util::SNPrintf(path, sizeof(path), "%s:/network_mitm/internal_pki.log",
                   fs::impl::SdCardFileSystemMountName);
    rc = fs::CreateFile(path, 0);
    if (R_FAILED(rc) && !fs::ResultPathAlreadyExists::Includes(rc)) return;
    if (R_FAILED(fs::OpenFile(&g_trace_file, path, fs::OpenMode_All))) return;
    if (R_FAILED(fs::GetFileSize(&g_trace_offset, g_trace_file))) {
        fs::CloseFile(g_trace_file);
        return;
    }
    g_trace_ready = true;
    const char header[] = "\n# network_mitm PKI trace boot build=" GIT_REVISION
                          " timestamp=monotonic_ms cap=8MiB metadata_only=1\n";
    Append(header, sizeof(header) - 1);
}

void TracePki(const sm::MitmProcessInfo &client, u64 context_id,
              const char *event, const char *format, ...) {
    if (!g_trace_internal_pki) return;
    char detail[256];
    va_list args;
    va_start(args, format);
    std::vsnprintf(detail, sizeof(detail), format, args);
    va_end(args);
    char line[512];
    std::scoped_lock lk(g_trace_mutex);
    const auto milliseconds = os::GetSystemTick().ToTimeSpan().GetMilliSeconds();
    util::SNPrintf(line, sizeof(line),
        "[%lld] program=%016llX pid=0x%llX ctx=%llu %s %s\n",
        static_cast<long long>(milliseconds),
        static_cast<unsigned long long>(static_cast<u64>(client.program_id)),
        static_cast<unsigned long long>(static_cast<u64>(client.process_id)),
        static_cast<unsigned long long>(context_id), event, detail);
    Append(line, std::strlen(line));
}
}
