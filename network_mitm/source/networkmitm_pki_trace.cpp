// SPDX-License-Identifier: GPL-2.0-only
#include "networkmitm_pki_trace.hpp"
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace ams::ssl::sf::impl {
namespace {
std::atomic<u64> g_next_context{1};
constinit os::SdkMutex g_trace_mutex;
fs::FileHandle g_trace_file;
s64 g_trace_offset = 0;
std::atomic<bool> g_trace_ready{false};
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

void InitializePkiTrace(bool enabled) {
    if (!enabled) return;
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

void TracePki(bool enabled, const sm::MitmProcessInfo &client, u64 context_id,
              const char *event, const char *format, ...) {
    if (!enabled) return;
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
void TraceResourceSnapshot(const char *stage) {
    if (!g_trace_ready) return;
    const sm::MitmProcessInfo self{};
    u64 value = 0;
    const Result opened = svc::GetInfo(&value, svc::InfoType_ResourceLimit, svc::InvalidHandle, 0);
    if (R_FAILED(opened)) {
        TracePki(true, self, 0, "Resources", "stage=%s query_result=0x%08X", stage, opened.GetValue());
        return;
    }
    const auto handle = static_cast<svc::Handle>(value);
    if (handle == svc::InvalidHandle) return;
    // This is a newly returned handle, not a service session or a global handle.
    ON_SCOPE_EXIT { (void)svc::CloseHandle(handle); };
    constexpr const char *Names[] = {"memory_bytes", "threads", "events", "transfer_memories", "sessions"};
    static_assert((sizeof(Names) / sizeof(Names[0])) == svc::LimitableResource_Count);
    for (u32 i = 0; i < svc::LimitableResource_Count; ++i) {
        s64 used = 0, limit = 0;
        const auto resource = static_cast<svc::LimitableResource>(i);
        const Result urc = svc::GetResourceLimitCurrentValue(&used, handle, resource);
        const Result lrc = svc::GetResourceLimitLimitValue(&limit, handle, resource);
        if (R_SUCCEEDED(urc) && R_SUCCEEDED(lrc)) {
            TracePki(true, self, 0, "Resources", "stage=%s scope=self_resource_group kind=%s used=%lld limit=%lld remaining=%lld",
                     stage, Names[i], static_cast<long long>(used), static_cast<long long>(limit), static_cast<long long>(limit-used));
        } else {
            TracePki(true, self, 0, "Resources", "stage=%s kind=%s used_result=0x%08X limit_result=0x%08X",
                     stage, Names[i], urc.GetValue(), lrc.GetValue());
        }
    }
}

}
