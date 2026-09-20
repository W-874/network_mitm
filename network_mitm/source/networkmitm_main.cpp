/*
 * Copyright (c) Mary Guillemard <mary@mary.zone>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "networkmitm_ssl_for_system_service_impl.hpp"
#include "networkmitm_ssl_service_impl.hpp"
#include "networkmitm_utils.hpp"
#include "networkmitm_pki_trace.hpp"
#include "networkmitm_device_pki.hpp"
#include <stratosphere.hpp>

namespace ams {
namespace impl {
#define AMS_DEFINE_SYSTEM_THREAD(__AMS_THREAD_PRIORITY__, __AMS_MODULE__,      \
                                 __AMS_THREAD_NAME__)                          \
    constexpr inline const ::ams::impl::SystemThreadDefinition                 \
        SystemThreadDefinition_##__AMS_MODULE__##_##__AMS_THREAD_NAME__ = {    \
            __AMS_THREAD_PRIORITY__,                                           \
            "ams." #__AMS_MODULE__ "." #__AMS_THREAD_NAME__}

AMS_DEFINE_SYSTEM_THREAD(10, network_mitm, Main);

#undef AMS_DEFINE_SYSTEM_THREAD
} // namespace impl

namespace diag::impl {
void ReplaceDefaultLogObserver(LogObserver observer);
void ResetDefaultLogObserver();
} // namespace diag::impl

namespace ssl {

constinit u8 g_fs_heap_memory[32_KB];
constinit lmem::HeapHandle g_fs_heap_handle;

void *AllocateForFs(size_t size) {
    return lmem::AllocateFromExpHeap(g_fs_heap_handle, size);
}

void DeallocateForFs(void *p, size_t size) {
    AMS_UNUSED(size);
    return lmem::FreeToExpHeap(g_fs_heap_handle, p);
}

void InitializeFsHeap() {
    g_fs_heap_handle = lmem::CreateExpHeap(
        g_fs_heap_memory, sizeof(g_fs_heap_memory), lmem::CreateOption_None);
}

void FinalizeFsHeap() { lmem::DestroyExpHeap(g_fs_heap_handle); }
} // namespace ssl

namespace {
static fs::FileHandle g_logger_file;
static s64 g_logger_file_ofs;
static bool g_logger_ready = false;
constinit os::SdkMutex g_logger_file_mutex;

void LogFileLogObserver(const diag::LogMetaData &meta,
                        const diag::LogBody &body, void *) {
    AMS_UNUSED(meta);

    std::scoped_lock lk(g_logger_file_mutex);

    if (R_SUCCEEDED(fs::WriteFile(g_logger_file, g_logger_file_ofs, body.message,
                                  body.message_size, fs::WriteOption::Flush)))
        g_logger_file_ofs += body.message_size;
}

void InitializeFileLogger() {
    bool dir_exists;
    char path[ams::fs::EntryNameLengthMax + 1];
    util::SNPrintf(path, sizeof(path), "%s:/atmosphere/logs/",
                   ams::fs::impl::SdCardFileSystemMountName);

    auto result = fs::HasDirectory(&dir_exists, path);
    if (R_FAILED(result)) {
        return;
    }

    if (!dir_exists) {
        result = fs::CreateDirectory(path);
        if (R_FAILED(result)) {
            return;
        }
    }

    util::SNPrintf(path, sizeof(path),
                   "%s:/atmosphere/logs/network_mitm_observer.log",
                   ams::fs::impl::SdCardFileSystemMountName);

    result = fs::CreateFile(path, 0);
    if (R_FAILED(result) && !fs::ResultPathAlreadyExists::Includes(result)) {
        return;
    }

    if (R_FAILED(fs::OpenFile(&g_logger_file, path, fs::OpenMode_All))) return;
    g_logger_ready = true;

    g_logger_file_ofs = 0;

    diag::impl::ReplaceDefaultLogObserver(LogFileLogObserver);
}

void FinalizeFileLogger() {
    diag::impl::ResetDefaultLogObserver();

    if (g_logger_ready) fs::CloseFile(g_logger_file);
}
} // namespace

namespace {
/* TODO: Use an ExpHeap and see if we need less/more */
constexpr size_t MallocBufferSize = 1_MB;
alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];
} // namespace

namespace init {

void InitializeSystemModule() {
    /* Initialize fs heap. */
    ssl::InitializeFsHeap();

    /* Initialize our connection to sm. */
    R_ABORT_UNLESS(sm::Initialize());

    /* Initialize fs. */
    fs::InitializeForSystem();
    fs::SetAllocator(ssl::AllocateForFs, ssl::DeallocateForFs);
    fs::SetEnabledAutoAbort(false);

    cfg::WaitSdCardInitialized();

    R_ABORT_UNLESS(fs::MountSdCard(ams::fs::impl::SdCardFileSystemMountName));

    /* Initialize logger early */
    // FIXME: Broken rn and cause memory corruption even on hello world.
    // ams::lm::Initialize();
    InitializeFileLogger();

    /* Initialize settings */
    R_ABORT_UNLESS((Result)::setsysInitialize());

    /* Initialize time for file dating :3 */
    R_ABORT_UNLESS((Result)::timeInitialize());
}

void FinalizeSystemModule() {
    timeExit();

    setsysExit();

    FinalizeFileLogger();

    // TODO: fs finalize?

    // ams::lm::Finalize();

    /* Close sm session */
    R_ABORT_UNLESS(sm::Finalize());

    /* Finalize the fs heap */
    ssl::FinalizeFsHeap();
}

void Startup() {
    /* Initialize the global malloc allocator. */
    init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
}

} // namespace init

bool ShouldSslMitm() {
    u8 en = 0;
    if (settings::fwdbg::GetSettingsItemValue(std::addressof(en), sizeof(en),
                                              "network_mitm",
                                              "enable_ssl") == sizeof(en)) {
        return (en != 0);
    }

    return false;
}

bool ShouldDumpSslTraffic() {
    // This diagnostic fork never writes decrypted traffic or credentials.
    return false;
}

bool ShouldMitmAll() {
    u8 en = 0;
    if (settings::fwdbg::GetSettingsItemValue(
            std::addressof(en), sizeof(en), "network_mitm",
            "should_mitm_all") == sizeof(en)) {
        return (en != 0);
    }

    return false;
}

bool ShouldDisableSslVerification() {
    u8 en = 0;
    if (settings::fwdbg::GetSettingsItemValue(
            std::addressof(en), sizeof(en), "network_mitm",
            "should_disable_ssl_verification") == sizeof(en)) {
        return (en != 0);
    }

    return false;
}

namespace ssl::sf::impl {
const int CAKeyStorageSize = 0x1000;
constinit u8 g_ca_public_key_storage_pem[CAKeyStorageSize];
constinit u8 g_ca_public_key_storage_der[CAKeyStorageSize];
Span<uint8_t> g_ca_certificate_public_key_pem;
Span<uint8_t> g_ca_certificate_public_key_der = Span<uint8_t>();
bool g_should_dump_ssl_traffic;
bool g_should_mitm_all;
bool g_should_disable_ssl_verification;
PcapLinkType g_link_type;

enum PortIndex {
    PortIndex_SslMitm,
    PortIndex_SslSystemMitm,
    PortIndex_Count,
};

constexpr sm::ServiceName MitmSslServiceName = sm::ServiceName::Encode("ssl");
constexpr sm::ServiceName MitmSslSystemServiceName =
    sm::ServiceName::Encode("ssl:s");

struct ServerOptions {
    // FIXME: Use real values from SSL after reverse
    static constexpr size_t PointerBufferSize = 0x10000;
    static constexpr size_t MaxDomains = 0x40;
    static constexpr size_t MaxDomainObjects = 0x4000;
    static constexpr bool CanDeferInvokeRequest = false;
    static constexpr bool CanManageMitmServers = true;
};

class ServerManager final
    : public ams::sf::hipc::ServerManager<PortIndex_Count, ServerOptions> {
  private:
    virtual Result OnNeedsToAccept(int port_index, Server *server) override;
};

ServerManager g_server_manager_for_user;
ServerManager g_server_manager_for_system;

Result ServerManager::OnNeedsToAccept(int port_index, Server *server) {
    AMS_LOG("OnNeedsToAccept\n");

    /* Acknowledge the mitm session. */
    std::shared_ptr<::Service> forward_service;
    sm::MitmProcessInfo client_info;
    server->AcknowledgeMitmSession(std::addressof(forward_service),
                                   std::addressof(client_info));

    const auto pki_options = GetClientPkiOptions(client_info.program_id);

    switch (port_index) {
    case PortIndex_SslMitm:
        AMS_LOG("AcceptMitmImpl SSL titleid: %lx\n",
                (u64)client_info.program_id);
        R_RETURN(this->AcceptMitmImpl(
            server,
            ams::sf::CreateSharedObjectEmplaced<ISslService, SslServiceImpl>(
                decltype(forward_service)(forward_service), client_info,
                g_should_dump_ssl_traffic, g_link_type,
                g_ca_certificate_public_key_der, pki_options),
            forward_service));
    case PortIndex_SslSystemMitm:
        AMS_LOG("AcceptMitmImpl SSL SYSTEM titleid: %lx\n",
                (u64)client_info.program_id);
        R_RETURN(this->AcceptMitmImpl(
            server,
            ams::sf::CreateSharedObjectEmplaced<ISslServiceForSystem,
                                                SslServiceForSystemImpl>(
                decltype(forward_service)(forward_service), client_info,
                g_should_dump_ssl_traffic, g_link_type,
                g_ca_certificate_public_key_der, pki_options),
            forward_service));
        AMS_UNREACHABLE_DEFAULT_CASE();
    }
}

constexpr size_t TotalThreads = 5;
static_assert(TotalThreads >= 1, "TotalThreads");
constexpr size_t NumExtraThreads = TotalThreads - 1;
constexpr size_t ThreadStackSize = 0x8000;
alignas(os::MemoryPageSize) u8
    g_extra_thread_stacks[NumExtraThreads][ThreadStackSize];

os::ThreadType g_extra_threads[NumExtraThreads];

void LoopServerThreadForUser(void *) {
    /* Loop forever, servicing our user service. */
    g_server_manager_for_user.LoopProcess();
}

void LoopServerThreadForSystem(void *) {
    /* Loop forever, servicing our system service. */
    g_server_manager_for_system.LoopProcess();
}

void ProcessForServerOnAllThreads() {
    bool has_system_manager = hos::GetVersion() >= hos::Version_15_0_0;

    /* Initialize threads. */
    if constexpr (NumExtraThreads > 0) {
        const s32 priority =
            os::GetThreadCurrentPriority(os::GetCurrentThread());
        for (size_t i = 0; i < NumExtraThreads; i++) {
            if (has_system_manager) {
                R_ABORT_UNLESS(os::CreateThread(
                    g_extra_threads + i,
                    i % 2 ? LoopServerThreadForUser : LoopServerThreadForSystem,
                    nullptr, g_extra_thread_stacks[i], ThreadStackSize,
                    priority));
            } else {
                R_ABORT_UNLESS(os::CreateThread(
                    g_extra_threads + i, LoopServerThreadForUser, nullptr,
                    g_extra_thread_stacks[i], ThreadStackSize, priority));
            }
        }
    }

    /* Start extra threads. */
    if constexpr (NumExtraThreads > 0) {
        for (size_t i = 0; i < NumExtraThreads; i++) {
            os::StartThread(g_extra_threads + i);
        }
    }

    /* Loop this thread. */
    if (has_system_manager)
        LoopServerThreadForSystem(nullptr);
    else
        LoopServerThreadForUser(nullptr);

    /* Wait for extra threads to finish. */
    if constexpr (NumExtraThreads > 0) {
        for (size_t i = 0; i < NumExtraThreads; i++) {
            os::WaitThread(g_extra_threads + i);
        }
    }
}

Result ReadFileToBuffer(const char *path, void *buffer, size_t buffer_size,
                        size_t &out_size) {
    /* Open the value file. */
    fs::FileHandle file;
    R_TRY(fs::OpenFile(std::addressof(file), path, fs::OpenMode_Read));
    ON_SCOPE_EXIT { fs::CloseFile(file); };

    /* Get the value size. */
    s64 file_size;
    R_TRY(fs::GetFileSize(std::addressof(file_size), file));

    /* Ensure there's enough space for the value. */
    R_UNLESS(file_size <= static_cast<s64>(buffer_size),
             kvdb::ResultBufferInsufficient());

    /* Read the value. */
    const size_t value_size = static_cast<size_t>(file_size);
    R_TRY(fs::ReadFile(file, 0, buffer, value_size));
    out_size = value_size;

    R_SUCCEED();
}

void Initialize(bool should_dump_ssl_traffic, bool should_mitm_all,
                bool should_disable_ssl_verification) {
    AMS_UNUSED(should_dump_ssl_traffic, should_disable_ssl_verification);
    InitializeDevicePkiPolicy();
    g_should_dump_ssl_traffic = false;
    g_should_disable_ssl_verification = false;
    g_should_mitm_all = should_mitm_all;
    g_link_type = PcapLinkType::User;
    // Deliberately never load custom_ca_public_cert in this build.
}

} // namespace ssl::sf::impl

void Main() {
    /* Set thread name. */
    os::SetThreadNamePointer(os::GetCurrentThread(),
                             AMS_GET_SYSTEM_THREAD_NAME(network_mitm, Main));
    AMS_ASSERT(os::GetThreadPriority(os::GetCurrentThread()) ==
               AMS_GET_SYSTEM_THREAD_PRIORITY(network_mitm, Main));

    if (!ShouldSslMitm()) {
        AMS_LOG("network_mitm is disabled by configuration.\n");
        AMS_LOG("To enable SSL mitm, set \"enable_ssl = 1\" in "
                "system_settings.ini\n");

        return;
    }

    using namespace ams::ssl::sf::impl;

    AMS_LOG("network_mitm enabled\n");
    const bool should_dump_ssl_traffic = ShouldDumpSslTraffic();
    const bool should_mitm_all = ShouldMitmAll();
    const bool should_disable_ssl_verification = ShouldDisableSslVerification();
    Initialize(should_dump_ssl_traffic, should_mitm_all,
               should_disable_ssl_verification);

    if (g_targeted_device_pki_mode) {
        AMS_LOG("Targeted device PKI mode: only mitm_program_ids; should_mitm_all ignored\n");
    } else if (should_mitm_all) {
        AMS_LOG("Legacy root MITM enabled; device PKI experiment disabled\n");
    }

    if (g_should_disable_ssl_verification) {
        AMS_LOG("SSL verification will be forcefully disabled\n");
    }

    if (!should_dump_ssl_traffic) {
        AMS_LOG("SSL service traffic dumping disabled\n");
    }

    /* Create mitm servers. */
    R_ABORT_UNLESS(
        (g_server_manager_for_user.RegisterMitmServer<SslServiceImpl>(
            PortIndex_SslMitm, MitmSslServiceName)));

    if (hos::GetVersion() >= hos::Version_15_0_0) {
        R_ABORT_UNLESS(
            (g_server_manager_for_system.RegisterMitmServer<SslServiceForSystemImpl>(
                PortIndex_SslSystemMitm, MitmSslSystemServiceName)));
    }

    /* Loop forever, servicing our services. */
    AMS_LOG("Accepting requests.\n");
    ProcessForServerOnAllThreads();
}

} // namespace ams
