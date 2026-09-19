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
#include "networkmitm_utils.hpp"
#include "shim/ssl_shim.h"
#include "networkmitm_pki_trace.hpp"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslServiceForSystemImpl::CreateContext(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out) {
    // If we aren't mitm the traffic or disabling verifications, we don't want
    // to control the sub objects to reduce overhead.
    if (!m_should_dump_traffic && !g_should_disable_ssl_verification && !g_trace_internal_pki) {
        return sm::mitm::ResultShouldForwardToSession();
    }

    const u64 context_id = AllocateTraceContextId();
    TracePki(m_client_info, context_id, "CreateContext", "phase=begin ssl_version=0x%08X", static_cast<u32>(version));
    Service out_tmp;
    const Result rc = sslsCreateContext_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp));
    TracePki(m_client_info, context_id, "CreateContext", "forward_result=0x%08X", rc.GetValue());
    R_TRY(rc);

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslContext, SslContextImpl>(
            std::make_unique<::Service>(out_tmp), m_client_info,
            m_should_dump_traffic, m_link_type, context_id),
        target_object_id);

    R_SUCCEED();
}

Result SslServiceForSystemImpl::GetCertificates(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &certificates) {
    R_TRY(sslsGetCertificates_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        certificates_count.GetPointer(), certificates.GetPointer(),
        certificates.GetSize()));

    R_TRY(PatchCertificates(ids, certificates_count, certificates));

    R_SUCCEED();
}

Result SslServiceForSystemImpl::GetCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    R_TRY(sslsGetCertificateBufSize_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        buffer_size.GetPointer()));

    R_TRY(PatchCertificateBufSize(ids, buffer_size));

    R_SUCCEED();
}

Result SslServiceForSystemImpl::CreateContextForSystem(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContextForSystem>>
        out) {
    // If we aren't mitm the traffic or disabling verifications, we don't want
    // to control the sub objects to reduce overhead.
    if (!m_should_dump_traffic && !g_should_disable_ssl_verification && !g_trace_internal_pki) {
        return sm::mitm::ResultShouldForwardToSession();
    }

    const u64 context_id = AllocateTraceContextId();
    TracePki(m_client_info, context_id, "CreateContextForSystem", "phase=begin ssl_version=0x%08X", static_cast<u32>(version));
    Service out_tmp;
    const Result rc = sslsCreateContextForSystem_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp));
    TracePki(m_client_info, context_id, "CreateContextForSystem", "forward_result=0x%08X", rc.GetValue());
    R_TRY(rc);

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(ams::sf::CreateSharedObjectEmplaced<ISslContextForSystem,
                                                     SslContextForSystemImpl>(
                     std::make_unique<::Service>(out_tmp), m_client_info,
                     m_should_dump_traffic, m_link_type, context_id),
                 target_object_id);

    R_SUCCEED();
}

Result SslServiceForSystemImpl::SetInterfaceVersion(u32 version) {
    const Result rc = sslsSetInterfaceVersion_sfMitm(m_forward_service.get(), version);
    TracePki(m_client_info, 0, "SetInterfaceVersion", "version=%u forward_result=0x%08X", version, rc.GetValue());
    return rc;
}

} // namespace ams::ssl::sf::impl