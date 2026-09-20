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
    AMS_UNUSED(version, client_pid, out);
    // The experiment does not own ordinary contexts or server trust.
    return sm::mitm::ResultShouldForwardToSession();
}

Result SslServiceForSystemImpl::GetCertificates(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &certificates) {
    AMS_UNUSED(ids, certificates_count, certificates);
    // The experiment does not own ordinary contexts or server trust.
    return sm::mitm::ResultShouldForwardToSession();
}

Result SslServiceForSystemImpl::GetCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    AMS_UNUSED(ids, buffer_size);
    // The experiment does not own ordinary contexts or server trust.
    return sm::mitm::ResultShouldForwardToSession();
}

Result SslServiceForSystemImpl::CreateContextForSystem(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContextForSystem>>
        out) {
    // Only this accepted client's trace/fallback options can wrap a context.
    if (!m_pki_options.trace && !m_pki_options.fallback) {
        return sm::mitm::ResultShouldForwardToSession();
    }

    const u64 context_id = AllocateTraceContextId();
    TracePki(m_pki_options.trace, m_client_info, context_id, "CreateContextForSystem", "phase=begin");
    Service out_tmp;
    const Result rc = sslsCreateContextForSystem_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp));
    TracePki(m_pki_options.trace, m_client_info, context_id, "CreateContextForSystem", "forward_result=0x%08X", rc.GetValue());
    R_TRY(rc);

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(ams::sf::CreateSharedObjectEmplaced<ISslContextForSystem,
                                                     SslContextForSystemImpl>(
                     std::make_unique<::Service>(out_tmp), m_client_info,
                     m_should_dump_traffic, m_link_type, context_id, m_pki_options),
                 target_object_id);

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl