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
#include "networkmitm_ssl_service_impl.hpp"
#include "networkmitm_utils.hpp"
#include "shim/ssl_shim.h"
#include "networkmitm_pki_trace.hpp"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslServiceImpl::CreateContext(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out) {
    // This service is accepted only for the fixed account-link diagnostic
    // candidates. The wrapper remains transparent after recording command 0.
    if (!m_diagnostic_trace) return sm::mitm::ResultShouldForwardToSession();
    const u64 context_id = AllocateTraceContextId();
    TracePki(true, m_client_info, context_id, "CreateContext",
             "service=ssl command=0 phase=begin");
    Service out_tmp;
    const Result rc = sslCreateContext_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp));
    TracePki(true, m_client_info, context_id, "CreateContext",
             "service=ssl command=0 forward_result=0x%08X", rc.GetValue());
    R_TRY(rc);

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};
    out.SetValue(ams::sf::CreateSharedObjectEmplaced<ISslContext, SslContextImpl>(
                     std::make_unique<::Service>(out_tmp), m_client_info,
                     m_should_dump_traffic, m_link_type, context_id, true),
                 target_object_id);
    R_SUCCEED();
}

Result SslServiceImpl::GetCertificates(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &certificates) {
    AMS_UNUSED(ids, certificates_count, certificates);
    // The experiment does not own ordinary contexts or server trust.
    return sm::mitm::ResultShouldForwardToSession();
}

Result SslServiceImpl::GetCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    AMS_UNUSED(ids, buffer_size);
    // The experiment does not own ordinary contexts or server trust.
    return sm::mitm::ResultShouldForwardToSession();
}

} // namespace ams::ssl::sf::impl
