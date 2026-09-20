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
#include "networkmitm_ssl_context_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslContextImpl::SetOption(const ams::ssl::sf::OptionType &option,
                                 u32 value) {
    R_TRY(sslContextSetOption_sfMitm(m_forward_service.get(),
                                     static_cast<u32>(option), value));

    R_SUCCEED();
}

Result SslContextImpl::GetOption(const ams::ssl::sf::OptionType &option,
                                 ams::sf::Out<u32> value) {
    R_TRY(sslContextGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(option), value.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::CreateConnection(
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out) {
    Service out_tmp;
    R_TRY(sslContextCreateConnection_sfMitm(m_forward_service.get(),
                                            std::addressof(out_tmp)));

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslConnection, SslConnectionImpl>(
            std::make_unique<::Service>(out_tmp), m_client_info),
        target_object_id);

    R_SUCCEED();
}

Result SslContextImpl::GetConnectionCount(ams::sf::Out<u32> count) {
    R_TRY(sslContextGetConnectionCount_sfMitm(m_forward_service.get(),
                                              count.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::ImportServerPki(
    const ams::ssl::sf::CertificateFormat &certificateFormat,
    const ams::sf::InBuffer &certificate, ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextImportServerPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(certificateFormat),
        certificate.GetPointer(), certificate.GetSize(),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::ImportClientPki(const ams::sf::InBuffer &certificate,
                                       const ams::sf::InBuffer &ascii_password,
                                       ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextImportClientPki_sfMitm(
        m_forward_service.get(), certificate.GetPointer(),
        certificate.GetSize(), ascii_password.GetPointer(),
        ascii_password.GetSize(), certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::RemoveServerPki(u64 certificate_id) {
    R_TRY(sslContextRemoveServerPki_sfMitm(m_forward_service.get(),
                                           certificate_id));

    R_SUCCEED();
}

Result SslContextImpl::RemoveClientPki(u64 certificate_id) {
    R_TRY(sslContextRemoveClientPki_sfMitm(m_forward_service.get(),
                                           certificate_id));

    R_SUCCEED();
}

Result SslContextImpl::RegisterInternalPki(const ams::ssl::sf::InternalPki &pki,
                                           ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextRegisterInternalPki_sfMitm(m_forward_service.get(),
                                               static_cast<u32>(pki),
                                               certificate_id.GetPointer()));

    R_SUCCEED();
}

Result
SslContextImpl::AddPolicyOid(const ams::sf::InBuffer &cert_policy_checking) {
    R_TRY(sslContextAddPolicyOid_sfMitm(m_forward_service.get(),
                                        cert_policy_checking.GetPointer(),
                                        cert_policy_checking.GetSize()));

    R_SUCCEED();
}

Result SslContextImpl::ImportCrl(const ams::sf::InBuffer &crl,
                                 ams::sf::Out<u64> crl_id) {
    R_TRY(sslContextImportCrl_sfMitm(m_forward_service.get(), crl.GetPointer(),
                                     crl.GetSize(), crl_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::RemoveCrl(u64 crl_id) {
    R_TRY(sslContextRemoveCrl_sfMitm(m_forward_service.get(), crl_id));

    R_SUCCEED();
}

Result SslContextImpl::ImportClientCertKeyPki(
    const ams::ssl::sf::CertificateFormat &certificateFormat,
    const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key,
    ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextImportClientCertKeyPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(certificateFormat),
        cert.GetPointer(), cert.GetSize(), key.GetPointer(), key.GetSize(),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::GeneratePrivateKeyAndCert(
    u32 val, const ams::sf::InBuffer &params, const ams::sf::OutBuffer &cert,
    const ams::sf::OutBuffer &key, ams::sf::Out<u32> out_cert_size,
    ams::sf::Out<u32> out_key_size) {
    R_TRY(sslContextGeneratePrivateKeyAndCert_sfMitm(
        m_forward_service.get(), val, params.GetPointer(), params.GetSize(),
        cert.GetPointer(), cert.GetSize(), key.GetPointer(), key.GetSize(),
        out_cert_size.GetPointer(), out_key_size.GetPointer()));

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
