// Copyright 2024 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::CertificateInfo;
use crate::service::{CommonServiceTask, ServiceTask};
use crate::util;
use crate::webhook;
use async_trait::async_trait;
use std::time::Duration;
use tracing::warn;

struct ValidityChecker {
    time_offset: i64,
    tls_cert_info_list: Vec<(String, CertificateInfo)>,
}

// Verify the validity period of tls certificate,
// include not after and not before.
fn validity_check(
    validity_list: &[(String, CertificateInfo)],
    time_offset: i64,
) -> Result<(), String> {
    let now = util::now().as_secs() as i64;
    for (name, cert) in validity_list.iter() {
        // will expire check
        if now > cert.not_after - time_offset {
            let message = format!(
                "{name} cert will be expired, issuer: {}, expired date: {:?}",
                cert.issuer, cert.not_after
            );
            return Err(message);
        }
        // not valid check
        if now < cert.not_before {
            let message = format!(
                "{name} cert is not valid, issuer: {}, valid date: {:?}",
                cert.issuer, cert.not_before
            );
            return Err(message);
        }
    }
    Ok(())
}

#[async_trait]
impl ServiceTask for ValidityChecker {
    async fn run(&self) -> Option<bool> {
        if let Err(message) =
            validity_check(&self.tls_cert_info_list, self.time_offset)
        {
            // certificate will be expired
            warn!(message);
            webhook::send(webhook::SendNotificationParams {
                level: webhook::NotificationLevel::Warn,
                category: webhook::NotificationCategory::TlsValidity,
                msg: message,
            });
        }
        None
    }
    fn description(&self) -> String {
        let offset_human: humantime::Duration =
            Duration::from_secs(self.time_offset as u64).into();
        format!(
            "offset: {offset_human}, tls_cert_info_list: {:?}",
            self.tls_cert_info_list
        )
    }
}

/// Create a tls certificate validity checker service,
/// if the certificate will be expired or not valid,
/// it will send webhook notificateion message.
pub fn new_tls_validity_service(
    tls_cert_info_list: Vec<(String, CertificateInfo)>,
) -> CommonServiceTask {
    let checker = ValidityChecker {
        tls_cert_info_list,
        // cert will be expired 7 days later
        time_offset: 7 * 24 * 3600_i64,
    };
    CommonServiceTask::new(
        "Tls validity checker",
        // check interval: one day
        Duration::from_secs(24 * 60 * 60),
        checker,
    )
}

#[cfg(test)]
mod tests {
    use super::{new_tls_validity_service, validity_check, ValidityChecker};
    use crate::{acme::CertificateInfo, service::ServiceTask};
    use pretty_assertions::assert_eq;
    use x509_parser::time::ASN1Time;

    #[test]
    fn test_validity_check() {
        let result = validity_check(
            &[(
                "Pingap".to_string(),
                CertificateInfo {
                    not_after: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    not_before: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    issuer: "pingap".to_string(),
                },
            )],
            7 * 24 * 3600,
        );

        assert_eq!(
            "Pingap cert is not valid, issuer: pingap, valid date: 2651852800",
            result.unwrap_err()
        );

        let result = validity_check(
            &[(
                "Pingap".to_string(),
                CertificateInfo {
                    not_after: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    not_before: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    issuer: "pingap".to_string(),
                },
            )],
            7 * 24 * 3600,
        );
        assert_eq!(
            "Pingap cert is not valid, issuer: pingap, valid date: 2651852800",
            result.unwrap_err()
        );
    }
    #[tokio::test]
    async fn test_validity_service() {
        let _ = new_tls_validity_service(vec![(
            "Pingap".to_string(),
            CertificateInfo {
                not_after: ASN1Time::from_timestamp(2651852800)
                    .unwrap()
                    .timestamp(),
                not_before: ASN1Time::from_timestamp(2651852800)
                    .unwrap()
                    .timestamp(),
                issuer: "".to_string(),
            },
        )]);
        let checker = ValidityChecker {
            tls_cert_info_list: vec![(
                "Pingap".to_string(),
                CertificateInfo {
                    not_after: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    not_before: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    issuer: "".to_string(),
                },
            )],
            time_offset: 7 * 24 * 3600_i64,
        };
        assert_eq!(
            r#"offset: 7days, tls_cert_info_list: [("Pingap", CertificateInfo { not_after: 2651852800, not_before: 2651852800, issuer: "" })]"#,
            checker.description()
        );
        let result = checker.run().await;
        assert_eq!(true, result.is_none());
    }
}
