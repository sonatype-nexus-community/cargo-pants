// Copyright 2021 Sonatype.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use reqwest::Url;
use std::error::Error;
use std::fmt;
use std::thread;
use std::time::Duration;

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationResponse {
    pub applications: Vec<Application>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub public_id: String,
    pub name: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationTag {
    pub id: String,
    pub tag_id: String,
    pub application_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomSubmitResult {
    pub status_url: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusURLResult {
    pub policy_action: String,
    pub report_html_url: String,
    pub report_pdf_url: String,
    pub report_data_url: String,
    pub embeddable_report_html_url: String,
    pub is_error: bool,
    pub components_affected: ComponentsAffected,
    pub open_policy_violations: OpenPolicyViolations,
    pub grandfathered_policy_violations: i64,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentsAffected {
    pub critical: i64,
    pub severe: i64,
    pub moderate: i64,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPolicyViolations {
    pub critical: i64,
    pub severe: i64,
    pub moderate: i64,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawReportResults {
    pub components: Vec<Component>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub hash: String,
    pub component_identifier: ComponentIdentifier,
    pub package_url: String,
    pub proprietary: bool,
    pub match_state: String,
    pub pathnames: Vec<String>,
    pub license_data: LicenseData,
    pub security_data: SecurityData,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentIdentifier {
    pub format: String,
    pub coordinates: Coordinates,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Coordinates {
    pub artifact_id: Option<String>,
    pub name: Option<String>,
    pub group_id: Option<String>,
    pub version: String,
    pub extension: Option<String>,
    pub classifier: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseData {
    pub declared_licenses: Vec<DeclaredLicense>,
    pub observed_licenses: Vec<ObservedLicense>,
    pub effective_licenses: Vec<EffectiveLicense>,
    pub overridden_licenses: Vec<::serde_json::Value>,
    pub status: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeclaredLicense {
    pub license_id: String,
    pub license_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedLicense {
    pub license_id: String,
    pub license_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveLicense {
    pub license_id: String,
    pub license_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityData {
    pub security_issues: Vec<SecurityIssue>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityIssue {
    pub source: String,
    pub reference: String,
    pub severity: f64,
    pub status: String,
    pub url: String,
    pub threat_category: String,
}

pub struct ReportResults {
    pub url_results: StatusURLResult,
    pub data_results: RawReportResults,
}

#[derive(Debug)]
struct PollingError(String);

impl fmt::Display for PollingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Too many polling attempts occurred: {}", self.0)
    }
}

impl Error for PollingError {}

#[derive(Debug)]
struct GeneralError(String);

impl fmt::Display for GeneralError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "A general error occurred talking to Nexus IQ Server: {}",
            self.0
        )
    }
}

impl Error for GeneralError {}

pub struct IQClient {
    pub server: String,
    user: String,
    token: String,
    stage: String,
    application: String,
    attempts: u32,
}

impl IQClient {
    pub fn new(
        mut server: String,
        user: String,
        token: String,
        stage: String,
        application: String,
        attempts: u32,
    ) -> IQClient {
        if server.ends_with("/") {
            server = server.trim_end_matches("/").to_string();
        }
        IQClient {
            server,
            user,
            token,
            stage,
            application,
            attempts,
        }
    }

    pub fn audit_with_iq_server(&self, sbom: String) -> Result<ReportResults, Box<dyn Error>> {
        let app = &self.application;
        let internal_application_id = match self.get_internal_application_id(app.to_string()) {
            Ok(internal_application_id) => internal_application_id,
            Err(e) => return Err(Box::new(e)),
        };

        let internal_app = &internal_application_id.applications[0].id;

        let status_url = match self.submit_to_third_party_api(internal_app.to_string(), sbom) {
            Ok(status_url) => status_url,
            Err(e) => return Err(Box::new(e)),
        };

        let mut i = 0;

        let status_url_string = &status_url.status_url;

        loop {
            if i > self.attempts {
                break;
            };

            let result = self.poll_status_url(status_url_string.to_string());
            if result.is_ok() {
                let res = result.unwrap();
                let data = self.get_raw_report_results(res.report_data_url.clone());

                if data.is_ok() {
                    let combined_results: ReportResults = ReportResults {
                        data_results: data.unwrap(),
                        url_results: res,
                    };
                    return Ok(combined_results);
                } else {
                    return Err(Box::new(GeneralError(data.unwrap_err().to_string())));
                }
            }
            if result.is_err() {
                let res_err = result.unwrap_err();
                if res_err.status().unwrap().is_client_error() {
                    match res_err.status().unwrap() {
                        StatusCode::NOT_FOUND => {
                            i = i + 1;

                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                        _ => break,
                    }
                }
            }
        }

        return Err(Box::new(PollingError("Exceeded polling attempts".into())));
    }

    fn get_internal_application_id(
        &self,
        application: String,
    ) -> Result<ApplicationResponse, reqwest::Error> {
        let client = Client::new();

        let url = Url::parse(&format!(
            "{}{}{}",
            &self.server, "/api/v2/applications?publicId=", &application
        ))
        .unwrap();

        let res = client
            .get(url)
            .basic_auth(&self.user.to_string(), Some(&self.token.to_string()))
            .send()?;

        return res.json();
    }

    fn submit_to_third_party_api(
        &self,
        internal_application_id: String,
        sbom: String,
    ) -> Result<SbomSubmitResult, reqwest::Error> {
        let client = Client::new();

        let url = Url::parse(&format!(
            "{}{}{}{}{}",
            &self.server,
            "/api/v2/scan/applications/",
            internal_application_id,
            "/sources/cargo-pants?stageId=",
            &self.stage
        ))
        .unwrap();

        let res = client
            .post(url)
            .basic_auth(&self.user.to_string(), Some(&self.token.to_string()))
            .body(sbom.clone())
            .send()?;

        return res.json();
    }

    fn poll_status_url(&self, status_url: String) -> Result<StatusURLResult, reqwest::Error> {
        let client = Client::new();

        let url_string = format!("{}/{}", &self.server, &status_url);
        let url = Url::parse(&url_string).unwrap();
        let res = client
            .get(url)
            .basic_auth(&self.user.to_string(), Some(&self.token.to_string()))
            .send()?;

        return res.json();
    }

    fn get_raw_report_results(
        &self,
        report_url: String,
    ) -> Result<RawReportResults, reqwest::Error> {
        let client = Client::new();

        let url_string = format!("{}/{}", &self.server, &report_url);
        let url = Url::parse(&url_string).unwrap();
        let res = client
            .get(url)
            .basic_auth(&self.user.to_string(), Some(&self.token.to_string()))
            .send()?;

        return res.json();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_iqclient() {
        let iq_server_url: &str = "iqServerURL";
        let user: &str = "iqUser";
        let token: &str = "iqToken";
        let stage: &str = "iqStage";
        let app_id: &str = "iqAppId";
        let client = IQClient::new(
            iq_server_url.to_string(),
            user.to_string(),
            token.to_string(),
            stage.to_string(),
            app_id.to_string(),
            1,
        );
        assert_eq!(client.server, iq_server_url.to_string());
        assert_eq!(client.user, user.to_string());
        assert_eq!(client.token, token.to_string());
        assert_eq!(client.stage, stage.to_string());
        assert_eq!(client.application, app_id.to_string());
        assert_eq!(client.attempts, 1);
    }
}
