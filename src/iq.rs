
use reqwest::Body;
use std::error::Error;
use reqwest::Url;
use reqwest::Client;
use reqwest::StatusCode;
use std::time::Duration;
use std::thread;
use std::fmt;

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
    pub name: String
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
    pub is_error: bool,
}

#[derive(Debug)]
struct PollingError(String);

impl fmt::Display for PollingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Too many polling attempts occurred: {}", self.0)
    }
}

impl Error for PollingError {}

pub struct IQClient {
  server: String,
  user: String,
  token: String,
  stage: String,
  application: String,
  attempts: u32
}

impl IQClient {
  pub fn new(server: String, user: String, token: String, stage: String, application: String, attempts: u32) -> IQClient {
    IQClient {server, user, token, stage, application, attempts}
  }

  pub fn audit_with_iq_server(&self, sbom: String) -> Result<StatusURLResult, Box<dyn Error>> {

    let app = &self.application;
    let internal_application_id = match self.get_internal_application_id(app.to_string()) {
      Ok(internal_application_id) => internal_application_id,
      Err(e) => {
        return Err(Box::new(e))
      }
    };

    let internal_app = &internal_application_id.applications[0].id;

    let status_url = match self.submit_to_third_party_api(internal_app.to_string(), sbom) {
      Ok(status_url) => status_url,
      Err(e) => {
        return Err(Box::new(e))
      }
    };

    let mut i = 0;

    let status_url_string = &status_url.status_url;

    loop {
      if i > self.attempts { break };

      let result = self.poll_status_url(status_url_string.to_string());
      if result.is_ok() {
        return Ok(result.unwrap())
      }
      if result.is_err() {
        let res_err = result.unwrap_err();
        if res_err.is_client_error() {
          match res_err.status().unwrap() {
            StatusCode::NOT_FOUND => {
              i = i + 1;

              thread::sleep(Duration::from_secs(1));
              continue
            },
            _ => break
          }
        }
      }
    };

    return Err(Box::new(PollingError("Exceeded polling attempts".into())))
  }

  fn get_internal_application_id(&self, application: String) -> Result<ApplicationResponse, reqwest::Error> {
    let client = Client::new();

    let user = &self.user;
    let token = &self.token;

    let url = Url::parse(&format!("{}{}{}", &self.server, "/api/v2/applications?publicId=", &application)).unwrap();
    let mut res = client.get(url)
      .basic_auth(user.to_string(), Some(token.to_string()))
      .send()?;

    return res.json();
  }

  fn submit_to_third_party_api(&self, internal_application_id: String, sbom: String) -> Result<SbomSubmitResult, reqwest::Error> {
    let client = Client::new();

    let user = &self.user;
    let token = &self.token;

    let url = Url::parse(&format!("{}{}{}{}{}", &self.server, "/api/v2/scan/applications/", internal_application_id, "/sources/cargo-pants?stageId=", &self.stage)).unwrap();

    let body = Body::from(sbom);
    let mut res = client.post(url)
      .basic_auth(user.to_string(), Some(token.to_string()))
      .body(body)
      .send()?;

    return res.json();
  }

  fn poll_status_url(&self, status_url: String) -> Result<StatusURLResult, reqwest::Error> {
    let client = Client::new();

    let user = &self.user;
    let token = &self.token;

    let url_string = format!("{}/{}", &self.server, &status_url);
    let url = Url::parse(&url_string).unwrap();
    let mut res = client.get(url)
      .basic_auth(user.to_string(), Some(token.to_string()))
      .send()?;

    return res.json();
  }
}
