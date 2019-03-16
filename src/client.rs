// Copyright 2019 Glenn Mohre.
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
use std::{
    collections::HashMap
};

use url::Url;
use reqwest::header::{USER_AGENT, HeaderValue, HeaderMap};
use reqwest::Client;
use log::{debug};

use crate::{package::Package, coordinate::Coordinate};

const PRODUCTION_API_BASE: &str = "https://ossindex.sonatype.org/api/v3/";

//type HttpsClient = Client<HttpsConnector<HttpConnector>, hyper::Body>;

pub struct OSSIndexClient {
    url_maker: UrlMaker,
}

struct UrlMaker {
    api_base: String,
    api_key: String
}

#[derive(Deserialize, Debug)]
struct OSSResponse {
    coordinates: Vec<Coordinate>,
}

impl OSSIndexClient {
    pub fn new(key: String) -> OSSIndexClient {
        env_logger::init();
        #[cfg(not(test))]
            let ossindex_api_base = PRODUCTION_API_BASE;

        #[cfg(test)]
            let ossindex_api_base =  &format!("{}/", &mockito::server_url());

        debug!("Value for ossindex_api_base: {}", ossindex_api_base);

        let url_maker = UrlMaker::new(
            ossindex_api_base.to_owned(),
            key,
        );

        OSSIndexClient {
            url_maker
        }
    }

    fn construct_headers(&self) -> HeaderMap {
        const VERSION: &'static str = env!("CARGO_PKG_VERSION");
        
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&format!("cargo-pants/{}", VERSION)).unwrap());
        headers
    }

    pub fn post_coordinates(
        &self,
        purls: Vec<Package>
    ) -> Vec<Coordinate> {
        let url = self.url_maker.component_report_url();
        let coordinates: Vec<Coordinate> = self.post_json_reqwest(url.to_string(), purls).unwrap();
        return coordinates
    }

    fn post_json_reqwest(
        &self,
        uri: String,
        packages: Vec<Package>
    ) ->  Result<Vec<Coordinate>, reqwest::Error> {
        let mut purls: HashMap<String, Vec<String>> = HashMap::new();

        purls.insert(
            "coordinates".to_string(),
            packages.iter().map(
                |x| x.as_purl()
            ).collect()
        );

        let response = Client::new()
            .post(&uri)
            .json(&purls)
            .headers(self.construct_headers())
            .send()?
            .json()?;

        Ok(response)
    }
}

impl UrlMaker {
    pub fn new (
        api_base: String,
        api_key: String
    ) -> UrlMaker {
        UrlMaker { api_base: api_base, api_key: api_key }
    }

    fn build_url(
        &self,
        path: &str
    ) -> Result<Url, url::ParseError> {
        let mut url = Url::parse(&self.api_base)?.join(path)?;
        url.query_pairs_mut()
            .append_pair("api_key", &self.api_key);
        Ok(url)
    }

    pub fn component_report_url(&self) -> Url {
        let url = self.build_url("component-report").unwrap();
        return url
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use mockito;

//     #[test]
//     fn new_ossindexclient() {
//         let key = String::from("ALL_YOUR_KEY");
//         let client = OSSIndexClient::new(key);
//         assert_eq!(client.uri_maker.api_key, "ALL_YOUR_KEY");
//     }
//     #[test]
//     fn new_urimaker() {
//         let api_base = "https://allyourbase.api/api/v3/";
//         let api_key = "ALL_YOUR_KEY";
//         let purl = "pkg:pypi/rust@0.1.1";
//         let uri = UriMaker::new(api_base.to_string(), api_key.to_string());
//         assert_eq!(uri.api_base, api_base);
//         assert_eq!(uri.api_key, api_key);
//         let url = uri.coordinate_by_purl(&purl);
//         assert_eq!(url, "https://allyourbase.api/api/v3/component-report/pkg:pypi/rust@0.1.1?api_key=ALL_YOUR_KEY");
//     }

//     #[test]
//     fn test_parse_bytes() {
//         let raw_json: &[u8] = r##"{
//             "coordinates": "pkg:pypi/rust@0.1.1",
//             "description": "Ribo-Seq Unit Step Transformation",
//             "reference": "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1",
//             "vulnerabilities": []
//         }"##.as_bytes();

//         let coordinate: Coordinate =
//             serde_json::from_slice(raw_json).unwrap();

//         assert_eq!(coordinate.reference, "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1");
//         assert_eq!(coordinate.description, "Ribo-Seq Unit Step Transformation");
//     }

//     #[test]
//     fn test_parse_bytes_as_value() {
//         let raw_json: &[u8] = r##"{
//             "coordinates": "pkg:pypi/rust@0.1.1",
//             "description": "Ribo-Seq Unit Step Transformation",
//             "reference": "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1",
//             "vulnerabilities": []
//         }"##.as_bytes();

//         let value: serde_json::Value =
//             serde_json::from_slice(raw_json).unwrap();


//         assert_eq!(value["coordinates"], "pkg:pypi/rust@0.1.1");
//         assert_eq!(value["description"], "Ribo-Seq Unit Step Transformation");
//     }

//     fn test_post_json() {
//         // let purl = "pkg:pypi/rust@0.1.1";
//         // let expected_url = format!("{}/component-report/{}", &mockito::server_url(), purl);
//         let mock = mockito::mock("POST", "/component-report/pkg:pypi/rust@0.1.1")
//             .with_status(200)
//             .with_header("content-type", "fixMe")
//             .with_body("fixMe")
//             .create();

//         {
//             // make a request
//             let key = String::from("ALL_YOUR_KEY");
//             let client = OSSIndexClient::new(key);
//             // todo assert return value
//             //assert_eq!(client.search_coordinates(purl).is_err(), true);
//         }
//         // todo this fails right now because client.search_coordinates() does not call the http endpoint expected_url
//         mock.assert();
//     }

//     fn test_component_report_json() {
//         let raw_json: &[u8] = r##"[{
//             "coordinates": "pkg:cargo/claxon@0.3.0",
//             "description": "A FLAC decoding library",
//             "reference": "https://ossindex.sonatype.org/component/pkg:cargo/claxon@0.3.0",
//             "vulnerabilities": [{
//                 "id": "bd1aacf1-bc91-441d-aaf8-44f40513200d",
//                 "title": "CWE-200: Information Exposure",
//                 "description": "An information exposure is the intentional or unintentional disclosure of information to an actor that is not explicitly authorized to have access to that information.",
//                 "cvssScore": 4.3,
//                 "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
//                 "cwe": "CWE-200",
//                 "reference": "https://ossindex.sonatype.org/vuln/bd1aacf1-bc91-441d-aaf8-44f40513200d"
//             }]
//             }, {
//             "coordinates": "pkg:cargo/arrayfire@3.5.0",
//             "description": "ArrayFire is a high performance software library for parallel computing with an easy-to-use API. Its array based function set makes parallel programming simple. ArrayFire's multiple backends (CUDA, OpenCL and native CPU) make it platform independent and highly portable. A few lines of code in ArrayFire can replace dozens of lines of parallel computing code, saving you valuable time and lowering development costs. This crate provides Rust bindings for ArrayFire library.",
//             "reference": "https://ossindex.sonatype.org/component/pkg:cargo/arrayfire@3.5.0",
//             "vulnerabilities": [{
//                 "id": "bb99215c-ee5f-4539-98a5-f1257429c3a0",
//                 "title": "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
//                 "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
//                 "cvssScore": 8.6,
//                 "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
//                 "cwe": "CWE-119",
//                 "reference": "https://ossindex.sonatype.org/vuln/bb99215c-ee5f-4539-98a5-f1257429c3a0"
//             }]
//         }]"##.as_bytes();
//     }

// }
