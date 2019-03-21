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
use log::{debug,error};

use crate::{package::{PackageName, Package}, coordinate::Coordinate};

const PRODUCTION_API_BASE: &str = "https://ossindex.sonatype.org/api/v3/";

pub struct OSSIndexClient {
    url_maker: UrlMaker,
}

struct UrlMaker {
    api_base: String,
    api_key: String
}

impl OSSIndexClient {
    pub fn new(key: String) -> OSSIndexClient {
        #[cfg(not(test))]
            let ossindex_api_base = PRODUCTION_API_BASE;

        #[cfg(test)]
            let ossindex_api_base =  &format!("{}/api/v3/", &mockito::server_url());

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
        let coordinates: Vec<Coordinate> = self.post_json(url.to_string(), purls).unwrap();
        return coordinates
    }

    fn post_json(
        &self,
        url: String,
        packages: Vec<Package>
    ) ->  Result<Vec<Coordinate>, reqwest::Error> {
        // TODO: The purl parsing should move into it's own function or builder, etc...
        let mut purls: HashMap<String, Vec<String>> = HashMap::new();

        purls.insert(
            "coordinates".to_string(),
            packages.iter().map(
                |x| x.as_purl()
            ).collect()
        );
        error!("\n Purls {:?}, {:?}", &purls, &url);
        let client = Client::new();
        let response: Vec<Coordinate> = client.post(&url)
            .json(&purls)
            .headers(self.construct_headers())
            .send()?
            .json()?;
        error!("\njson{:?}", response);
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
            .append_pair(&"api_key".to_string(), &self.api_key);
        Ok(url)
    }

    pub fn component_report_url(&self) -> Url {
        let url = self.build_url("component-report").unwrap();
        return url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;
    extern crate env_logger;
    
    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
    #[test]
    fn new_ossindexclient() {
        let key = String::from("ALL_YOUR_KEY");
        let client = OSSIndexClient::new(key);
        assert_eq!(client.url_maker.api_key, "ALL_YOUR_KEY");
    }
    #[test]
    fn new_urlmaker() {
        error!("Stuff");
        let api_base = "https://allyourbase.api/api/v3/";
        let api_key = "ALL_YOUR_KEY";
        let urlmaker = UrlMaker::new(api_base.to_string(), api_key.to_string());
        assert_eq!(urlmaker.api_base, api_base);
        assert_eq!(urlmaker.api_key, api_key);
    }

    #[test]
    fn test_parse_bytes_as_value() {
        let raw_json: &[u8] = r##"{
            "coordinates": "pkg:pypi/rust@0.1.1",
            "description": "Ribo-Seq Unit Step Transformation",
            "reference": "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1",
            "vulnerabilities": []
        }"##.as_bytes();
        let value: serde_json::Value =
            serde_json::from_slice(raw_json).unwrap();
        assert_eq!(value["coordinates"], "pkg:pypi/rust@0.1.1");
        assert_eq!(value["description"], "Ribo-Seq Unit Step Transformation");
    }

    fn test_package_data() -> Package {
        let package_data = r##"{
            "name": "claxon",
            "version": "0.3.0"
        }"##.as_bytes();
        let package: Package = match serde_json::from_slice::<Package>(package_data) {
            Ok(p) => p,
            Err(p) => panic!(format!("Someshit {}", p))
        };
        return package
    }
    #[test]
    fn test_post_json() {
        init_logger();
        let raw_json: &[u8] = r##"{
            "coordinates": "pkg:cargo/claxon@0.3.0",
            "description": "A FLAC decoding library",
            "reference": "https://ossindex.sonatype.org/component/pkg:cargo/claxon@0.3.0",
            "vulnerabilities": 
                [
                    {
                        "title": "CWE-200: Information Exposure",
                        "description": "An information exposure is the intentional or unintentional disclosure of information to an actor that is not explicitly authorized to have access to that information.",
                        "cvssScore": 4.3,
                        "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                        "reference": "https://ossindex.sonatype.org/vuln/bd1aacf1-bc91-441d-aaf8-44f40513200d"
                    }
                ]
            }"##.as_bytes();
        let coord: Coordinate = serde_json::from_slice(raw_json).unwrap();
        error!("\nCoord {}", coord);
        let package: Package = test_package_data();
        error!("\n Package {}", package);
        let mock = mock("POST", "/component-report")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json)
            .create();
        let packages = vec![package];
        {
            let key = String::from("ALL_YOUR_KEY");
            let client = OSSIndexClient::new(key);
            client.post_coordinates(packages);
        }
        mock.assert();
    }
    fn test_component_report_json() -> &'static [u8] {
        return r##"[{
            "coordinates": "pkg:cargo/claxon@0.3.0",
            "description": "A FLAC decoding library",
            "reference": "https://ossindex.sonatype.org/component/pkg:cargo/claxon@0.3.0",
            "vulnerabilities": [{
                "id": "bd1aacf1-bc91-441d-aaf8-44f40513200d",
                "title": "CWE-200: Information Exposure",
                "description": "An information exposure is the intentional or unintentional disclosure of information to an actor that is not explicitly authorized to have access to that information.",
                "cvssScore": 4.3,
                "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                "cwe": "CWE-200",
                "reference": "https://ossindex.sonatype.org/vuln/bd1aacf1-bc91-441d-aaf8-44f40513200d"
            }]
            }, {
            "coordinates": "pkg:cargo/arrayfire@3.5.0",
            "description": "ArrayFire is a high performance software library for parallel computing with an easy-to-use API. Its array based function set makes parallel programming simple. ArrayFire's multiple backends (CUDA, OpenCL and native CPU) make it platform independent and highly portable. A few lines of code in ArrayFire can replace dozens of lines of parallel computing code, saving you valuable time and lowering development costs. This crate provides Rust bindings for ArrayFire library.",
            "reference": "https://ossindex.sonatype.org/component/pkg:cargo/arrayfire@3.5.0",
            "vulnerabilities": [{
                "id": "bb99215c-ee5f-4539-98a5-f1257429c3a0",
                "title": "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
                "cvssScore": 8.6,
                "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
                "cwe": "CWE-119",
                "reference": "https://ossindex.sonatype.org/vuln/bb99215c-ee5f-4539-98a5-f1257429c3a0"
            }]
        }]"##.as_bytes();
     }
 }

