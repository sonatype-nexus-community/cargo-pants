// Copyright 2019 Glenn Mohre, Sonatype.
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
#![allow(dead_code)]

extern crate serde;
extern crate url;

#[macro_use]
extern crate serde_derive;
extern crate log;
extern crate serde_json;

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use terminal_size::{terminal_size, Height, Width};

pub mod client;
pub mod common;
pub mod coordinate;
pub mod cyclonedx;
pub mod error;
pub mod iq;
pub mod package;
pub mod parse;
pub mod vulnerability;

pub use crate::{
    client::*, common::*, coordinate::*, cyclonedx::CycloneDXGenerator, error::*, iq::IQClient,
    package::*, parse::*, vulnerability::*,
};

pub fn calculate_term_width() -> u16 {
    match terminal_size() {
        Some((Width(w), Height(_h))) => {
            return w;
        }
        None => {
            return 80;
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterList {
    pub ignore: Vec<Ignore>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ignore {
    pub id: String,
    pub reason: Option<String>,
}

pub fn filter_vulnerabilities(packages: &mut Vec<Coordinate>, exclude_vuln_file_path: PathBuf) {
    let file = File::open(exclude_vuln_file_path).expect("Unable to open file");
    let reader = BufReader::new(file);
    let filter_list_json: FilterList =
        serde_json::from_reader(reader).expect("JSON was not well formatted");

    let ids = filter_list_json
        .ignore
        .into_iter()
        .map(|filter| filter.id)
        .collect::<Vec<String>>();

    for i in (0..packages.len()).rev() {
        if packages[i].has_vulnerabilities() {
            let mut vulns: Vec<Vulnerability> = vec![];
            let old_vulns = &packages[i].vulnerabilities;
            old_vulns.into_iter().all(|vuln| {
                if !ids.contains(&vuln.id) {
                    vulns.push(vuln.clone());
                    return true;
                } else {
                    return false;
                }
            });
            packages[i].vulnerabilities = vulns;
        }
    }
}
