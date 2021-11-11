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

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use terminal_size::{terminal_size, Height, Width};
use tracing::trace;

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
    return match terminal_size() {
        Some((Width(w), Height(_h))) => w,
        None => 80,
    };
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterList {
    pub ignore: Vec<Ignore>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ignore {
    pub id: String,
    pub reason: Option<String>,
}

pub fn filter_vulnerabilities(packages: &mut Vec<Coordinate>, exclude_vuln_file_path: PathBuf) {
    match File::open(exclude_vuln_file_path) {
        Ok(file) => {
            let exclude_reader = BufReader::new(file);
            let filter_list_json: FilterList =
                serde_json::from_reader(exclude_reader).expect("JSON was not well formatted");

            let ignored_ids: HashSet<String> = filter_list_json
                .ignore
                .into_iter()
                .map(|filter| filter.id)
                .collect();

            packages.iter_mut().for_each(|p| {
                if p.has_vulnerabilities() {
                    p.vulnerabilities.retain(|v| !ignored_ids.contains(&v.id))
                }
            });
        }
        Err(err) => {
            trace!("No file found at location provided: {}", err.to_string())
        }
    }
}
