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

use crate::Vulnerability;
use serde::Deserialize;
use std::fmt;

#[derive(Debug, Default, Deserialize)]
pub struct Coordinate {
    #[serde(rename(deserialize = "coordinates"))]
    pub purl: String,
    #[serde(default)]
    pub description: String,
    pub reference: String,
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
}

impl Coordinate {
    pub fn has_vulnerabilities(&self) -> bool {
        self.vulnerabilities.len() > 0
    }

    pub fn get_threat_score(&self) -> u8 {
        let mut score = 0u8;
        for vulnerability in &self.vulnerabilities {
            score = score.max(vulnerability.cvss_score as u8);
        }
        score
    }
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut vul_str = String::new();
        for v in &self.vulnerabilities {
            vul_str.push_str(&format!("\nVulnerability - {} \n{}", self.purl, v));
        }
        write!(f, "{}:{}\n{}", self.description, self.reference, vul_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bytes() {
        let raw_json: &[u8] = r##"{
            "coordinates": "pkg:pypi/rust@0.1.1",
            "description": "Ribo-Seq Unit Step Transformation",
            "reference": "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1",
            "vulnerabilities": []
        }"##
        .as_bytes();
        let coordinate: Coordinate =
            serde_json::from_slice(raw_json).expect("failed to parse coordinate JSON");
        assert_eq!(
            coordinate.reference,
            "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1"
        );
        assert_eq!(coordinate.description, "Ribo-Seq Unit Step Transformation");
    }

    #[test]
    fn test_has_no_vulnerabilities() {
        let coordinate = Coordinate::default();
        assert_eq!(coordinate.has_vulnerabilities(), false);
    }

    #[test]
    fn test_has_vulnerabilities() {
        let mut coordinate = Coordinate::default();
        coordinate.vulnerabilities.push(Vulnerability::default());
        assert_eq!(coordinate.has_vulnerabilities(), true);
    }
}
