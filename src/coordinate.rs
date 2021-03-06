use std::fmt;
use crate::Vulnerability;

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

    pub fn get_threat_color(&self) -> Option<ansi_term::Color> {
        use ansi_term::Color;

        match self.get_threat_score() {
            9..=10 => Some(Color::Red),
            7..=8 => Some(Color::Red),
            4..=6 => Some(Color::Yellow),
            _ => None,
        }
    }

    pub fn get_threat_format(&self) -> ansi_term::Style {
        use ansi_term::{Color, Style};

        let color: Option<Color> = self.get_threat_color();
        match color {
            Some(value) => {
                match self.get_threat_score() {
                    9..=10 => value.bold(),
                    _ => value.normal(),
                }
            },
            None => Style::default()
        }
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
        let coordinate: Coordinate = serde_json::from_slice(raw_json).unwrap();
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
