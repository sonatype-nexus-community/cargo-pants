use std::fmt;

#[derive(Debug, Deserialize)]
pub struct Coordinate {
    #[serde(rename(deserialize = "coordinates"))]
    pub purl: String,
    #[serde(default)]
    pub description: String,
    pub reference: String,
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub title: String,
    pub description: String,
    pub cvss_score: f32,
    pub cvss_vector: String,
    pub reference: String,
}

impl fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}\n{}\n{}\n{}\n{}",
            self.title, self.description, self.cvss_score, self.cvss_vector, self.reference
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mockito;

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
}
