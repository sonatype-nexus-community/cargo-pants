use std::fmt;

#[derive(Debug, Deserialize)]
pub struct Coordinate {
    #[serde(rename(deserialize = "coordinates"))]
    pub purl: String,
    #[serde(default)]
    pub description: String,

    pub reference: String,

    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>
}

#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Vulnerability {
    pub title: String,
    pub description: String,
    pub cvss_score: f32,
    pub cvss_vector: String,
    pub reference: String
}

impl fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\n{}\n{}\n{}\n{}", self.title, self.description, self.cvss_score, self.cvss_vector, self.reference)
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