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

extern crate packageurl;
extern crate quick_xml;

use crate::Package;
use packageurl::PackageUrl;
use quick_xml::events::BytesEnd;
use quick_xml::events::BytesStart;
use quick_xml::events::BytesText;
use quick_xml::events::Event;
use quick_xml::Writer;
use std::io::Cursor;
use std::str::FromStr;
use tracing::trace;

pub struct CycloneDXGenerator();

impl CycloneDXGenerator {
    pub fn generate_sbom_from_purls(&self, purls: Vec<Package>) -> String {
        return generate_1_3_sbom_from_purls(purls);
    }
}

fn generate_1_3_sbom_from_purls(purls: Vec<Package>) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    let mut bom = BytesStart::borrowed_name(b"bom");

    bom.push_attribute(("xmlns", "http://cyclonedx.org/schema/bom/1.3"));
    bom.push_attribute(("version", "1"));

    assert!(writer.write_event(Event::Start(bom)).is_ok());
    assert!(writer
        .write_event(Event::Start(BytesStart::borrowed_name(b"components")))
        .is_ok());
    for p in purls {
        let purl = PackageUrl::from_str(&p.as_purl()).unwrap();
        let mut component = BytesStart::borrowed_name(b"component");
        component.push_attribute(("type", "library"));
        component.push_attribute(("bom-ref", purl.clone().to_string().as_ref()));
        assert!(writer.write_event(Event::Start(component)).is_ok());

        // Name tag
        assert!(writer
            .write_event(Event::Start(BytesStart::borrowed_name(b"name")))
            .is_ok());
        let name = &purl.name();
        let name_value = BytesText::from_plain_str(name);
        assert!(writer.write_event(Event::Text(name_value)).is_ok());
        assert!(writer
            .write_event(Event::End(BytesEnd::borrowed(b"name")))
            .is_ok());

        // Version tag
        assert!(writer
            .write_event(Event::Start(BytesStart::borrowed_name(b"version")))
            .is_ok());
        let vers = &purl.version().unwrap();
        let version_value = BytesText::from_plain_str(vers);
        assert!(writer.write_event(Event::Text(version_value)).is_ok());
        assert!(writer
            .write_event(Event::End(BytesEnd::borrowed(b"version")))
            .is_ok());

        // License tag
        match p.license {
            Some(license) => {
                assert!(writer
                    .write_event(Event::Start(BytesStart::borrowed_name(b"licenses")))
                    .is_ok());

                assert!(writer
                    .write_event(Event::Start(BytesStart::borrowed_name(b"license")))
                    .is_ok());
                assert!(writer
                    .write_event(Event::Start(BytesStart::borrowed_name(b"name")))
                    .is_ok());

                let license_value = BytesText::from_plain_str(&license);
                assert!(writer.write_event(Event::Text(license_value)).is_ok());

                assert!(writer
                    .write_event(Event::End(BytesEnd::borrowed(b"name")))
                    .is_ok());

                assert!(writer
                    .write_event(Event::End(BytesEnd::borrowed(b"license")))
                    .is_ok());

                assert!(writer
                    .write_event(Event::End(BytesEnd::borrowed(b"licenses")))
                    .is_ok());
            }
            None => {
                trace!("No license found for component");
            }
        }

        // Purl tag
        assert!(writer
            .write_event(Event::Start(BytesStart::borrowed_name(b"purl")))
            .is_ok());
        let purl_string = &purl.clone().to_string();
        let purl_value = BytesText::from_plain_str(purl_string);
        assert!(writer.write_event(Event::Text(purl_value)).is_ok());
        assert!(writer
            .write_event(Event::End(BytesEnd::borrowed(b"purl")))
            .is_ok());

        assert!(writer
            .write_event(Event::End(BytesEnd::borrowed(b"component")))
            .is_ok());
    }

    assert!(writer
        .write_event(Event::End(BytesEnd::borrowed(b"components")))
        .is_ok());
    assert!(writer
        .write_event(Event::End(BytesEnd::borrowed(b"bom")))
        .is_ok());

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(s) => return s,
        Err(e) => panic!("Something went horribly wrong: {}", e),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_metadata::PackageId;

    #[test]
    fn can_generate_sbom_from_purls_test() {
        let cyclonedx = CycloneDXGenerator {};

        let mut packages: Vec<Package> = Vec::new();

        packages.push(Package {
            name: "test".to_string(),
            version: cargo_metadata::Version {
                major: 1,
                minor: 0,
                patch: 0,
                build: semver::BuildMetadata::default(),
                pre: semver::Prerelease::default(),
            },
            license: None,
            package_id: PackageId {
                repr: "".to_string(),
            },
        });
        packages.push(Package {
            name: "test".to_string(),
            version: cargo_metadata::Version {
                major: 1,
                minor: 0,
                patch: 1,
                build: semver::BuildMetadata::default(),
                pre: semver::Prerelease::default(),
            },
            license: None,
            package_id: PackageId {
                repr: "".to_string(),
            },
        });
        packages.push(Package {
            name: "test".to_string(),
            version: cargo_metadata::Version {
                major: 1,
                minor: 0,
                patch: 2,
                build: semver::BuildMetadata::default(),
                pre: semver::Prerelease::default(),
            },
            license: Some("Apache-2.0".to_string()),
            package_id: PackageId {
                repr: "".to_string(),
            },
        });

        let sbom = cyclonedx.generate_sbom_from_purls(packages);

        let expected = "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.3\" version=\"1\"><components><component type=\"library\" bom-ref=\"pkg:cargo/test@1.0.0\"><name>test</name><version>1.0.0</version><purl>pkg:cargo/test@1.0.0</purl></component><component type=\"library\" bom-ref=\"pkg:cargo/test@1.0.1\"><name>test</name><version>1.0.1</version><purl>pkg:cargo/test@1.0.1</purl></component><component type=\"library\" bom-ref=\"pkg:cargo/test@1.0.2\"><name>test</name><version>1.0.2</version><licenses><license><name>Apache-2.0</name></license></licenses><purl>pkg:cargo/test@1.0.2</purl></component></components></bom>";

        assert_eq!(sbom, expected);
    }
}
