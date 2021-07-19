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

use packageurl::PackageUrl;
use quick_xml::events::BytesEnd;
use quick_xml::events::BytesStart;
use quick_xml::events::BytesText;
use quick_xml::events::Event;
use quick_xml::Writer;
use std::io::Cursor;
use std::str::FromStr;

pub struct CycloneDXGenerator();

impl CycloneDXGenerator {
    pub fn generate_sbom_from_purls(&self, purls: Vec<String>) -> String {
        return generate_1_3_sbom_from_purls(purls);
    }
}

fn generate_1_3_sbom_from_purls(purls: Vec<String>) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    let mut bom = BytesStart::borrowed_name(b"bom");

    bom.push_attribute(("xmlns", "http://cyclonedx.org/schema/bom/1.3"));
    bom.push_attribute(("version", "1"));

    assert!(writer.write_event(Event::Start(bom)).is_ok());
    assert!(writer
        .write_event(Event::Start(BytesStart::borrowed_name(b"components")))
        .is_ok());
    for p in purls {
        let purl = PackageUrl::from_str(&p).unwrap();
        let mut component = BytesStart::borrowed_name(b"component");
        component.push_attribute(("type", "library"));
        component.push_attribute(("bom-ref", &p[..]));
        assert!(writer.write_event(Event::Start(component)).is_ok());

        // Name tag
        assert!(writer
            .write_event(Event::Start(BytesStart::borrowed_name(b"name")))
            .is_ok());
        let name_value = BytesText::from_plain_str(&purl.name);
        assert!(writer.write_event(Event::Text(name_value)).is_ok());
        assert!(writer
            .write_event(Event::End(BytesEnd::borrowed(b"name")))
            .is_ok());

        // Version tag
        assert!(writer
            .write_event(Event::Start(BytesStart::borrowed_name(b"version")))
            .is_ok());
        let vers = &purl.version.unwrap();
        let version_value = BytesText::from_plain_str(vers);
        assert!(writer.write_event(Event::Text(version_value)).is_ok());
        assert!(writer
            .write_event(Event::End(BytesEnd::borrowed(b"version")))
            .is_ok());

        // Purl tag
        assert!(writer
            .write_event(Event::Start(BytesStart::borrowed_name(b"purl")))
            .is_ok());
        let version_value = BytesText::from_plain_str(&p[..]);
        assert!(writer.write_event(Event::Text(version_value)).is_ok());
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

    #[test]
    fn can_generate_sbom_from_purls_test() {
        let cyclonedx = CycloneDXGenerator {};

        let mut purls: Vec<String> = Vec::new();

        purls.push("pkg:cargo/test@1.0.0".to_string());
        purls.push("pkg:cargo/test@1.0.1".to_string());
        purls.push("pkg:cargo/test@1.0.2".to_string());

        let sbom = cyclonedx.generate_sbom_from_purls(purls);

        let expected = "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.3\" version=\"1\"><components><component type=\"library\" bom-ref=\"pkg:cargo/test@1.0.0\"><name>test</name><version>1.0.0</version><purl>pkg:cargo/test@1.0.0</purl></component><component type=\"library\" bom-ref=\"pkg:cargo/test@1.0.1\"><name>test</name><version>1.0.1</version><purl>pkg:cargo/test@1.0.1</purl></component><component type=\"library\" bom-ref=\"pkg:cargo/test@1.0.2\"><name>test</name><version>1.0.2</version><purl>pkg:cargo/test@1.0.2</purl></component></components></bom>";

        assert_eq!(sbom, expected);
    }
}