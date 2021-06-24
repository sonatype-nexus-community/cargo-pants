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
use crate::{error::Error, package::Package};
use std::{fs::File, io::Read, path::Path};
use toml;

// Parsed Cargo.lock file containing dependencies
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Lockfile {
    // Dependencies enumerated in the lockfile
    #[serde(rename = "package")]
    pub packages: Vec<Package>,
}

impl Lockfile {
    // Load lock data from a `Cargo.lock` file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let lockfile = path.as_ref().to_string_lossy().to_string();
        let mut file =
            File::open(path.as_ref()).map_err(|e| Error::from_file_open(&lockfile, e))?;
        let mut toml = String::new();
        file.read_to_string(&mut toml)?;
        Self::from_toml(&lockfile, &toml)
    }

    // Parse the TOML data from the `Cargo.lock` file
    pub fn from_toml(lockfile: &str, toml_string: &str) -> Result<Self, Error> {
        toml::from_str(toml_string).map_err(|e| Error::from_cargo_toml(lockfile, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_cargo_lockfile() {
        let lockfile =
            Lockfile::load("Cargo.lock").expect("failed to load project's Cargo.lock file");
        assert!(lockfile.packages.len() > 0);
    }

    #[test]
    fn load_cargo_lockfile_nonexistant() {
        let error = Lockfile::load("nosuchfile.notexist").expect_err("Test should have failed");
        assert_eq!(
            &format!("{}", error),
            r#"couldn't open the Cargo.lock file: "nosuchfile.notexist""#
        );
    }

    #[test]
    fn load_cargo_lockfile_invalid() {
        let error = Lockfile::load("README.md").expect_err("Test should have failed");
        assert_eq!(
            &format!("{}", error),
            r#"couldn't parse the Cargo.lock file: "README.md""#
        );
    }
}
