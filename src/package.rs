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

//! Crate metadata as parsed from `Cargo.lock`

use cargo_metadata::Version;
use std::fmt;

/// A Rust package (i.e. crate) as structured in `Cargo.lock`
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Package {
    /// Name of a crate
    pub name: String,

    /// Crate version (using `semver`)
    pub version: Version,

    pub license: Option<String>, // /// Source of the crate
    // #[serde(default)]
    // pub source: String,

    // /// Dependencies of this crate
    // #[serde(default)]
    // pub dependencies: Vec<String>
    pub package_id: cargo_metadata::PackageId,
}

impl Package {
    pub fn as_purl(&self) -> String {
        format!("pkg:cargo/{}@{}", self.name, self.version)
    }
}

impl fmt::Display for Package {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.name, self.version)
    }
}

/// Name of a crate
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
pub struct PackageName(pub String);

impl PackageName {
    /// Get string reference to this package name
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<PackageName> for PackageName {
    fn as_ref(&self) -> &PackageName {
        self
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> From<&'a str> for PackageName {
    fn from(string: &'a str) -> PackageName {
        PackageName(string.into())
    }
}

impl Into<String> for PackageName {
    fn into(self) -> String {
        self.0
    }
}
