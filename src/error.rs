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
//! Error types used by this crate

#[cfg(feature = "chrono")]
use chrono;
use std::str::Utf8Error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad parameter")]
    BadParam,

    /// An error occurred performing an I/O operation (e.g. network, file)
    #[error("I/O operation failed")]
    Io(#[from] std::io::Error),

    /// Couldn't parse response data
    #[error("couldn't parse data as UTF-8")]
    ParseUtf8(Utf8Error),

    #[cfg(feature = "chrono")]
    /// Couldn't parse response data
    #[error("couldn't parse data")]
    ParseChrono(#[from] chrono::ParseError),

    /// A Cargo Metadata error occurred
    #[error("couldn't get cargo metadata")]
    CargoMetadataError(#[from] cargo_metadata::Error),

    #[error(r#"couldn't open the Cargo.lock file: "{lock_file}""#)]
    LockFileOpen {
        lock_file: String,
        open_error: std::io::Error,
    },

    /// Error processing the Cargo.toml file
    #[error(r#"couldn't parse the Cargo.toml file: "{lock_file}""#)]
    ParseCargoLockToml { lock_file: String },
}

impl Error {
    pub fn from_file_open(lock_file: &str, open_error: std::io::Error) -> Self {
        Self::LockFileOpen {
            lock_file: lock_file.to_owned(),
            open_error,
        }
    }

    pub fn from_cargo_toml(lock_file: &str) -> Self {
        Self::ParseCargoLockToml {
            lock_file: lock_file.to_owned(),
        }
    }
}
