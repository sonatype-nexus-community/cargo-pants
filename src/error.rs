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
use std::{
    fmt::{self, Display},
    io,
    str::Utf8Error,
};
use toml;

/// Error type
#[derive(Debug)]
pub struct Error {
    /// Contextual information about the error
    inner: ErrorKind,

    /// Description of the error providing additional information
    description: String,
}

impl Error {
    /// Create a new error with the given description
    pub fn new<S: ToString>(kind: ErrorKind, description: &S) -> Self {
        Self {
            inner: kind,
            description: description.to_string(),
        }
    }

    /// Obtain the inner `ErrorKind` for this error
    pub fn kind(&self) -> ErrorKind {
        self.inner
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", &self.inner, &self.description)
    }
}

/// Custom error type for this library
#[derive(Copy, Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ErrorKind {
    /// Invalid argument or parameter
    #[error("bad parameter")]
    BadParam,

    /// An error occurred performing an I/O operation (e.g. network, file)
    #[error("I/O operation failed")]
    Io,

    /// Couldn't parse response data
    #[error("couldn't parse data")]
    Parse,
}

/// Create a new error (of a given enum variant) with a formatted message
macro_rules! err {
    ($kind:path, $msg:expr) => {
        crate::error::Error::new(
            $kind,
            &$msg.to_string()
        )
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        err!($kind, &format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted message
#[allow(unused_macros)]
macro_rules! fail {
    ($kind:path, $msg:expr) => {
        return Err(err!($kind, $msg).into());
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        fail!($kind, &format!($fmt, $($arg)+));
    };
}

impl From<Utf8Error> for Error {
    fn from(other: Utf8Error) -> Self {
        err!(ErrorKind::Parse, &other)
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::ParseError> for Error {
    fn from(other: chrono::ParseError) -> Self {
        err!(ErrorKind::Parse, &other)
    }
}

impl From<fmt::Error> for Error {
    fn from(other: fmt::Error) -> Self {
        err!(ErrorKind::Io, &other)
    }
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self {
        err!(ErrorKind::Io, &other)
    }
}

impl From<toml::de::Error> for Error {
    fn from(other: toml::de::Error) -> Self {
        err!(ErrorKind::Parse, &other)
    }
}
