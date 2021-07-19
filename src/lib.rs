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
#![allow(dead_code)]

extern crate serde;
extern crate url;

#[macro_use]
extern crate serde_derive;
extern crate env_logger;
extern crate log;
extern crate serde_json;

pub mod client;
pub mod coordinate;
pub mod cyclonedx;
pub mod error;
pub mod iq;
pub mod lockfile;
pub mod package;
pub mod vulnerability;

pub use crate::{
    client::*, coordinate::*, cyclonedx::CycloneDXGenerator, error::*, iq::IQClient, lockfile::*,
    package::*, vulnerability::*,
};

// Global Singletons are bad kids. Don't use them (unless you need the terminal width everywhere).
const DEFAULT_TERM_SIZE: termsize::Size = termsize::Size { cols: 80, rows: 40 };
use lazy_static::lazy_static;
lazy_static! {
    pub static ref TERM_WIDTH: u16 = calculate_term_width();
}

fn calculate_term_width() -> u16 {
    match termsize::get() {
        Some(val) => {
            return val.cols;
        }
        None => {
            return DEFAULT_TERM_SIZE.cols;
        }
    }
}
