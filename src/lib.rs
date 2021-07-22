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
extern crate log;
extern crate serde_json;

use terminal_size::{terminal_size, Height, Width};

pub mod client;
pub mod common;
pub mod coordinate;
pub mod cyclonedx;
pub mod error;
pub mod iq;
pub mod package;
pub mod parse;
pub mod vulnerability;

pub use crate::{
    client::*, common::*, coordinate::*, cyclonedx::CycloneDXGenerator, error::*, iq::IQClient,
    package::*, parse::*, vulnerability::*,
};

pub fn calculate_term_width() -> u16 {
    match terminal_size() {
        Some((Width(w), Height(_h))) => {
            return w;
        }
        None => {
            return 80;
        }
    }
}
