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

use std::path::PathBuf;

use crate::common;
use log::LevelFilter;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Cargo Pants",
    author = "Glenn Mohre <glennmohre@gmail.com>",
    bin_name = "cargo" // required to make help documentation match running as a cargo subcommand
)]
pub enum Opt {
    #[structopt(
        about = "A library for auditing your cargo dependencies for vulnerabilities and checking your pants",
        author = "Glenn Mohre <glennmohre@gmail.com>"
    )]
    Pants {
        /// The path to your Cargo.toml file
        #[structopt(long = "tomlfile", default_value = common::CARGO_DEFAULT_TOMLFILE)]
        toml_file: PathBuf,

        /// Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v
        #[structopt(short = "v", long = "verbose", parse(from_occurrences = common::parse_log_level))]
        log_level: LevelFilter,

        /// A flag to include dev dependencies
        #[structopt(long = "dev")]
        include_dev_dependencies: bool,

        /// Also show non-vulnerable dependencies
        #[structopt(short = "d", long = "loud")]
        loud: bool,

        /// Disable color output
        #[structopt(short = "m", long = "no-color")]
        no_color: bool,

        /// Your pants style
        #[structopt(short = "s", long = "pants_style")]
        pants_style: Option<String>,

        /// OSS Index API Key
        #[structopt(long = "ossi-api-key", env, hide_env_values = true)]
        oss_index_api_key: Option<String>,
    },
}
