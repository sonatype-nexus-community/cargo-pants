// Copyright 2021 Sonatype and Glenn Mohre.
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

use dirs::home_dir;
use std::fs::OpenOptions;
use std::sync::Mutex;
use tracing_subscriber::filter::EnvFilter;

pub static CARGO_DEFAULT_TOMLFILE: &str = "Cargo.toml";

pub fn banner(name: String, version: String) {
    println!("{}", std::include_str!("banner.txt"));
    println!("{} version: {}", name, version);
}

pub fn print_dev_dependencies_info(dev: bool) {
    if dev {
        println!("Scanning all dependencies for project due to use of --dev");
    } else {
        println!("Scanning only runtime dependencies for project (use --dev to include all dependencies)");
    }
    println!();
}

pub fn parse_log_level(verbosity: u64) -> EnvFilter {
    match verbosity {
        0 => env_filter_at_level("error"),
        1 => env_filter_at_level("warn"),
        2 => env_filter_at_level("info"),
        3 => env_filter_at_level("debug"),
        4 => env_filter_at_level("trace"),
        _ => EnvFilter::from_default_env(),
    }
}

fn env_filter_at_level(level: &str) -> EnvFilter {
    EnvFilter::default()
        .add_directive(
            format!("cargo_pants={}", level)
                .parse()
                .expect("Failed to parse level directive"),
        )
        .add_directive(
            format!("cargo_iq={}", level)
                .parse()
                .expect("Failed to parse level directive"),
        )
}

pub fn construct_logger(folder: &str, log_level_filter: EnvFilter) {
    let home = home_dir().unwrap();

    let log_folder = home.join(folder);
    std::fs::create_dir_all(&log_folder).expect("Could not create the log folder");

    let log_location = log_folder.join("cargo-pants.combined.log");

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_location)
        .expect("Failed to open log file for writing");

    tracing_subscriber::fmt()
        .with_env_filter(log_level_filter)
        .json()
        .with_writer(Mutex::new(log_file))
        .init();

    println!();
    println!("Logging to: {:?}", log_location.clone());
    println!();
}
