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

use clap::{Arg, ArgMatches};
use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::Appender;
use log4rs::config::Logger;
use log4rs::config::Root;
use log4rs::encode::json::JsonEncoder;
use log4rs::Config;
use dirs::home_dir;

macro_rules! ternary {
    ($c:expr, $v:expr, $v1:expr) => {
        if $c {
            $v
        } else {
            $v1
        }
    };
}

static CARGO_DEFAULT_TOMLFILE: &str = "Cargo.toml";

pub fn get_lockfile_arg() -> Arg<'static, 'static> {
    return Arg::with_name("tomlfile")
        .long("tomlfile")
        .takes_value(true)
        .help("The path to your Cargo.toml file")
        .default_value(CARGO_DEFAULT_TOMLFILE);
}

pub fn get_dev_arg() -> Arg<'static, 'static> {
    return Arg::with_name("dev")
        .long("dev")
        .help("A flag to include dev dependencies");
}

pub fn get_verbose_arg() -> Arg<'static, 'static> {
    return Arg::with_name("verbose")
  .short("v")
  .takes_value(false)
  .multiple(true)
  .help("Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v");
}

pub fn banner() {
    println!("{}", std::include_str!("banner.txt"));
    println!("{} version: {}", crate_name!(), crate_version!());
}

pub fn print_no_command_found() {
    println!("Error, this tool is designed to be executed from cargo itself.");
    println!("Therefore at least the command line parameter 'pants' must be provided.");
}

pub fn print_dev_dependencies_info(dev: bool) {
    if dev {
        println!("Scanning all dependencies for project due to use of --dev");
    } else {
        println!("Scanning only runtime dependencies for project (use --dev to include all dependencies)");
    }
    println!("");
}


pub fn get_log_level_filter(matches: &ArgMatches) -> LevelFilter {
    match matches.occurrences_of("verbose") {
        1 => return LevelFilter::Warn,
        2 => return LevelFilter::Info,
        3 => return LevelFilter::Debug,
        4 => return LevelFilter::Trace,
        _ => return LevelFilter::Error,
    };
}

pub fn construct_logger(iq: bool, log_level_filter: LevelFilter) {
    let home = home_dir().unwrap();

    let log_location_base_dir = ternary!(iq, home.join(".iqserver"), home.join(".ossindex"));
    let full_log_location = log_location_base_dir.join("cargo-pants.combined.log");

    let file = FileAppender::builder()
        .encoder(Box::new(JsonEncoder::new()))
        .build(full_log_location.clone())
        .unwrap();

    let config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(file)))
        .logger(
            Logger::builder()
                .appender("file")
                .additive(true)
                .build("app::file", log_level_filter),
        )
        .build(Root::builder().appender("file").build(log_level_filter))
        .unwrap();

    let _handle = log4rs::init_config(config).unwrap();

    println!("");
    println!("Log Level set to: {}", log_level_filter);
    println!("Logging to: {:?}", full_log_location.clone());
    println!("");
}
