// Copyright 2020 Sonatype and Glenn Mohre.
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
use clap::Arg;

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
