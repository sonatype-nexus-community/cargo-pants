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
        #[structopt(short, long, parse(from_occurrences = parse_log_level))]
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

fn parse_log_level(verbosity: u64) -> LevelFilter {
    match verbosity {
        1 => return LevelFilter::Warn,
        2 => return LevelFilter::Info,
        3 => return LevelFilter::Debug,
        4 => return LevelFilter::Trace,
        _ => return LevelFilter::Error,
    }
}
