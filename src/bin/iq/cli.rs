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
    Iq {
        /// The path to your Cargo.toml file
        #[structopt(long = "tomlfile", default_value = common::CARGO_DEFAULT_TOMLFILE)]
        toml_file: PathBuf,

        /// Specify Nexus IQ server url for request
        #[structopt(
            short = "x",
            long = "iq-server-url",
            default_value = "http://localhost:8070"
        )]
        server_url: String,

        /// Specify Nexus IQ public application ID for request
        #[structopt(short = "a", long = "iq-application")]
        application: String,

        /// Specify Nexus IQ username for request
        #[structopt(short = "l", long = "iq-username", default_value = "admin")]
        username: String,

        /// Specify Nexus IQ token for request
        #[structopt(short = "k", long = "iq-token", default_value = "admin123", env)]
        token: String,

        /// Specify Nexus IQ stage for request
        #[structopt(short = "s", long = "iq-stage", default_value = "develop")]
        stage: String,

        /// Specify Nexus IQ attempts in seconds
        #[structopt(short = "t", long = "iq-attempts", default_value = "60")]
        attempts: u32,

        /// Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v
        #[structopt(short = "v", long = "verbose", parse(from_occurrences = common::parse_log_level))]
        log_level: LevelFilter,

        /// A flag to include dev dependencies
        #[structopt(long = "dev")]
        include_dev_dependencies: bool,
    },
}
