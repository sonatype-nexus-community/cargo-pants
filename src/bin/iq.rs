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
#[macro_use]
extern crate clap;

use cargo_metadata::{CargoOpt, MetadataCommand};
use cargo_pants::iq::OpenPolicyViolations;
use cargo_pants::package::Package;
use cargo_pants::CycloneDXGenerator;
use cargo_pants::Error;
use cargo_pants::IQClient;
use clap::ArgMatches;
use clap::{App, Arg, SubCommand};
use cli_table::TableStruct;
use cli_table::{format::Border, format::Justify, print_stdout, Cell, Style, Table};
use console::StyledObject;
use console::{style, Emoji};
use dirs::home_dir;
use indicatif::{ProgressBar, ProgressStyle};
use log::LevelFilter;
use log::{debug, trace};
use log4rs::append::file::FileAppender;
use log4rs::config::Appender;
use log4rs::config::Logger;
use log4rs::config::Root;
use log4rs::encode::json::JsonEncoder;
use log4rs::Config;
use std::{env, process};

const CARGO_DEFAULT_TOML: &str = "Cargo.toml";

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍 ", "");
static SPARKIES: Emoji<'_, '_> = Emoji("✨ ", "");
static CROSS_MARK: Emoji<'_, '_> = Emoji("❌ ", "");
static CRAB: Emoji<'_, '_> = Emoji("🦀 ", "");
static SHIP: Emoji<'_, '_> = Emoji("🚢 ", "");
static CONSTRUCTION: Emoji<'_, '_> = Emoji("🚧 ", "");

macro_rules! ternary {
    ($c:expr, $v:expr, $v1:expr) => {
        if $c {
            $v
        } else {
            $v1
        }
    };
}

fn main() {
    let lockfile_arg = Arg::with_name("tomlfile")
        .long("tomlfile")
        .takes_value(true)
        .help("The path to your Cargo.toml file")
        .default_value(CARGO_DEFAULT_TOML);

    let logger_arg = Arg::with_name("verbose")
    .short("v")
    .takes_value(false)
    .multiple(true)
    .help("Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v");

    let matches = App::new("Cargo Pants")
    .version(crate_version!())
    .bin_name("cargo")
    .author("Glenn Mohre <glennmohre@gmail.com>")
    .about("A library for auditing your cargo dependencies for vulnerabilities and checking your pants")
    .subcommand(SubCommand::with_name("iq")
      .arg(Arg::with_name("iq-server-url")
        .short("x")
        .long("iq-server-url")
        .takes_value(true)
        .help("Specify Nexus IQ server url for request")
        .default_value("http://localhost:8070"))
      .arg(Arg::with_name("iq-application")
        .short("a")
        .long("iq-application")
        .required(true)
        .takes_value(true)
        .help("Specify Nexus IQ public application ID for request"))
      .arg(Arg::with_name("iq-username")
        .short("l")
        .long("iq-username")
        .takes_value(true)
        .default_value("admin")
        .help("Specify Nexus IQ username for request"))
      .arg(Arg::with_name("iq-token")
        .short("k")
        .long("iq-token")
        .takes_value(true)
        .default_value("admin123")
        .help("Specify Nexus IQ token for request"))
      .arg(Arg::with_name("iq-stage")
        .short("s")
        .long("iq-stage")
        .takes_value(true)
        .default_value("develop")
        .help("Specify Nexus IQ stage for request"))
      .arg(Arg::with_name("iq-attempts")
        .short("t")
        .long("iq-attempts")
        .takes_value(true)
        .default_value("60")
        .help("Specify Nexus IQ attempts in seconds"))
      .arg(logger_arg.clone())
      .arg(lockfile_arg.clone())
    )
    .get_matches();

    match matches.subcommand() {
        ("iq", Some(sub_m)) => {
            let log_level = get_log_level_filter(sub_m);

            banner();

            construct_logger(true, log_level);

            handle_iq_sub_command(sub_m);
        }
        _ => print_no_command_found(),
    }
}

fn handle_iq_sub_command(iq_sub_command: &ArgMatches) {
    let spinner_style = ProgressStyle::default_spinner().template("{prefix:.bold.dim} {wide_msg}");
    let package_bar = ProgressBar::new_spinner();
    package_bar.set_style(spinner_style.clone());
    package_bar.set_message(format!("{}{}", LOOKING_GLASS, "Getting package list"));

    let toml_file_path = iq_sub_command.value_of("tomlfile").unwrap();
    match get_packages(toml_file_path.to_string()) {
        Ok(packages) => {
            package_bar.finish_with_message(format!("{}{}", CRAB, "Obtained package list"));

            let sbom_bar = ProgressBar::new_spinner();
            sbom_bar.set_style(spinner_style.clone());

            sbom_bar.set_message(format!(
                "{}{}",
                SPARKIES, "Generating SBOM representation of project"
            ));
            let sbom = handle_packages(packages);
            sbom_bar.finish_with_message(format!("{}{}", CRAB, "SBOM generated"));

            let iq_bar = ProgressBar::new_spinner();
            iq_bar.set_style(spinner_style.clone());
            iq_bar.set_message(format!(
                "{}{}",
                SPARKIES, "Sending SBOM to Nexus IQ Server for evaluation"
            ));
            let iq = obtain_iq_client(iq_sub_command);
            match iq.audit_with_iq_server(sbom) {
                Ok(res) => {
                    iq_bar.finish_with_message(format!("{}{}", CRAB, "Nexus IQ Results obtained"));
                    println!("");

                    let table = generate_summary_table(res.url_results.open_policy_violations);

                    match res.url_results.policy_action.as_ref() {
                        "Failure" => {
                            print_iq_summary(
                                CRAB,
                                style("Aw Crabs! Policy violations exist in your scan.")
                                    .red()
                                    .bold(),
                                table,
                                iq.server.clone(),
                                res.url_results.report_html_url,
                            );

                            process::exit(1);
                        }
                        "Warning" => {
                            print_iq_summary(
                                CONSTRUCTION,
                                style("Barnacles! Warnings have been detected in your scan.")
                                    .yellow()
                                    .bold(),
                                table,
                                iq.server.clone(),
                                res.url_results.report_html_url,
                            );
                        }
                        "None" => {
                            print_iq_summary(
                                SHIP,
                                style("Smooth sailing! No policy issues found in your scan.")
                                    .green()
                                    .bold(),
                                table,
                                iq.server.clone(),
                                res.url_results.report_html_url,
                            );
                        }
                        _ => {
                            println!(
              "{}", "The response from Nexus IQ Server did not include a policy action, which is odd"
              );

                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    iq_bar.finish_with_message(format!(
                        "{}{}",
                        CROSS_MARK, "Error generating Nexus IQ Server results"
                    ));
                    println!("{}", e);

                    process::exit(1);
                }
            }
        }
        Err(e) => {
            package_bar
                .finish_with_message(format!("{}{}", CROSS_MARK, "Unable to obtain package list"));
            println!("{}", e);

            process::exit(1);
        }
    }
}

fn handle_packages(packages: Vec<Package>) -> String {
    let purls: Vec<String> = packages.iter().map(|pkg| pkg.as_purl()).collect();
    let sbom_generator = CycloneDXGenerator {};

    return sbom_generator.generate_sbom_from_purls(purls);
}

fn obtain_iq_client(iq_sub_command: &ArgMatches) -> IQClient {
    let server = String::from(iq_sub_command.value_of("iq-server-url").unwrap());
    let user = String::from(iq_sub_command.value_of("iq-username").unwrap());
    let token = String::from(iq_sub_command.value_of("iq-token").unwrap());
    let stage = String::from(iq_sub_command.value_of("iq-stage").unwrap());
    let application = String::from(iq_sub_command.value_of("iq-application").unwrap());
    let attempts: u32 = String::from(iq_sub_command.value_of("iq-attempts").unwrap())
        .parse()
        .unwrap();

    return IQClient::new(server.clone(), user, token, stage, application, attempts);
}

fn get_log_level_filter(matches: &ArgMatches) -> LevelFilter {
    match matches.occurrences_of("verbose") {
        1 => return LevelFilter::Warn,
        2 => return LevelFilter::Info,
        3 => return LevelFilter::Debug,
        4 => return LevelFilter::Trace,
        _ => return LevelFilter::Error,
    };
}

fn construct_logger(iq: bool, log_level_filter: LevelFilter) {
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

fn print_iq_summary(
    emoji: Emoji,
    summary_line: StyledObject<&str>,
    table: TableStruct,
    server: String,
    html_url: String,
) {
    println!("{}{}", emoji, summary_line);
    println!("");
    assert!(print_stdout(table).is_ok());
    println!("");
    println!("{}{}/{}", style("Report URL: ").dim(), server, html_url);
}

fn generate_summary_table(policy_violations: OpenPolicyViolations) -> TableStruct {
    debug!(
        "Generating summary table with policy violations {:?}",
        policy_violations
    );

    return vec![
        vec![
            style("Critical").red().bold().cell(),
            policy_violations.critical.cell().justify(Justify::Right),
        ],
        vec![
            style("Severe").yellow().bold().cell(),
            policy_violations.severe.cell().justify(Justify::Right),
        ],
        vec![
            style("Moderate").cyan().bold().cell(),
            policy_violations.moderate.cell().justify(Justify::Right),
        ],
    ]
    .table()
    .border(Border::builder().build())
    .title(vec![
        "Policy Violation Type".cell().bold(true),
        "Total".cell().bold(true),
    ])
    .bold(true);
}

fn print_no_command_found() {
    println!("Error, this tool is designed to be executed from cargo itself.");
    println!("Therefore at least the command line parameter 'pants' must be provided.");
}

fn get_packages(toml_file_path: String) -> Result<Vec<Package>, Error> {
    debug!("Attempting to get package list from {}", toml_file_path);

    let metadata = MetadataCommand::new()
        .manifest_path(toml_file_path)
        .features(CargoOpt::AllFeatures)
        .exec()?;

    let packages: Vec<Package> = metadata
        .packages
        .into_iter()
        .map(|p: cargo_metadata::Package| Package {
            name: p.name,
            version: p.version,
        })
        .collect();

    trace!("Obtained packages {:#?}", packages);
    return Ok(packages);
}

fn banner() {
    println!("{}", std::include_str!("../banner.txt"));
    println!("{} version: {}", crate_name!(), crate_version!());
}
