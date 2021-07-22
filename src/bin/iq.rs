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

use cargo_pants::iq::Component;
use cargo_pants::iq::OpenPolicyViolations;
use cargo_pants::iq::PolicyReportResult;
use cargo_pants::iq::Violation;
use cargo_pants::package::Package;
use cargo_pants::CycloneDXGenerator;
use cargo_pants::IQClient;
use cargo_pants::ParseCargoToml;
use cargo_pants::ParseToml;
use clap::ArgMatches;
use clap::{App, Arg, SubCommand};
use cli_table::TableStruct;
use cli_table::{format::Border, format::Justify, print_stdout, Cell, Style, Table};
use console::StyledObject;
use console::{style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, trace};
use std::{env, process};

#[path = "../common.rs"]
mod common;

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍 ", "");
static SPARKIES: Emoji<'_, '_> = Emoji("✨ ", "");
static CROSS_MARK: Emoji<'_, '_> = Emoji("❌ ", "");
static CRAB: Emoji<'_, '_> = Emoji("🦀 ", "");
static SHIP: Emoji<'_, '_> = Emoji("🚢 ", "");
static CONSTRUCTION: Emoji<'_, '_> = Emoji("🚧 ", "");

fn main() {
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
    .arg(common::get_verbose_arg().clone())
    .arg(common::get_lockfile_arg().clone())
    .arg(common::get_dev_arg().clone())
    )
    .get_matches();

    match matches.subcommand() {
        ("iq", Some(sub_m)) => {
            let log_level = common::get_log_level_filter(sub_m);

            common::banner(crate_name!().to_string(), crate_version!().to_string());

            common::construct_logger(true, log_level);

            handle_iq_sub_command(sub_m);
        }
        _ => common::print_no_command_found("iq".to_string()),
    }
}

fn handle_iq_sub_command(iq_sub_command: &ArgMatches) {
    let dev: bool = iq_sub_command.is_present("dev");
    common::print_dev_dependencies_info(dev);

    let spinner_style = ProgressStyle::default_spinner().template("{prefix:.bold.dim} {wide_msg}");
    let package_bar = ProgressBar::new_spinner();
    package_bar.set_style(spinner_style.clone());
    package_bar.set_message(format!("{}{}", LOOKING_GLASS, "Getting package list"));

    let toml_file_path = iq_sub_command.value_of("tomlfile").unwrap();

    let mut parser = ParseCargoToml::new(toml_file_path.to_string(), dev);
    match parser.get_packages() {
        Ok(packages) => {
            package_bar.finish_with_message(format!(
                "{}{}",
                CRAB,
                format!("Obtained package list ({})", packages.len())
            ));

            let sbom_bar = ProgressBar::new_spinner();
            sbom_bar.set_style(spinner_style.clone());

            sbom_bar.set_message(format!(
                "{}{}",
                SPARKIES, "Generating SBOM representation of project"
            ));
            let sbom = handle_packages(packages);
            trace!("{}", sbom);
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
                    trace!("Response recieved: {:#?}", res.url_results);

                    if res.url_results.is_error {
                        panic!("{}", res.url_results.error_message.unwrap());
                    }

                    iq_bar.finish_with_message(format!("{}{}", CRAB, "Nexus IQ Results obtained"));
                    println!("");

                    let table = generate_summary_table(res.url_results.open_policy_violations);

                    match res.url_results.policy_action.as_ref() {
                        "Failure" => {
                            print_iq_policy_violations(res.policy_report_results, &parser);
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
                            print_iq_policy_violations(res.policy_report_results, &parser);
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
                    error!("{}", e);

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
    let sbom_generator = CycloneDXGenerator {};

    return sbom_generator.generate_sbom_from_purls(packages);
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

fn print_iq_policy_violations(res: PolicyReportResult, parser: &impl ParseToml) -> () {
    let policy_violations: Vec<Component> = res
        .components
        .clone()
        .into_iter()
        .filter(|p| {
            if p.violations
                .as_ref()
                .unwrap_or(&(vec![] as Vec<Violation>))
                .is_empty()
            {
                return false;
            } else {
                return true;
            }
        })
        .collect();

    if policy_violations.len() > 0 {
        println!(
            "Components ({}) with policy violations found",
            policy_violations.len()
        );
        println!("");

        for comp in policy_violations {
            println!("Package URL: {}", comp.package_url);
            match comp.violations {
                Some(violations) => {
                    println!(
                        "\tKnown violations: {}",
                        violations
                            .into_iter()
                            .map(|v| v.policy_name as String)
                            .collect::<Vec<String>>()
                            .join(",")
                    );
                    println!("\tInverse Dependency graph");
                    assert!(parser.print_the_graph(comp.package_url).is_ok());
                    println!("");
                }
                None => {}
            }
        }

        println!();
    }
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
