// Copyright 2019 Glenn Mohre, Sonatype.
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

use cargo_pants::iq::Component;
use cargo_pants::iq::OpenPolicyViolations;
use cargo_pants::iq::PolicyReportResult;
use cargo_pants::package::Package;
use cargo_pants::CycloneDXGenerator;
use cargo_pants::IQClient;
use cargo_pants::ParseCargoToml;
use cargo_pants::ParseToml;
use console::StyledObject;
use console::{style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};
use std::{env, process};
use structopt::StructOpt;
use term_table::row::Row;
use term_table::table_cell::TableCell;
use tracing::{debug, error, trace};

#[path = "../../common.rs"]
mod common;

mod cli;

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍 ", "");
static SPARKIES: Emoji<'_, '_> = Emoji("✨ ", "");
static CROSS_MARK: Emoji<'_, '_> = Emoji("❌ ", "");
static CRAB: Emoji<'_, '_> = Emoji("🦀 ", "");
static SHIP: Emoji<'_, '_> = Emoji("🚢 ", "");
static CONSTRUCTION: Emoji<'_, '_> = Emoji("🚧 ", "");

fn main() {
    let opt = cli::Opt::from_args();

    match opt {
        cli::Opt::Iq {
            toml_file,
            server_url,
            application,
            username,
            token,
            stage,
            attempts,
            log_level,
            include_dev_dependencies,
        } => {
            common::banner(
                env!("CARGO_BIN_NAME").to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            );
            common::construct_logger(".iqserver", log_level);
            common::print_dev_dependencies_info(include_dev_dependencies);

            let spinner_style =
                ProgressStyle::default_spinner().template("{prefix:.bold.dim} {wide_msg}");
            let package_bar = ProgressBar::new_spinner();
            package_bar.set_style(spinner_style.clone());
            package_bar.set_message(format!("{}{}", LOOKING_GLASS, "Getting package list"));

            let mut parser = ParseCargoToml::new(
                toml_file.to_string_lossy().to_string(),
                include_dev_dependencies,
            );
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
                    let iq =
                        IQClient::new(server_url, username, token, stage, application, attempts);
                    match iq.audit_with_iq_server(sbom) {
                        Ok(res) => {
                            trace!("Response received: {:#?}", res.url_results);

                            if res.url_results.is_error {
                                panic!("{}", res.url_results.error_message.unwrap());
                            }

                            iq_bar.finish_with_message(format!(
                                "{}{}",
                                CRAB, "Nexus IQ Results obtained"
                            ));
                            println!();

                            match res.url_results.policy_action.as_ref() {
                                "Failure" => {
                                    print_iq_policy_violations(res.policy_report_results, &parser);
                                    print_iq_summary(
                                        CRAB,
                                        style("Aw Crabs! Policy violations exist in your scan.")
                                            .red()
                                            .bold(),
                                        res.url_results.open_policy_violations,
                                        iq.server.clone(),
                                        res.url_results.report_html_url,
                                    );

                                    process::exit(1);
                                }
                                "Warning" => {
                                    print_iq_policy_violations(res.policy_report_results, &parser);
                                    print_iq_summary(
                                        CONSTRUCTION,
                                        style(
                                            "Barnacles! Warnings have been detected in your scan.",
                                        )
                                        .yellow()
                                        .bold(),
                                        res.url_results.open_policy_violations,
                                        iq.server.clone(),
                                        res.url_results.report_html_url,
                                    );
                                }
                                "None" => {
                                    print_iq_summary(
                                        SHIP,
                                        style(
                                            "Smooth sailing! No policy issues found in your scan.",
                                        )
                                        .green()
                                        .bold(),
                                        res.url_results.open_policy_violations,
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
                    package_bar.finish_with_message(format!(
                        "{}{}",
                        CROSS_MARK, "Unable to obtain package list"
                    ));
                    println!("{}", e);

                    process::exit(1);
                }
            }
        }
    }
}

fn handle_packages(packages: Vec<Package>) -> String {
    let sbom_generator = CycloneDXGenerator {};

    return sbom_generator.generate_sbom_from_purls(packages);
}

fn print_iq_policy_violations(res: PolicyReportResult, parser: &impl ParseToml) -> () {
    let policy_violations: Vec<Component> = res
        .components
        .clone()
        .into_iter()
        .filter(|p| p.violations.as_ref().map_or(false, |v| !v.is_empty()))
        .collect();

    if policy_violations.len() > 0 {
        println!(
            "Components ({}) with policy violations found",
            policy_violations.len()
        );
        println!();

        for comp in policy_violations {
            println!("Package URL: {}", comp.package_url);
            match comp.violations {
                Some(violations) => {
                    println!(
                        "Known violations: {}",
                        violations
                            .into_iter()
                            .map(|v| policy_violation_to_styled_object(v.policy_name).to_string())
                            .collect::<Vec<String>>()
                            .join(",")
                    );
                    println!("Inverse Dependency graph");
                    let clean_purl = remove_url_parameter_suffix(&comp.package_url);
                    assert!(parser.print_the_graph(clean_purl.to_string()).is_ok());
                    println!();
                }
                None => {}
            }
        }

        println!();
    }
}

fn remove_url_parameter_suffix(s: &str) -> &str {
    if s.contains("?") {
        let param_location = s.find("?").unwrap_or(s.len());

        let clean_url = &s[..param_location];
        return clean_url;
    }
    return s;
}

fn policy_violation_to_styled_object(violation: String) -> StyledObject<String> {
    // TODO: Implement the rest of the violation types to colors?
    match violation.as_ref() {
        "Security-Critical" => style(violation).red().bold(),
        "Security-Medium" => style(violation).yellow().bold(),
        &_ => style(violation).dim(),
    }
}

fn print_iq_summary(
    emoji: Emoji,
    summary_line: StyledObject<&str>,
    policy_violations: OpenPolicyViolations,
    server: String,
    html_url: String,
) {
    println!("{}{}", emoji, summary_line);
    println!();
    generate_summary_table(policy_violations);
    println!();
    println!("{}{}/{}", style("Report URL: ").dim(), server, html_url);
}

fn generate_summary_table(policy_violations: OpenPolicyViolations) -> () {
    debug!(
        "Generating summary table with policy violations {:?}",
        policy_violations
    );

    let mut table = term_table::Table::new();

    if cfg!(windows) {
        table.style = term_table::TableStyle::simple();
    } else {
        table.style = term_table::TableStyle::rounded();
    }

    table.add_row(Row::new(vec![
        TableCell::new(style("Policy Violation Type").bold()),
        TableCell::new(style("Total").bold()),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new(style("Critical").red().bold()),
        TableCell::new_with_alignment(
            policy_violations.critical,
            1,
            term_table::table_cell::Alignment::Right,
        ),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new(style("Severe").yellow().bold()),
        TableCell::new_with_alignment(
            policy_violations.severe,
            1,
            term_table::table_cell::Alignment::Right,
        ),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new(style("Moderate").cyan().bold()),
        TableCell::new_with_alignment(
            policy_violations.moderate,
            1,
            term_table::table_cell::Alignment::Right,
        ),
    ]));

    println!("{}", table.render());
}

#[cfg(test)]
mod tests {
    use crate::{print_iq_policy_violations, remove_url_parameter_suffix};
    use cargo_pants::iq::{Component, PolicyReportResult, Violation};
    use cargo_pants::{ParseCargoToml, ParseToml};

    #[test]
    fn remove_url_param_suffix_variants() {
        assert_eq!(
            "package-name",
            remove_url_parameter_suffix("package-name?type=crate")
        );
        assert_eq!("hello", remove_url_parameter_suffix("hello"));
        assert_eq!("", remove_url_parameter_suffix(""));
        assert_eq!("", remove_url_parameter_suffix("?"));
    }

    #[test]
    fn handle_iq_purl_suffix() {
        // find pure purl to use for test
        let mut parser = ParseCargoToml::default(); // @todo Why does this not work under debug mode?
        let packages = match parser.get_packages() {
            Ok(packages) => packages,
            Err(e) => {
                println!("{}", e);
                println!("toml file: {}", parser.toml_file_path);
                assert!(false, "did you perhaps run 'ParseCargoToml' under debug mode? maybe try running full speed? error: {}", e);
                return ();
            }
        };

        let mut test_package_url = "".to_string();
        let test_package_name = "openssl-sys"; // real package
        for package in packages {
            if package.name.to_string().eq(test_package_name) {
                test_package_url.push_str(
                    &("pkg:cargo/".to_string()
                        + &package.name.to_string()
                        + "@"
                        + &package.version.to_string()),
                );
                break;
            }
        }
        assert_ne!("".to_string(), test_package_url);

        // fake IQ result containing test package with purl suffix
        let violation = Violation {
            policy_id: "".to_string(),
            policy_name: "".to_string(),
            policy_threat_category: "".to_string(),
            policy_threat_level: 0,
            policy_violation_id: "".to_string(),
            waived: false,
            grandfathered: false,
            constraints: vec![],
        };
        let iq_purl_suffix = "?type=crate";
        let component_from_iq = Component {
            hash: "".to_string(),
            match_state: "".to_string(),
            component_identifier: Default::default(),
            package_url: (test_package_url + iq_purl_suffix).to_string(),
            proprietary: false,
            pathnames: vec![],
            dependency_data: None,
            violations: Option::from(vec![violation]),
            display_name: None,
        };
        let iq_result = PolicyReportResult {
            report_time: 0,
            report_title: "".to_string(),
            commit_hash: None,
            initiator: "".to_string(),
            application: Default::default(),
            counts: Default::default(),
            components: vec![component_from_iq],
        };

        print_iq_policy_violations(iq_result, &parser)
    }
}
