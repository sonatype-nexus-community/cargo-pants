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

use clap::ArgMatches;
use log4rs::encode::json::JsonEncoder;
use dirs::home_dir;
use log4rs::config::Root;
use log4rs::config::Logger;
use log4rs::config::Appender;
use log4rs::Config;
use log4rs::append::file::FileAppender;
use log::LevelFilter;
use log::{debug, error};
use cargo_pants::iq::OpenPolicyViolations;
use cli_table::TableStruct;
use console::StyledObject;
use cargo_pants::IQClient;
use cargo_pants::Error;
use cargo_pants::CycloneDXGenerator;
use cargo_pants::{
    client::OSSIndexClient, coordinate::Coordinate, lockfile::Lockfile, package::Package,
};
use clap::{App, Arg, SubCommand};
use std::io::{stdout, Write};
use std::{env, io, process};
use indicatif::{ProgressBar, ProgressStyle};
use console::{Emoji, style};
use cli_table::{format::Justify, format::Border, print_stdout, Cell, Style, Table};

const CARGO_DEFAULT_LOCKFILE: &str = "Cargo.lock";

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍 ", "");
static SPARKIES: Emoji<'_, '_> = Emoji("✨ ", "");
static CROSS_MARK: Emoji<'_, '_> = Emoji("❌ ", "");
static CRAB: Emoji<'_, '_> = Emoji("🦀 ", "");
static SHIP: Emoji<'_, '_> = Emoji("🚢 ", "");
static CONSTRUCTION: Emoji<'_, '_> = Emoji("🚧 ", "");

macro_rules! ternary {
  ($c:expr, $v:expr, $v1:expr) => {
      if $c {$v} else {$v1}
  };
}

fn main() {
  let lockfile_arg = Arg::with_name("lockfile")
    .long("lockfile")
    .takes_value(true)
    .help("The path to your Cargo.lock file")
    .default_value(CARGO_DEFAULT_LOCKFILE);

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
    .subcommand(SubCommand::with_name("pants")
      .arg(Arg::with_name("pants_style")
        .short("s")
        .long("pants_style")
        .takes_value(true)
        .help("Your pants style"))
      .arg(Arg::with_name("loud")
        .short("d")
        .long("loud")
        .takes_value(false)
        .help("Also show non-vulnerable dependencies"))
      .arg(Arg::with_name("no-color")
        .short("m")
        .long("no-color")
        .takes_value(false)
        .help("Disable color output"))
      .arg(logger_arg.clone())
      .arg(lockfile_arg.clone())
    )
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
    ("pants", Some(sub_m)) => {
      let log_level = get_log_level_filter(sub_m);

      construct_logger(false, log_level);

      if sub_m.is_present("pants_style") {
        let pants_style = String::from(sub_m.value_of("pants_style").unwrap());
        check_pants(pants_style);
      }

      let lockfile_path = sub_m.value_of("lockfile").unwrap();
      let verbose_output = sub_m.is_present("loud");
      let enable_color: bool = !sub_m.is_present("no-color");

      audit(lockfile_path.to_string(), verbose_output, enable_color);
    },
    ("iq", Some(sub_m)) => {
      let log_level = get_log_level_filter(sub_m);

      banner();

      construct_logger(true, log_level);

      let spinner_style = ProgressStyle::default_spinner()
        .template("{prefix:.bold.dim} {wide_msg}");
      let package_bar = ProgressBar::new_spinner();
      package_bar.set_style(spinner_style.clone());
      package_bar.set_message(format!("{}{}", LOOKING_GLASS, "Getting package list"));

      let lockfile_path = sub_m.value_of("lockfile").unwrap();
      match get_packages(lockfile_path.to_string()) {
        Ok(packages) => {
          package_bar.finish_with_message(format!("{}{}", CRAB, "Obtained package list"));

          let sbom_bar = ProgressBar::new_spinner();
          sbom_bar.set_style(spinner_style.clone());

          sbom_bar.set_message(format!("{}{}", SPARKIES, "Generating SBOM representation of project"));
          let purls: Vec<String> = packages.iter().map(|pkg| pkg.as_purl()).collect();
          let sbom_generator = CycloneDXGenerator{};
          let sbom = sbom_generator.generate_sbom_from_purls(purls);
          sbom_bar.finish_with_message(format!("{}{}", CRAB, "SBOM generated"));

          let server = String::from(sub_m.value_of("iq-server-url").unwrap());
          let user = String::from(sub_m.value_of("iq-username").unwrap());
          let token = String::from(sub_m.value_of("iq-token").unwrap());
          let stage = String::from(sub_m.value_of("iq-stage").unwrap());
          let application = String::from(sub_m.value_of("iq-application").unwrap());
          let attempts: u32 = String::from(sub_m.value_of("iq-attempts").unwrap()).parse().unwrap();

          let iq_bar = ProgressBar::new_spinner();
          iq_bar.set_style(spinner_style.clone());
          iq_bar.set_message(format!("{}{}", SPARKIES, "Sending SBOM to Nexus IQ Server for evaluation"));

          let iq = IQClient::new(server.clone(), user, token, stage, application, attempts);
          match iq.audit_with_iq_server(sbom) {
            Ok(res) => {
              iq_bar.finish_with_message(format!("{}{}", CRAB, "Nexus IQ Results obtained"));
              println!("");

              let table = generate_summary_table(res.url_results.open_policy_violations);

              match res.url_results.policy_action.as_ref() {
                "Failure" => {
                  print_iq_summary(
                    CRAB,
                    style("Aw Crabs! Policy violations exist in your scan.").red().bold(), 
                    table, 
                    server, 
                    res.url_results.report_html_url);

                  process::exit(1);
                }
                "Warning" => {
                  print_iq_summary(
                    CONSTRUCTION,
                    style("Barnacles! Warnings have been detected in your scan.").yellow().bold(), 
                    table, 
                    server, 
                    res.url_results.report_html_url);
                }
                "None" => {
                  print_iq_summary(
                    SHIP,
                    style("Smooth sailing! No policy issues found in your scan.").green().bold(), 
                    table, 
                    server, 
                    res.url_results.report_html_url);
                },
                _ => {
                  println!(
                    "{}", "The response from Nexus IQ Server did not include a policy action, which is odd"
                  );

                  process::exit(1);
                }
              }
            },
            Err(e) => {
              iq_bar.finish_with_message(
                format!("{}{}", CROSS_MARK, "Error generating Nexus IQ Server results")
              );
              println!("{}", e);

              process::exit(1);
            }
          }
        },
        Err(e) => {
          package_bar.finish_with_message(format!("{}{}", CROSS_MARK, "Unable to obtain package list"));
          println!("{}", e);

          process::exit(1);
        }
      };
    }
    _ => print_no_command_found()
  }
}

fn get_log_level_filter(matches: &ArgMatches) -> LevelFilter {
  match matches.occurrences_of("verbose") {
    1 => {
      return LevelFilter::Warn
    },
    2 => {
      return LevelFilter::Info
    },
    3 => {
      return LevelFilter::Debug
    },
    4 => {
      return LevelFilter::Trace
    }
    _ => {
      return LevelFilter::Error
    }
  };
}

fn construct_logger(iq: bool, log_level_filter: LevelFilter) {
  static FILENAME: &str = "cargo-pants.combined.log";
  static IQ_DIR: &str = ".iqserver";
  static OSS_INDEX_DIR: &str = ".ossindex";
  let home = home_dir().unwrap();

  let log_location_base_dir = ternary!(iq, home.join(IQ_DIR), home.join(OSS_INDEX_DIR));

  let file = FileAppender::builder()
    .encoder(Box::new(JsonEncoder::new()))
    .build(log_location_base_dir.join(FILENAME))
    .unwrap();

  let config = Config::builder()
    .appender(Appender::builder().build("file", Box::new(file)))
    .logger(Logger::builder()
      .appender("file")
      .additive(true)
      .build("app::file", log_level_filter))
    .build(Root::builder().appender("file").build(log_level_filter))
    .unwrap();

  let _handle = log4rs::init_config(config).unwrap();

  println!("Log Level set to: {}", log_level_filter);
  println!("Logging to: {:?}", log_location_base_dir.join(FILENAME));
}

fn print_iq_summary(emoji: Emoji, summary_line: StyledObject<&str>, table: TableStruct, server: String, html_url: String) {
  println!(
    "{}{}",
    emoji,
    summary_line
  );
  println!("");
  assert!(print_stdout(table).is_ok());
  println!("");
  println!("{}{}/{}", style("Report URL: ").dim(), server, html_url);
}

fn generate_summary_table(policy_violations: OpenPolicyViolations) -> TableStruct {
  debug!("Generating summary table with policy violations {:?}", policy_violations);

  return vec![
    vec![style("Critical").red().bold().cell(), policy_violations.critical.cell().justify(Justify::Right)],
    vec![style("Severe").yellow().bold().cell(), policy_violations.severe.cell().justify(Justify::Right)],
    vec![style("Moderate").cyan().bold().cell(), policy_violations.moderate.cell().justify(Justify::Right)],
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

pub fn get_api_key() -> String {
  let api_key: String = match env::var("OSS_INDEX_API_KEY") {
      Ok(val) => val,
      Err(e) => {
          println!("Warning: missing optional 'OSS_INDEX_API_KEY': {}", e);
          "".to_string()
      }
  };
  return api_key;
}

fn get_packages(lockfile_path: String) -> Result<Vec<Package>, Error> {
  debug!("Attempting to get package list from {}", lockfile_path);

  match Lockfile::load(lockfile_path) {
    Ok(f) => {
      debug!("Got packages from lockfile, cloning and moving forward");
      let packages: Vec<Package> = f.packages.clone();

      return Ok(packages);
    },
    Err(e) => {
      error!("Encountered error in get_packages, attempting to load Lockfile");
      return Err(e)
    }
  };
}

fn audit(lockfile_path: String, verbose_output: bool, enable_color: bool) -> ! {
  let packages = match get_packages(lockfile_path) {
    Ok(packages) => packages,
    Err(e) => {
      println!("{}", e);
      process::exit(1);
    }
  };

  let api_key: String = get_api_key();
  let client = OSSIndexClient::new(api_key);
  let mut coordinates: Vec<Coordinate> = Vec::new();
  for chunk in packages.chunks(128) {
      coordinates.append(&mut client.post_coordinates(chunk.to_vec()));
  }

  let mut non_vulnerable_package_count: u32 = 0;
  let mut vulnerable_package_count: u32 = 0;

  for coordinate in &coordinates {
      if coordinate.has_vulnerabilities() {
          vulnerable_package_count += 1;
      } else {
          non_vulnerable_package_count += 1;
      }
  }

  let mut stdout = stdout();
  if verbose_output {
      banner();

      write_package_output(
          &mut stdout,
          &coordinates,
          non_vulnerable_package_count,
          false,
          enable_color,
          None,
      )
      .expect("Error writing non-vulnerable packages to output");
  }

  if vulnerable_package_count > 0 {
      write_package_output(
          &mut stdout,
          &coordinates,
          vulnerable_package_count,
          true,
          enable_color,
          None,
      )
      .expect("Error writing vulnerable packages to output");
  }

  // show a summary so folks know we are not pantless
  println!(
      "{}",
      get_summary_message(coordinates.len() as u32, vulnerable_package_count)
  );

  match vulnerable_package_count {
      0 => process::exit(0),
      _ => process::exit(3),
  }
}

fn banner() {
  println!("{}", std::include_str!("banner.txt"));
  println!("{} version: {}", crate_name!(), crate_version!());
}

fn write_package_output(
  output: &mut dyn Write,
  coordinates: &Vec<Coordinate>,
  package_count: u32,
  vulnerable: bool,
  enable_color: bool,
  width_override: Option<u16>,
) -> io::Result<()> {
  use ansi_term::{Color, Style};

  let vulnerability = match vulnerable {
      true => "Vulnerable",
      false => "Non-vulnerable",
  };
  writeln!(output, "\n{} Dependencies\n", vulnerability)?;

  for (index, coordinate) in coordinates
      .iter()
      .filter(|c| vulnerable == c.has_vulnerabilities())
      .enumerate()
  {
      let style: Style = match vulnerable {
          true => Color::Red.bold(),
          false => Color::Green.normal(),
      };

      if enable_color {
          writeln!(
              output,
              "[{}/{}] {}",
              index + 1,
              package_count,
              style.paint(&coordinate.purl)
          )?;
      } else {
          writeln!(
              output,
              "[{}/{}] {}",
              index + 1,
              package_count,
              &coordinate.purl
          )?;
      }
      if vulnerable {
          let vulnerability_count = coordinate.vulnerabilities.len();
          let plural_text = match vulnerability_count {
              1 => "vulnerability",
              _ => "vulnerabilities",
          };

          let text = format!("{} known {} found", vulnerability_count, plural_text);
          if enable_color {
              writeln!(output, "{}", Color::Red.paint(text))?;
          } else {
              writeln!(output, "{}", text)?;
          }

          for vulnerability in &coordinate.vulnerabilities {
              if !vulnerability.title.is_empty() {
                  vulnerability
                      .output_table(output, enable_color, width_override)
                      .expect("Unable to output Vulnerability details");
                  writeln!(output, "\n")?;
              }
          }
      }
  }
  Ok(())
}

fn get_summary_message(component_count: u32, vulnerability_count: u32) -> String {
  let message = format!(
      "\nAudited Dependencies: {}\nVulnerable Dependencies: {}\n",
      component_count, vulnerability_count
  );
  return message;
}

fn check_pants(n: String) -> ! {
  match n.as_ref() {
      "JNCO" => {
          println!("{}", "Amber is the color of your energy");
          process::exit(311)
      }
      "Wrangler" => {
          println!("{}", "The 80s are over, friend");
          process::exit(1982)
      }
      "Levi" => {
          println!("{}", "Yippie Ki Yay, friendo bendo");
          process::exit(12251987)
      }
      _ => {
          println!("{}", "Uhhhhh");
          process::exit(1337)
      }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use cargo_pants::Vulnerability;

  #[test]
  fn empty_get_api_key() {
      let empty_env_value = get_api_key();
      assert_eq!(empty_env_value, "");
  }

  fn setup_test_coordinates() -> (Vec<Coordinate>, u32) {
      let mut coordinates: Vec<Coordinate> = Vec::new();

      let mut coord1 = Coordinate::default();
      coord1.purl = "coord one purl-1vuln".to_owned();
      let mut coord1_vuln1 = Vulnerability::default();
      coord1_vuln1.title = "coord1-vuln1 title".to_owned();
      coord1.vulnerabilities.push(coord1_vuln1);
      coordinates.push(coord1);

      let mut coord2 = Coordinate::default();
      coord2.purl = "coord two purl-3vulns".to_owned();
      let mut coord2_vuln1 = Vulnerability::default();
      coord2_vuln1.title = "coord2-vuln1 title".to_owned();
      coord2.vulnerabilities.push(coord2_vuln1);

      // empty title for vuln_two is intentional
      coord2.vulnerabilities.push(Vulnerability::default());

      let mut coord2_vuln3 = Vulnerability::default();
      coord2_vuln3.title = "coord2-vuln3 title".to_owned();
      coord2.vulnerabilities.push(coord2_vuln3);
      coordinates.push(coord2);

      let mut coordinate_three = Coordinate::default();
      coordinate_three.purl = "coord three purl-no vulns".to_owned();
      coordinates.push(coordinate_three);

      let package_count = coordinates.len() as u32;
      return (coordinates, package_count);
  }

  fn convert_output(output: &Vec<u8>) -> &str {
      std::str::from_utf8(output.as_slice()).unwrap()
  }

  #[test]
  fn write_package_output_non_vulnerable() {
      let (coordinates, package_count) = setup_test_coordinates();
      let mut package_output = Vec::new();
      write_package_output(
          &mut package_output,
          &coordinates,
          package_count,
          false,
          false,
          Some(30),
      )
      .unwrap();
      assert_eq!(
          convert_output(&package_output),
          "\nNon-vulnerable Dependencies\n\n[1/3] coord three purl-no vulns\n"
      );
  }

  #[test]
  fn write_package_output_vulnerable() {
      let (coordinates, package_count) = setup_test_coordinates();
      let mut package_output = Vec::new();
      write_package_output(
          &mut package_output,
          &coordinates,
          package_count,
          true,
          false,
          Some(30),
      )
      .unwrap();
      assert_eq!(
          convert_output(&package_output),
          "\nVulnerable Dependencies\n\n[1/3] coord one purl-1vuln\n1 known vulnerability found\n\
          ╭────────────────────────────╮\
          │ coord1-vuln1 title         │\
          ├─────────────┬──────────────┤\
          │ Description ┆              │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │  CVSS Score ┆ 0            │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │ CVSS Vector ┆              │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │   Reference ┆              │\
          ╰─────────────┴──────────────╯\
          \n\n[2/3] coord two purl-3vulns\n3 known vulnerabilities found\n\
          ╭────────────────────────────╮\
          │ coord2-vuln1 title         │\
          ├─────────────┬──────────────┤\
          │ Description ┆              │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │  CVSS Score ┆ 0            │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │ CVSS Vector ┆              │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │   Reference ┆              │\
          ╰─────────────┴──────────────╯\n\n\
          ╭────────────────────────────╮\
          │ coord2-vuln3 title         │\
          ├─────────────┬──────────────┤\
          │ Description ┆              │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │  CVSS Score ┆ 0            │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │ CVSS Vector ┆              │\
          ├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤\
          │   Reference ┆              │\
          ╰─────────────┴──────────────╯\
          \n\n"
      );
  }

  #[test]
  fn get_summary_message_content() {
      let summary_message = get_summary_message(2, 1);
      assert_eq!(
          summary_message,
          "\nAudited Dependencies: 2\nVulnerable Dependencies: 1\n"
      );
  }
}
