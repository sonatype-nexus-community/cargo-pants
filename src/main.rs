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

use cargo_pants::{
    client::OSSIndexClient, coordinate::Coordinate, lockfile::Lockfile, package::Package,
};
use clap::{App, Arg, SubCommand};
use std::io::{stdout, Write};
use std::{env, io, process};

const CARGO_DEFAULT_LOCKFILE: &str = "Cargo.lock";

fn main() {
    env_logger::init();
    let matches = App::new("Cargo Pants")
        .version(crate_version!())
        .bin_name("cargo")
        .author("Glenn Mohre <glennmohre@gmail.com>")
        .about("A library for auditing your cargo dependencies for vulnerabilities and checking your pants")
        .subcommand(SubCommand::with_name("pants")
            .arg(Arg::with_name("lockfile")
                .short("l")
                .long("lockfile")
                .takes_value(true)
                .help("The path to your Cargo.lock file")
                .default_value(CARGO_DEFAULT_LOCKFILE))
            .arg(Arg::with_name("pants_style")
                .short("s")
                .long("pants_style")
                .takes_value(true)
                .help("Your pants style"))
            .arg(Arg::with_name("loud")
                .short("v")
                .long("loud")
                .takes_value(false)
                .help("Also show non-vulnerable dependencies"))
            .arg(Arg::with_name("no-color")
                .short("m")
                .long("no-color")
                .takes_value(false)
                .help("Disable color output"))
        )
        .get_matches();

    match matches.subcommand_matches("pants") {
        None => {
            println!("Error, this tool is designed to be executed from cargo itself.");
            println!("Therefore at least the command line parameter 'pants' must be provided.");
        }
        Some(pants_matches) => {
            if let Some(pants_style) = pants_matches.value_of("pants_style") {
                check_pants(pants_style);
            }

            let lockfile = pants_matches
                .value_of("lockfile")
                .expect("lockfile command argument not present");
            let verbose_output = pants_matches.is_present("loud");
            let enable_color: bool = !pants_matches.is_present("no-color");

            audit(lockfile.to_string(), verbose_output, enable_color);
        }
    }
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

fn audit(lockfile_path: String, verbose_output: bool, enable_color: bool) -> ! {
    let lockfile: Lockfile = Lockfile::load(lockfile_path).unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(3);
    });

    let packages: Vec<Package> = lockfile.packages.clone();
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

fn check_pants(n: &str) -> ! {
    match n {
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
        std::str::from_utf8(output.as_slice()).expect("Could not convert output to UTF-8")
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
        .expect("Failed to write package output");
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
        .expect("Failed to write package output");
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
