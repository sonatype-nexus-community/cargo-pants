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
use std::{env, process};

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
        )
        .get_matches();

    match matches.subcommand_matches("pants") {
        None => {
            println!("Error, this tool is designed to be executed from cargo itself.");
            println!("Therefore at least the command line parameter 'pants' must be provided.");
        }
        Some(pants_matches) => {
            if pants_matches.is_present("pants_style") {
                let pants_style = String::from(pants_matches.value_of("pants_style").unwrap());
                check_pants(pants_style);
            }

            let lockfile = pants_matches.value_of("lockfile").unwrap();
            let verbose_output = pants_matches.is_present("loud");

            audit(lockfile.to_string(), verbose_output);
        }
    }
}

fn get_api_key() -> String {
    let api_key: String = match env::var("OSS_INDEX_API_KEY") {
        Ok(val) => val,
        Err(e) => {
            println!("Warning: missing optional 'OSS_INDEX_API_KEY': {}", e);
            "".to_string()
        }
    };
    return api_key;
}

fn audit(lockfile_path: String, verbose_output: bool) -> ! {
    let lockfile: Lockfile = Lockfile::load(lockfile_path).unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(3);
    });

    let packages: Vec<Package> = lockfile.packages.clone();
    // for package in &packages {
    //     println!("{}", package);
    // }

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

    if verbose_output {
        write_package_output(&coordinates, non_vulnerable_package_count, false);
    }

    if vulnerable_package_count > 0 {
        write_package_output(&coordinates, vulnerable_package_count, true);
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

fn write_package_output(coordinates: &Vec<Coordinate>, package_count: u32, vulnerable: bool) {
    let vulnerability = match vulnerable {
        true => "Vulnerable",
        false => "Non-vulnerable",
    };
    println!("\n{} Dependencies\n", vulnerability);

    for (index, coordinate) in coordinates
        .iter()
        .filter(|c| vulnerable == c.has_vulnerabilities())
        .enumerate()
    {
        println!("[{}/{}] {}", index + 1, package_count, coordinate.purl);
        if vulnerable {
            let vulnerability_count = coordinate.vulnerabilities.len();
            let plural_text = match vulnerability_count {
                1 => "vulnerability",
                _ => "vulnerabilities",
            };
            println!("{} known {} found\n", vulnerability_count, plural_text);
            for vulnerability in &coordinate.vulnerabilities {
                if !vulnerability.title.is_empty() {
                    println!("{}\n", vulnerability);
                }
            }
        }
    }
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

    #[test]
    fn empty_get_api_key() {
        let empty_env_value = get_api_key();
        assert_eq!(empty_env_value, "");
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
