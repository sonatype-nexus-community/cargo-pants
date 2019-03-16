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

use std::{
    env,
    process,
};
use cargo_pants::{package::Package, lockfile::Lockfile, client::OSSIndexClient, coordinate::Coordinate};
use clap::{Arg, App, SubCommand};

const CARGO_DEFAULT_LOCKFILE: &str = "Cargo.lock";

fn main() {
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
        )
        .get_matches();


    let pants_matches = matches.subcommand_matches("pants").unwrap();

    if pants_matches.is_present("pants_style") {
        let pants_style = String::from(pants_matches.value_of("pants_style").unwrap());
        check_pants(pants_style);
    }

    let lockfile = pants_matches.value_of("lockfile").unwrap();

    audit(lockfile.to_string());
}

fn get_api_key() -> String {
    let api_key:String = match env::var("OSS_INDEX_API_KEY") {
        Ok(val) => val,
        Err(e) => {
            println!("{}", e);
            "".to_string()
        }
    };
    return api_key
}

fn audit(lockfile_path: String) -> ! {
    let lockfile : Lockfile = Lockfile::load(lockfile_path).unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(3);
    });

    println!("\nBill of Materials Header\n");
    let packages: Vec<Package> = lockfile.packages.clone();
    for package in &packages {
        println!("{}", package);
    }

    let api_key:String = get_api_key();
    let client = OSSIndexClient::new(api_key);
    let mut coordinates: Vec<Coordinate> = Vec::new();
    for chunk in packages.chunks(128) {
        coordinates.append(&mut client.post_coordinates(chunk.to_vec()));
    }

    let mut vulnerabilities_count: u32 = 0;
    let mut vul_str = String::new();

    for coordinate in &coordinates {
        for v in &coordinate.vulnerabilities {
            if !v.title.is_empty() {
                vul_str.push_str(&format!("\nVulnerability - {}\n{}\n", coordinate.purl, v));
            }
        }
        vulnerabilities_count = vulnerabilities_count + coordinate.vulnerabilities.len() as u32;
    }

    if !vul_str.is_empty() {
        println!("\nVulnerabilities Count - {}\n{}", vulnerabilities_count, vul_str);
    }

    match vulnerabilities_count {
        0 => process::exit(0),
        _ => process::exit(3)
    }
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
        },
    }
}
