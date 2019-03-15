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
use std::{
    process,
};
use cargo_pants::{package::Package, lockfile::Lockfile, client::OSSIndexClient, coordinate::Coordinate};
use argparse::{Store, StoreTrue, ArgumentParser};

const CARGO_DEFAULT_LOCKFILE: &str = "Cargo.lock";
const NOPANTS: &str = "No Pants";

fn main() {
    let mut lockfile = CARGO_DEFAULT_LOCKFILE.to_string();
    let mut pants_style = NOPANTS.to_string();
    let mut help = false;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Audit Cargo.lock files for vulnerable crates using Sonatype OSSIndex");
        ap.refer(&mut lockfile)
            .add_option(&["-l", "--lockfile"], Store,
            "Name for the greeting");
        ap.refer(&mut pants_style)
            .add_option(&["-p", "--pants_style"], Store,
            "Pants Style");
        ap.refer(&mut help)
            .add_option(&["--help"], StoreTrue,
            "Help");
        ap.parse_args_or_exit();
    }
    if pants_style != NOPANTS {
        check_pants(pants_style);
    }
    if help {
        helper(0);
    }
    audit(lockfile);
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

    let client = OSSIndexClient::new("KEY".to_string());
    let mut coordinates: Vec<Coordinate> = Vec::new();
    for chunk in packages.chunks(128) {
        coordinates.append(&mut client.post_coordinates(chunk.to_vec()).unwrap());
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

/// Print help message
fn helper(code: i32) -> ! {
    println!("Usage: cargo pants [OPTIONS]");
    println!();
    process::exit(code);
}
