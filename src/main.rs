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
    env,
    process
};
use cargo_pants::{package::Package, lockfile::Lockfile, client::OSSIndexClient, coordinate::Coordinate};
use gumdrop::Options;

const CARGO_DEFAULT_LOCKFILE: &str = "Cargo.lock";

#[derive(Debug, Options)]
enum Opts {
    #[options(help = "Audit Cargo.lock files for vulnerable crates using Sonatype OSSIndex")]
    Pants(PantsOpts),
}

/// Options for the `cargo pants` subcommand
#[derive(Debug, Options)]
struct PantsOpts {
    /// Lockfile Path
    #[options(
        short = "l",
        long = "lockfile",
        help = "The path to your Cargo.lock file"
    )]
    lockfile: Option<String>,

    /// Pants Style
    #[options(
        short = "s",
        long = "pants_style",
        help = "pants style"
    )]
    pants_style: Option<String>,

}
impl Default for PantsOpts {
    fn default() -> PantsOpts {
        PantsOpts {
            lockfile: None,
            pants_style: None
        }
    }
}
fn main() {
    let args: Vec<_> = env::args().collect();

    let Opts::Pants(opts) = Opts::parse_args_default(&args[1..]).unwrap_or_else(|_| {
        help(1);
    });
    let pants_style = opts.pants_style.as_ref().map(|s| s.as_ref()).unwrap_or("");

    if pants_style.len() > 0 {
        check_pants(pants_style.to_string());
    }

    let lockfile_path = opts.lockfile.as_ref().map(|s| s.as_ref()).unwrap_or(CARGO_DEFAULT_LOCKFILE);
    audit(lockfile_path.to_string());
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
fn help(code: i32) -> ! {
    println!("Usage: cargo pants [OPTIONS]");
    println!();
    println!("{}", Opts::command_usage("lockfile").unwrap());
    process::exit(code);
}
