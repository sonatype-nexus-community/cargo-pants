<!-- 
Copyright 2019 Glenn Mohre

Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License. 
-->

<p align="center">
    <img src="https://raw.githubusercontent.com/sonatype-nexus-community/cargo-pants/main/docs/images/pants.png" width="350"/>
</p>
<p align="center">
    <a href="https://circleci.com/gh/sonatype-nexus-community/cargo-pants"><img src="https://circleci.com/gh/sonatype-nexus-community/cargo-pants.svg?style=shield" alt="Circle CI Build Status"></img></a>
    <a href="https://crates.io/crates/cargo-pants"><img src="https://img.shields.io/crates/v/cargo-pants.svg"></img></a>
</p>

# cargo pants

`cargo-pants` is a Cargo subcommand that provides a bill of materials in a project, and any vulnerabilities that are found on those dependencies, powered by [Sonatype OSS Index](https://ossindex.sonatype.org/).

## Why pants?

Don't you check your pants for holes? Similarly, we think you should check your app's dependencies for vulnerabilities, and that's what `cargo-pants` does! As well, we provide a Bill Of Materials from parsing your `Cargo.lock` file, so you can see all the dependencies you are using.

## Requirements

`cargo-pants` was built with Rust 1.49.0, you should likely start there.

## Installation

`cargo-pants` is a Cargo subcommand, and can be installed using `cargo install`:

```
$ cargo install cargo-pants
```

Set an environment variable `OSS_INDEX_API_KEY` to auth requests with your key.

Once you have installed `cargo-pants`, you can run it like so:

```
$ cargo pants
```

## Usage

`cargo pants` can be run in your builds context, or ran separately. Two command line options are supported:

```
$ cargo pants --lockfile /path/to/Cargo.lock
```

This allows you to run `cargo pants` on a `Cargo.lock` file anywhere on your filesystem.

If this option is not supplied, `cargo pants` will assume a local `Cargo.lock` file.

We will also inform you of our opinions of your pants style choice:

```
$ cargo pants --pants_style JNCO
```

We are very serious about pants.

There are also two command line flags that affect the output further:

```
$ cargo pants --loud --lockfile /path/to/Cargo.lock
```
This shows all non-vulnerable dependencies for a complete Bill of Materials.

```
$ cargo pants --no-color --lockfile /path/to/Cargo.lock
```
This disables any coloring of the output.


If vulnerabilities are found, `cargo-pants` exits with status code 3, and prints the Bill Of Materials/Found Vulnerabilities. If there are no issues, it will exit with status code 0.

## IQ Usage

More TBD, but experimental usage for Nexus IQ Server now exists:

```
cargo-iq

USAGE:
    cargo iq [FLAGS] [OPTIONS] --iq-application <iq-application>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v

OPTIONS:
    -a, --iq-application <iq-application>    Specify Nexus IQ public application ID for request
    -t, --iq-attempts <iq-attempts>          Specify Nexus IQ attempts in seconds [default: 60]
    -x, --iq-server-url <iq-server-url>      Specify Nexus IQ server url for request [default: http://localhost:8070]
    -s, --iq-stage <iq-stage>                Specify Nexus IQ stage for request [default: develop]
    -k, --iq-token <iq-token>                Specify Nexus IQ token for request [default: admin123]
    -l, --iq-username <iq-username>          Specify Nexus IQ username for request [default: admin]
        --tomlfile <tomlfile>                The path to your Cargo.toml file [default: Cargo.toml]
```

## CI Usage

Similar to `cargo audit` but with more pants, you can run `cargo pants` on your builds on Travis CI using this example config:

```
language: rust
before_script:
  - cargo install --force cargo-pants
script:
  - cargo pants
```

We use [CircleCI](https://circleci.com) to build this project. See our CircleCI config: [.circleci/config.yml](.circleci/config.yml)
for how we use cargo-pants in our CI build. This file is also a good reference for a number of useful cargo commands.

## Contributing

We care a lot about making the world a safer place, and that's why we created `cargo-pants`. If you as well want to
speed up the pace of software development by working on this project, jump on in! Before you start work, create
a new issue, or comment on an existing issue, to let others know you are!

## Acknowledgements

The code for `cargo-pants` was largely written by Glenn Mohre, and we want to give ultimate thanks, kudos, congratulations to Glenn for contributing this to the community. Open Source is awesome, and you help make it better!

The `cargo-pants` logo was grabbed from [www.pexels.com](https://www.pexels.com), specifically from [this image](https://www.pexels.com/photo/people-wearing-denim-jeans-1353361/). 

Code for `cargo-pants` was influenced by `cargo-audit`, and we acknowledge we stand on the shoulders of giants.

## Development

You can run your local changes without installing the package via:

```shell
cargo run pants
```
or
```shell
cargo run iq --iq-application sandbox-application
```

Use the commands below to build and install the package locally:

```shell
cargo build --all --all-targets
cargo install cargo-pants --force --path .
```

### Release Process

The Continuous Integration build will automatically perform a new release with every commit to the `main` branch.

To skip performing a release from `main` be sure your commit message includes: `[skip ci]`.

## The Fine Print

It is worth noting that this is **NOT SUPPORTED** by Sonatype, and is a contribution of ours
to the open source community (read: you!)

Remember:

* Use this contribution at the risk tolerance that you have
* Do NOT file Sonatype support tickets related to `cargo-pants` support in regard to this project
* DO file issues here on GitHub, so that the community can pitch in

Phew, that was easier than I thought. Last but not least of all:

Have fun creating and using `cargo-pants` and the [Sonatype OSS Index](https://ossindex.sonatype.org/), we are glad to have you here!

## Getting help

Looking to contribute to our code but need some help? There's a few ways to get information:

* Chat with us on [Gitter](https://gitter.im/sonatype/nexus-developers)

