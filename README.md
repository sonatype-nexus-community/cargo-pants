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

```
cargo-pants 0.3.2
Glenn Mohre <glennmohre@gmail.com>
A library for auditing your cargo dependencies for vulnerabilities and checking your pants

USAGE:
    cargo pants [FLAGS] [OPTIONS]

FLAGS:
    -h, --help        Prints help information
        --dev         A flag to include dev dependencies
    -v, --verbose     Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v
    -d, --loud        Also show non-vulnerable dependencies
    -m, --no-color    Disable color output
    -V, --version     Prints version information

OPTIONS:
        --ignore-file <ignore-file>           The path to your .pants-ignore file [default: .pants-ignore]
        --ossi-api-key <oss-index-api-key>    OSS Index API Key [env: OSS_INDEX_API_KEY]
    -s, --pants_style <pants-style>           Your pants style
        --tomlfile <toml-file>                The path to your Cargo.toml file [default: Cargo.toml]
```

`cargo pants` can be run in your builds context, or ran separately.

We will also inform you of our opinions of your pants style choice:

```
$ cargo pants --pants_style JNCO
```

We are very serious about pants.

There are also two command line flags that affect the output further:

```
$ cargo pants --loud
```
This shows all non-vulnerable dependencies for a complete Bill of Materials.

```
$ cargo pants --no-color
```
This disables any coloring of the output.

If vulnerabilities are found, `cargo-pants` exits with status code 3, and prints the Bill Of Materials/Found Vulnerabilities. If there are no issues, it will exit with status code 0.

### Excluding Vulnerabilities
Exclusion of vulnerabilities can be done! To accomplish this thus far we have implemented the ability to have a file named `.pants-ignore` checked in to your repo ideally, so that it would be at the root where you run `cargo-pants`. Alternatively you can run `cargo-pants` with a exclusion file at a different location, with an example such as:

```
$ cargo pants --ignore-file /Users/cooldeveloperperson/code/sonatype-nexus-community/cargo-pants/.pants-ignore
```

The file should look like:

```
{
  "ignore": [{ "id": "78a61524-80c5-4371-b6d1-6b32af349043", "reason": "Insert reason here" }]
}
```
The only field that actually matters is id and that is the ID you receive from OSS Index for a vulnerability. You can add fields such as reason so that you later can understand why you whitelisted a vulnerability.

Any id that is excluded will be squelched from the results, and not cause a failure.

## IQ Usage

More TBD, but experimental usage for Nexus IQ Server now exists:

```
cargo-iq 0.3.1
Glenn Mohre <glennmohre@gmail.com>
A library for auditing your cargo dependencies for vulnerabilities and checking your pants

USAGE:
    cargo iq [FLAGS] [OPTIONS] --iq-application <application>

FLAGS:
    -h, --help       Prints help information
        --dev        A flag to include dev dependencies
    -v, --verbose    Set the verbosity of the logger, more is more verbose, so -vvvv is more verbose than -v
    -V, --version    Prints version information

OPTIONS:
    -a, --iq-application <application>    Specify Nexus IQ public application ID for request
    -t, --iq-attempts <attempts>          Specify Nexus IQ attempts in seconds [default: 60]
    -x, --iq-server-url <server-url>      Specify Nexus IQ server url for request [default: http://localhost:8070]
    -s, --iq-stage <stage>                Specify Nexus IQ stage for request [default: develop]
    -k, --iq-token <token>                Specify Nexus IQ token for request [env: TOKEN=]  [default: admin123]
        --tomlfile <toml-file>            The path to your Cargo.toml file [default: Cargo.toml]
    -l, --iq-username <username>          Specify Nexus IQ username for request [default: admin]
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

