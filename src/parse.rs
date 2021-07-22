// Copyright 2021 Sonatype, and Authors of https://github.com/sfackler/cargo-tree.
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

use crate::error::Error;
use cargo_metadata::DependencyKind::Normal;
use cargo_metadata::Metadata;
use cargo_metadata::PackageId;
use cargo_metadata::Resolve;
use cargo_metadata::{CargoOpt, MetadataCommand};
use log::{debug, trace};
use petgraph::graph::Graph;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;
use std::collections::HashSet;
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::ops::Index;

#[derive(Clone, Copy)]
enum Prefix {
    None,
    Indent,
    Depth,
}

struct Symbols {
    down: &'static str,
    tee: &'static str,
    ell: &'static str,
    right: &'static str,
}

static UTF8_SYMBOLS: Symbols = Symbols {
    down: "│",
    tee: "├",
    ell: "└",
    right: "─",
};

static ASCII_SYMBOLS: Symbols = Symbols {
    down: "|",
    tee: "|",
    ell: "`",
    right: "-",
};

pub trait ParseToml {
    fn new(toml_file_path: String, include_dev: bool) -> Self;
    fn get_packages(&mut self) -> Result<Vec<crate::package::Package>, Error>;
    fn print_the_graph(&self, purl: String) -> Result<(), Error>;
    fn parse_dependencies(&mut self, metadata: Metadata, resolve: Resolve) -> Result<(), Error>;
}

pub struct ParseCargoToml {
    pub toml_file_path: String,
    pub include_dev: bool,
    deps_add_queue: VecDeque<PackageId>,
    packages: Vec<crate::package::Package>,
    nodes: HashMap<PackageId, NodeIndex>,
    purl_map: HashMap<String, PackageId>,
    existing_packages: HashMap<PackageId, bool>,
    graph: Graph<crate::package::Package, cargo_metadata::DependencyKind>,
}

pub struct TestParseCargoToml {
    pub toml_file_path: String,
    pub include_dev: bool,
}

impl ParseToml for TestParseCargoToml {
    fn new(_: std::string::String, _: bool) -> Self {
        return Self {
            include_dev: false,
            toml_file_path: "".to_string(),
        };
    }

    fn get_packages(&mut self) -> std::result::Result<Vec<crate::package::Package>, Error> {
        let pkg = crate::package::Package {
            name: "test".to_string(),
            version: cargo_metadata::Version {
                major: 1,
                minor: 0,
                patch: 2,
                build: vec![],
                pre: vec![],
            },
            license: Some("Apache-2.0".to_string()),
            package_id: PackageId {
                repr: "".to_string(),
            },
        };

        Ok(vec![pkg])
    }

    fn print_the_graph(&self, _: std::string::String) -> Result<(), Error> {
        Ok(())
    }
    fn parse_dependencies(
        &mut self,
        _: cargo_metadata::Metadata,
        _: cargo_metadata::Resolve,
    ) -> std::result::Result<(), Error> {
        Ok(())
    }
}

impl Default for ParseCargoToml {
    fn default() -> Self {
        Self {
            toml_file_path: crate::common::CARGO_DEFAULT_TOMLFILE.to_string(),
            include_dev: false,
            deps_add_queue: VecDeque::new(),
            packages: Vec::new(),
            nodes: HashMap::new(),
            purl_map: HashMap::new(),
            existing_packages: HashMap::new(),
            graph: Graph::new(),
        }
    }
}

impl ParseToml for ParseCargoToml {
    fn new(toml_file_path: String, include_dev: bool) -> Self {
        return Self {
            toml_file_path: toml_file_path,
            include_dev: include_dev,
            ..Default::default()
        };
    }

    fn get_packages(&mut self) -> Result<Vec<crate::package::Package>, Error> {
        debug!(
            "Attempting to get package list from {}",
            self.toml_file_path.clone()
        );

        let metadata: Metadata = MetadataCommand::new()
            .manifest_path(self.toml_file_path.clone())
            .features(CargoOpt::AllFeatures)
            .exec()?;

        let workspace_members: Vec<PackageId> = metadata.clone().workspace_members;

        let resolve = metadata.clone().resolve.unwrap();

        for package in metadata.clone().packages {
            let id = package.id.clone();
            let pkg = crate::package::Package {
                name: package.name,
                version: package.version,
                license: package.license,
                package_id: id.clone(),
            };
            let index = self.graph.add_node(pkg.clone());
            self.nodes.insert(id.clone(), index);
            self.purl_map.insert(pkg.as_purl(), id);
        }

        for pkg_id in &workspace_members {
            let _pkg: &cargo_metadata::Package = metadata.clone().index(pkg_id);
            self.deps_add_queue.push_back(pkg_id.clone());
        }

        match self.parse_dependencies(metadata.clone(), resolve.clone()) {
            Ok(()) => {
                return Ok(self.packages.clone());
            }
            Err(e) => return Err(e),
        };
    }

    fn print_the_graph(&self, purl: String) -> Result<(), Error> {
        let symbols = &UTF8_SYMBOLS;

        let prefix = Prefix::Indent;

        let pkg_id = self.purl_map.get(&purl).unwrap();

        print_tree(&self.graph, &self.nodes, pkg_id, symbols, prefix);

        Ok(())
    }

    fn parse_dependencies(&mut self, metadata: Metadata, resolve: Resolve) -> Result<(), Error> {
        while let Some(pkg_id) = self.deps_add_queue.pop_front() {
            let p: &cargo_metadata::Package = metadata.index(&pkg_id);
            self.packages.push(crate::package::Package {
                name: p.name.clone(),
                version: p.version.clone(),
                license: p.license.clone(),
                package_id: pkg_id.clone(),
            });

            if let Some(resolved_dep) = resolve.nodes.iter().find(|n| n.id == pkg_id) {
                let from = self.nodes[&resolved_dep.id];

                for dep in &resolved_dep.deps {
                    let mut into_iter = dep.dep_kinds.clone().into_iter();
                    let abby_normal: bool = match into_iter.find(|dk| dk.kind != Normal) {
                        Some(_val) => true,
                        None => false,
                    };

                    if !self.include_dev && abby_normal {
                        trace!(
                            "Entry skipped, ignoring it as it not a normal dependency {:?}",
                            dep
                        );
                        continue;
                    }

                    let to = self.nodes[&dep.pkg];

                    for kind in dep.clone().dep_kinds {
                        self.graph.add_edge(from, to, kind.kind);
                    }

                    match self.existing_packages.entry(dep.pkg.clone()) {
                        Entry::Occupied(o) => {
                            trace!("Entry exists, skipping {:?}", o);
                        }
                        Entry::Vacant(v) => {
                            v.insert(true);
                            self.deps_add_queue.push_back(dep.pkg.clone());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn print_tree<'a>(
    graph: &'a Graph<crate::package::Package, cargo_metadata::DependencyKind>,
    nodes: &'a HashMap<PackageId, NodeIndex>,
    pkg: &'a PackageId,
    symbols: &Symbols,
    prefix: Prefix,
) {
    let mut visited_deps = HashSet::new();
    let mut levels_continue = vec![];

    print_package(
        graph,
        nodes,
        pkg,
        symbols,
        prefix,
        &mut visited_deps,
        &mut levels_continue,
    );
}

fn print_package<'a>(
    graph: &'a Graph<crate::package::Package, cargo_metadata::DependencyKind>,
    nodes: &'a HashMap<PackageId, NodeIndex>,
    pkg: &'a PackageId,
    symbols: &Symbols,
    prefix: Prefix,
    visited_deps: &mut HashSet<&'a PackageId>,
    levels_continue: &mut Vec<bool>,
) {
    visited_deps.insert(&pkg);

    match prefix {
        Prefix::Depth => print!("{}", levels_continue.len()),
        Prefix::Indent => {
            if let Some((last_continues, rest)) = levels_continue.split_last() {
                for continues in rest {
                    let c = if *continues { symbols.down } else { " " };
                    print!("{}   ", c);
                }

                let c = if *last_continues {
                    symbols.tee
                } else {
                    symbols.ell
                };
                print!("{0}{1}{1} ", c, symbols.right);
            }
        }
        Prefix::None => {}
    }

    // let star = if new { "" } else { " (*)" };
    println!("{}", pkg);
    print_dependencies(
        graph,
        nodes,
        pkg,
        symbols,
        prefix,
        visited_deps,
        levels_continue,
    );
}

fn print_dependencies<'a>(
    graph: &'a Graph<crate::package::Package, cargo_metadata::DependencyKind>,
    nodes: &'a HashMap<PackageId, NodeIndex>,
    pkg: &'a PackageId,
    symbols: &Symbols,
    prefix: Prefix,
    visited_deps: &mut HashSet<&'a PackageId>,
    levels_continue: &mut Vec<bool>,
) {
    let mut deps = vec![];
    let idx = nodes[&pkg];
    for edge in graph.edges_directed(idx, EdgeDirection::Incoming) {
        let dep = &graph[edge.source()];
        deps.push(dep);
    }

    if deps.is_empty() {
        return;
    }

    deps.sort_by_key(|p| &p.package_id);

    let mut it = deps.iter().peekable();
    while let Some(dependency) = it.next() {
        levels_continue.push(it.peek().is_some());

        print_package(
            graph,
            nodes,
            &dependency.package_id,
            symbols,
            prefix,
            visited_deps,
            levels_continue,
        );
        levels_continue.pop();
    }
}
