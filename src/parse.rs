// Copyright 2021 Sonatype.
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
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::ops::Index;

pub struct ParseCargoToml {
    pub toml_file_path: String,
    pub include_dev: bool,
    deps_add_queue: VecDeque<PackageId>,
    packages: Vec<crate::package::Package>,
    existing_packages: HashMap<PackageId, bool>,
}

impl ParseCargoToml {
    pub fn new(toml_file_path: String, include_dev: bool) -> ParseCargoToml {
        return ParseCargoToml {
            toml_file_path: toml_file_path,
            include_dev: include_dev,
            deps_add_queue: VecDeque::new(),
            packages: Vec::new(),
            existing_packages: HashMap::new(),
        };
    }

    pub fn get_packages(&mut self) -> Result<Vec<crate::package::Package>, Error> {
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

    fn parse_dependencies(&mut self, metadata: Metadata, resolve: Resolve) -> Result<(), Error> {
        while let Some(pkg_id) = self.deps_add_queue.pop_front() {
            let p: &cargo_metadata::Package = metadata.index(&pkg_id);
            self.packages.push(crate::package::Package {
                name: p.name.clone(),
                version: p.version.clone(),
                license: p.license.clone(),
            });

            if let Some(resolved_dep) = resolve.nodes.iter().find(|n| n.id == pkg_id) {
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
