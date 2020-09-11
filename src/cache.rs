use crate::{coordinate::Coordinate, types::OSSINDEX_DIRNAME};
use std::fmt;
use pickledb::{error::Error as PickleError, PickleDb, PickleDbDumpPolicy, SerializationMethod};
use std::path::PathBuf;

use chrono::{DateTime, Utc};

const DBNAME: &str = ".cargo-pantsdb";

#[derive(Debug)]
pub struct Options {
    db_options: DBOptions,
    ttl: u64,
}

#[derive(Default, Debug)]
pub struct DBOptions {
    db_dir: String,
    db_name: String,
}

pub struct Cache {
    options: Options,
    db: PickleDb
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DBValue {
    key: String,
    coords: Coordinate,
    ttl: DateTime<Utc>,
}

impl fmt::Display for Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Use `self.number` to refer to each positional data point.
        let vals = self.db.get_all();
        let stuff_str: String = vals.into_iter().map(|i| i.to_string()).collect::<String>();
        write!(f, "keys {}", stuff_str )
    }
}

impl fmt::Display for DBValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "({}, {})", self.key, self.ttl)
    }
}

fn get_db(options: &DBOptions) -> PickleDb {
    let path_buf: PathBuf = get_database_path(&options);
    let db: Result<PickleDb, PickleError> =
        PickleDb::load(path_buf, PickleDbDumpPolicy::AutoDump, SerializationMethod::Json);
    match db {
        Ok(db) => {
            return db
        }
        Err(_e) => {
            let path_buf: PathBuf = get_database_path(&options);
            let new_db: PickleDb = PickleDb::new(path_buf, PickleDbDumpPolicy::AutoDump, SerializationMethod::Json);
            new_db
        }
    }
}
fn get_database_path(options: &DBOptions) -> PathBuf {
    let path = PathBuf::from(format!(
        "{}/{}/{}/{}",
        std::env::var("HOME").unwrap(),
        OSSINDEX_DIRNAME,
        options.db_dir,
        options.db_name
    ));
    println!("path {:?}", path);
    path
}

impl Cache {
    fn new(options: Options) -> Cache {
        let db: PickleDb = get_db(&options.db_options);
        let cache: Cache = Cache { options, db };
        cache
    }


    pub fn clear(&self) {
        // Handle closing
        // get db path and handle error
        // try to clear db handle, if no err return
        // handle error
    }

    pub fn get(&mut self, key: &str) -> Option<DBValue> {
        match self.db.exists(&key) {
            true => {
                println!("Found {:?}", &key);
                let val: Option<DBValue> = self.db.get::<DBValue>(&key);
                return val
                // match val {
                //     Some(val) => {
                //         if val.ttl < Utc::now() {
                //             return Some(val)
                //         } else {
                //             return None
                //         }
                //     }
                //     None => return None,
                // }
            }
            false => {
                println!("Didnt find {:?}", &key);
                return None
            }
        }
    }

    pub fn set(&mut self, mut db_value: DBValue) {
        match self.db.exists(&db_value.key) {
            true => {
                println!("It Exists {:?}", self.db.exists(&db_value.key));
                println!("Key exists {:?}", self.db.get::<DBValue>(&db_value.key));
                let val: Option<DBValue> = self.db.get::<DBValue>(&db_value.key);
                if val.unwrap().ttl < Utc::now() {
                    // Remove and update key. Ok can be true or false, if the rem failed.
                    self.db.rem(&db_value.key).unwrap();
                    db_value.ttl = Utc::now();
                    let _res: Result<_, PickleError> = self.db.set(&db_value.key, &db_value);
                }
            }
            false => {
                let _res = self.db.set(&db_value.key, &db_value).unwrap();
                println!("Setting it{:?}", _res);
                return
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn _get_coordinate() -> Coordinate {
        let raw_json: &[u8] = r##"{
            "coordinates": "pkg:pypi/rust@0.1.1",
            "description": "Ribo-Seq Unit Step Transformation",
            "reference": "https://ossindex.sonatype.org/component/pkg:pypi/rust@0.1.1",
            "vulnerabilities": []
        }"##
        .as_bytes();
        let coordinate: Coordinate = serde_json::from_slice(raw_json).unwrap();
        return coordinate
    }

    #[test]
    fn set_value() {
        let mut cache: Cache = Cache::new(Options {
            db_options: DBOptions {
                db_dir: "dbdir".to_string(),
                db_name: "testdb".to_string(),
            },
            ttl: 60 * 60 * 12,
        });

        let coordinate: Coordinate = _get_coordinate();
        println!("cache {}", cache);
        let key: String = "pkg:pypi/rust@0.1.1".into();
        let db_value = DBValue {
            key: key.clone(),
            coords: coordinate,
            ttl: Utc::now()
        };
        cache.set(db_value);
        println!("post set cache {}", cache);
        let get_val: Option<DBValue> = cache.get(&key);
        assert_eq!(get_val.unwrap().coords.purl, "pkg:pypi/rust@0.1.1");
    }
}
