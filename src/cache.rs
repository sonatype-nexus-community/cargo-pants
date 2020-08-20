use crate::{coordinate::Coordinate, types::OSSINDEX_DIRNAME};

use pickledb::{error::Error as PickleError, PickleDb, PickleDbDumpPolicy};
use std::path::PathBuf;

use chrono::{DateTime, Utc};

const DBNAME: &str = ".cargo-pantsdb";

#[derive(Default)]
pub struct Options {
    db_dir: String,
    db_name: String,
    ttl: u64,
}

#[derive(Default)]
pub struct Cache {
    options: Options,
    db: Option<PickleDb>,
}

#[derive(Serialize, Deserialize)]
pub struct DBValue {
    key: String,
    coords: Coordinate,
    ttl: DateTime<Utc>,
}

impl Cache {
    fn new(options: Options) -> Cache {
        let mut cache: Cache = Cache { options, db: None };
        let db: PickleDb = cache.get_db();
        cache.db = Some(db);
        // Filter out expired values
        cache
    }

    fn get_db(&self) -> PickleDb {
        let db: Result<PickleDb, PickleError> =
            PickleDb::load_json(self.get_database_path(), PickleDbDumpPolicy::AutoDump);
        match db {
            Ok(db) => return db,
            Err(_e) => {
                let new_db: PickleDb =
                    PickleDb::new_json(self.get_database_path(), PickleDbDumpPolicy::AutoDump);
                return new_db;
            }
        }
    }

    pub fn clear(&self) {
        // Handle closing
        // get db path and handle error
        // try to clear db handle, if no err return
        // handle error
    }

    pub fn get(&self, _key: &str) {
        //attempt get
        //miss None
        //get
        // if ttl < None
        //res
    }
    pub fn set(&mut self, db_value: DBValue) {
        let exists = self.get_key_and_hydrate(&db_value.coords.purl);
        match exists {
            // Is the key in the DB?
            Some(mut db_value) => {
                // Is it expired?
                if db_value.ttl < Utc::now() {
                    // Remove and update key. Ok can be true or false, if the rem failed.
                    let res: Result<_, PickleError> = match self.db {
                        Some(ref mut db) => db.rem(&db_value.coords.purl),
                        None => Ok(false),
                    };
                    match res {
                        Ok(true) => {
                            db_value.ttl = Utc::now();
                            {
                                let _res: Result<_, PickleError> = match self.db.as_mut() {
                                    Some(db) => db.set(&db_value.coords.purl, &db_value),
                                    None => return,
                                };
                            }
                            return;
                        }
                        Ok(false) => return,
                        Err(_) => return,
                    }
                }
            }
            // Otherwise, do set
            None => {
                let _res: Result<_, PickleError> = match self.db.as_mut() {
                    Some(db) => db.set(&db_value.coords.purl, &db_value),
                    None => return,
                };
                return;
            }
        }
    }

    fn get_key_and_hydrate(&mut self, key: &str) -> Option<DBValue> {
        let val: Option<DBValue> = self.db.as_ref().unwrap().get(key);
        val
    }

    fn get_database_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "{}/{}/{}/{}",
            std::env::var("HOME").unwrap(),
            OSSINDEX_DIRNAME,
            self.options.db_dir,
            self.options.db_name
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_cache() {
        let cache: Cache = Cache::new(Options {
            db_dir: "dbdir".to_string(),
            db_name: "dbname".to_string(),
            ttl: 60 * 60 * &12,
        });
        let db_path: String = format!(
            "{}/{}/{}/{}",
            std::env::var("HOME").unwrap(),
            OSSINDEX_DIRNAME,
            "dbdir",
            "dbname"
        )
        .to_string();
        assert_eq!(
            cache
                .get_database_path()
                .into_os_string()
                .into_string()
                .unwrap(),
            db_path.to_string()
        );
    }
}
