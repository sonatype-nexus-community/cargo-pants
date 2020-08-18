use std::time::Duration;
use std::path::{ PathBuf };
use crate::{
    types::OSSINDEX_DIRNAME,
    coordinate::Coordinate,
};
const DBNAME: &str = ".cargo-pantsdb";

pub struct Options  {
    db_dir: String,
    db_name: String,
    ttl: Duration
}
pub struct Cache {
    options: Options,
}

pub struct DBValue {
    coordinates: Coordinate,
    ttl: u64
}

impl Cache {
    pub fn get_database_path(&self) -> PathBuf {
        PathBuf::from(
            format!("{}/{}/{}/{}",
                std::env::var("HOME").unwrap(),
                OSSINDEX_DIRNAME,
                self.options.db_dir,
                self.options.db_name
            )
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_cache() {
        let cache: Cache = Cache {
            options: Options {
                db_dir: "dbdir".to_string(),
                db_name: "dbname".to_string(),
                ttl: Duration::from_secs(5)
            }
        };
        let db_path: String = format!("{}/{}/{}/{}",
            std::env::var("HOME").unwrap(),
            OSSINDEX_DIRNAME,
            "dbdir",
            "dbname"
        ).to_string();
        assert_eq!(cache.get_database_path().into_os_string().into_string().unwrap(),  db_path.to_string());
    }
}