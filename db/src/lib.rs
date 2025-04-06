pub mod db;

use anyhow::anyhow;
use chrono::{Duration, Utc};
use db::SilenceUser;
use toasty::Db;
// use toasty_sqlite::Sqlite;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct TenacityDB {
    pub db: Option<Db>,
}

impl TenacityDB {
    pub async fn new_memory() -> anyhow::Result<Self> {
        // let schema = toasty::schema::from_file(path)?;
        // let driver = Sqlite::in_memory();
        let db = Db::builder()
            .register::<SilenceUser>()
            .connect("sqlite::memory:")
            .await?;

        db.reset_db().await?;
        Ok(Self { db: Some(db) })
    }

    pub async fn silence(
        &self,
        id: Uuid,
        time: i64,
        reason: Option<String>,
    ) -> anyhow::Result<SilenceUser> {
        let exp_time = (Utc::now() + Duration::seconds(time)).timestamp();
        let user = match self.get_silenced(id).await {
            Ok(mut user) => {
                let mut update = user.update().exp_time(exp_time);
                if let Some(reason) = reason {
                    update = update.reason(reason);
                }
                update.exec(self.db()?).await?;
                user
            }
            Err(_) => {
                let mut user = SilenceUser::create()
                    .tenacity_id(id.to_string())
                    .exp_time(exp_time);
                if let Some(reason) = reason {
                    user = user.reason(reason);
                }
                user.exec(self.db()?).await?
            }
        };
        Ok(user)
    }

    pub async fn unsilence(&self, id: Uuid) -> anyhow::Result<bool> {
        match self.get_silenced(id).await {
            Ok(user) => {
                user.delete(self.db()?).await?;
                Ok(true)
            }
            Err(e) => {
                info!(target: "DbUnsilence", "User not in database, {e}");
                Ok(false)
            }
        }
    }

    pub async fn is_silenced(&self, id: Uuid) -> anyhow::Result<bool> {
        let user = SilenceUser::get_by_tenacity_id(self.db()?, id.to_string()).await?;
        if user.exp_time > Utc::now().timestamp() {
            Ok(true)
        } else {
            user.delete(self.db()?).await?;
            Ok(false)
        }
    }

    pub async fn get_silenced(&self, id: Uuid) -> anyhow::Result<SilenceUser> {
        SilenceUser::get_by_tenacity_id(self.db()?, id.to_string()).await
    }

    fn db(&self) -> anyhow::Result<&Db> {
        if let Some(db) = &self.db {
            Ok(db)
        } else {
            Err(anyhow!("Error, db is not available!"))
        }
    }
}

#[cfg(test)]
mod tests {
    // use super::*;

    // // #[tokio::test]
    // // async fn test_create_user() -> Result<(), Box<dyn std::error::Error>> {
    // //     let schema_file = std::env::current_dir().unwrap().join("schema/user.toasty");
    // //     let schema = toasty::schema::from_file(schema_file).unwrap();

    // //     println!("{schema:#?}");

    // //     // Use the in-memory sqlite driver
    // //     let driver = Sqlite::in_memory();

    // //     let db = Db::new(schema, driver).await;
    // //     // For now, reset!s
    // //     db.reset_db().await.unwrap();

    // //     let user = db::SilenceUser::create()
    // //         .tenacity_id(uuid::Uuid::new_v4().to_string())
    // //         .exp_time(100)
    // //         .exec(&db)
    // //         .await?;
    // //     dbg!(&user);

    // //     Ok(())
    // // }
}
