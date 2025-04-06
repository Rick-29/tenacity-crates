use toasty::stmt::Id;

#[derive(Debug)]
#[toasty::model]
pub struct SilenceUser {
    #[key]
    #[auto]
    pub id: Id<Self>,

    #[unique]
    pub tenacity_id: String,

    pub exp_time: i64,

    pub reason: Option<String>,
}
