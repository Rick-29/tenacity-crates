use anyhow::anyhow;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, Watcher};
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{debug, error};

// pub struct NotificationWrapper<T> {
//     pub inner: Arc<Mutex<T>>
// }

// pub trait Notification {
//     fn init(&self) -> anyhow::Result<ReadDirectoryChangesWatcher>;
// }

pub trait Load: Default + Send + Debug {
    fn load() -> anyhow::Result<Self>;
}

// impl<T> Notification for NotificationWrapper<T>
//     where T: Load + Send + Debug + 'static
// {
//     fn init(&self) -> anyhow::Result<ReadDirectoryChangesWatcher> {
//         initialize(self.inner.clone())
//     }
// }

pub fn initialize<T: Load + 'static>(target: Arc<Mutex<T>>) -> anyhow::Result<RecommendedWatcher> {
    let t_clone = Arc::clone(&target);
    RecommendedWatcher::new(
        move |res: notify::Result<Event>| match res {
            Ok(event) => {
                if event.kind.is_modify() {
                    match T::load() {
                        Ok(config) => {
                            *t_clone.lock().unwrap() = config;
                            debug!(target: "Notify", "New configuration loaded, {:?}", t_clone);
                        }
                        Err(e) => error!(target: "Notify", "Error loading config, {}", e),
                    }
                }
            }
            Err(e) => error!(target: "Notify", "Error processing notify event: {}", e),
        },
        NotifyConfig::default()
            .with_poll_interval(Duration::from_secs(2))
            .with_compare_contents(true),
    )
    .map_err(|e| anyhow!("Error creating notification watcher, {e}"))
}
