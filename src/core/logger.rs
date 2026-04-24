use crate::core::{db::Database, models::NewAttackLog};
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Clone)]
pub struct AttackLogger {
    sender: mpsc::Sender<NewAttackLog>,
}

impl AttackLogger {
    pub fn start(database: Database) -> Self {
        let (sender, mut receiver) = mpsc::channel::<NewAttackLog>(256);

        tokio::spawn(async move {
            while let Some(log_entry) = receiver.recv().await {
                if let Err(error) = database.create_attack_log(&log_entry).await {
                    error!(error = %error, "failed to persist attack log");
                } else {
                    info!(
                        source_ip = %log_entry.source_ip,
                        action_taken = %log_entry.action_taken,
                        matched_rule_id = ?log_entry.matched_rule_id,
                        "attack log persisted"
                    );
                }
            }
        });

        Self { sender }
    }

    pub async fn enqueue(&self, log_entry: NewAttackLog) {
        if let Err(error) = self.sender.send(log_entry).await {
            error!(error = %error, "failed to enqueue attack log");
        }
    }
}
