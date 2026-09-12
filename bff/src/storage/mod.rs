use crate::model::session::SessionData;

pub(crate) mod in_memory;

pub(crate) trait SessionStorage {
    async fn save_session(&mut self, session_id: String, data: SessionData);
    async fn get_session(&self, session_id: &str) -> Option<SessionData>;
}
