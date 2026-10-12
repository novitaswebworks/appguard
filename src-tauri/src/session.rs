use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    pub bundle_id: String,
    pub name: String,
    pub request_id: u64,
    #[serde(skip)]
    pub window: Option<String>,
}

#[derive(Default)]
pub struct Challenge {
    target: Option<Target>,
    ticket: Option<(u64, Instant)>,
    generation: u64,
}

impl Challenge {
    pub fn set(&mut self, bundle_id: String, name: String, window: Option<String>) -> Target {
        if let Some(target) = &self.target {
            if target.bundle_id == bundle_id && target.window == window {
                return target.clone();
            }
        }
        self.generation = self.generation.wrapping_add(1);
        let target = Target {
            bundle_id,
            name,
            request_id: self.generation,
            window,
        };
        self.target = Some(target.clone());
        self.ticket = None;
        target
    }

    pub fn get(&self) -> Option<Target> {
        self.target.clone()
    }

    pub fn validate(&self, id: &str, request: u64) -> Result<Target, String> {
        self.target
            .as_ref()
            .filter(|target| target.bundle_id == id && target.request_id == request)
            .cloned()
            .ok_or_else(|| "Authentication target changed; try again".into())
    }

    pub fn authorize(&mut self, target: &Target) -> Result<(), String> {
        if self.target.as_ref() != Some(target) {
            return Err("Authentication target changed; try again".into());
        }
        self.ticket = Some((target.request_id, Instant::now()));
        Ok(())
    }

    pub fn consume(&mut self, id: &str, request: u64) -> Result<Target, String> {
        let target = self.validate(id, request)?;
        match self.ticket.take() {
            Some((issued_for, time))
                if issued_for == request && time.elapsed() < Duration::from_secs(15) =>
            {
                self.target = None;
                Ok(target)
            }
            _ => Err("Authenticate this application before unlocking it".into()),
        }
    }

    pub fn cancel(&mut self, id: &str, request: u64) -> Result<Target, String> {
        let target = self.validate(id, request)?;
        self.clear();
        Ok(target)
    }

    pub fn clear(&mut self) {
        self.target = None;
        self.ticket = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tickets_are_single_use_and_bound_to_window_generation() {
        let mut challenge = Challenge::default();
        let first = challenge.set("app".into(), "App".into(), Some("1".into()));
        challenge.authorize(&first).unwrap();
        assert!(challenge.consume("other", first.request_id).is_err());
        let second = challenge.set("app".into(), "App".into(), Some("2".into()));
        assert!(challenge.authorize(&first).is_err());
        assert!(challenge.consume("app", second.request_id).is_err());
        challenge.authorize(&second).unwrap();
        assert!(challenge.consume("app", second.request_id).is_ok());
        assert!(challenge.consume("app", second.request_id).is_err());
    }
    #[test]
    fn clearing_a_challenge_revokes_authorization() {
        let mut challenge = Challenge::default();
        let target = challenge.set("app".into(), "App".into(), None);
        challenge.authorize(&target).unwrap();
        challenge.clear();
        assert!(challenge.consume("app", target.request_id).is_err());
    }
}
