//! Fake `etd_app::ProfileStore`. Owned by A1.
use etd_app::{Profile, ProfileError, ProfileStore};
use std::{collections::VecDeque, sync::Mutex};

#[derive(Default)]
struct Inner {
    profiles: Vec<Profile>,
    load_error: Option<ProfileError>,
    save_errors: VecDeque<ProfileError>,
    saved: Vec<Vec<Profile>>,
}

/// In-memory library with injectable failures. It records exactly what it
/// is given.
#[derive(Default)]
pub struct FakeProfileStore(Mutex<Inner>);

impl FakeProfileStore {
    pub fn new(profiles: Vec<Profile>) -> Self {
        let store = Self::default();
        store.0.lock().expect("fake profile lock").profiles = profiles;
        store
    }

    pub fn fail_load(&self, error: ProfileError) {
        self.0.lock().expect("fake profile lock").load_error = Some(error);
    }

    /// The next save fails and keeps the previous library.
    pub fn fail_save(&self, error: ProfileError) {
        self.0
            .lock()
            .expect("fake profile lock")
            .save_errors
            .push_back(error);
    }

    pub fn profiles(&self) -> Vec<Profile> {
        self.0.lock().expect("fake profile lock").profiles.clone()
    }

    /// Every library successfully saved, oldest first.
    pub fn saved(&self) -> Vec<Vec<Profile>> {
        self.0.lock().expect("fake profile lock").saved.clone()
    }
}

impl ProfileStore for FakeProfileStore {
    fn load(&self) -> Result<Vec<Profile>, ProfileError> {
        let inner = self.0.lock().expect("fake profile lock");
        match &inner.load_error {
            Some(error) => Err(error.clone()),
            None => Ok(inner.profiles.clone()),
        }
    }

    fn save(&self, profiles: &[Profile]) -> Result<(), ProfileError> {
        let mut inner = self.0.lock().expect("fake profile lock");
        if let Some(error) = inner.save_errors.pop_front() {
            return Err(error);
        }
        inner.profiles = profiles.to_vec();
        inner.saved.push(profiles.to_vec());
        Ok(())
    }
}
