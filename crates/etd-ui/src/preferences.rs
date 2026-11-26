//! Local UI-only preferences. The persisted schema contains no host or
//! network data; it lives beside, not inside, the profile library.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ThemePreference {
    #[default]
    FollowSystem,
    Light,
    Dark,
}

impl ThemePreference {
    pub(crate) fn is_dark(self, system_dark: bool) -> bool {
        match self {
            Self::FollowSystem => system_dark,
            Self::Light => false,
            Self::Dark => true,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::FollowSystem => "Follow system",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct UiPreferences {
    theme: ThemePreference,
}

pub(crate) struct UiPreferencesStore {
    path: PathBuf,
}

impl UiPreferencesStore {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn default_store() -> Option<Self> {
        etd_app::profiles_toml::TomlProfileStore::default_path()
            .map(|path| Self::new(path.with_file_name("ui-preferences.json")))
    }

    pub(crate) fn load(&self) -> io::Result<ThemePreference> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice::<UiPreferences>(&bytes)
                .map(|prefs| prefs.theme)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UI preferences")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ThemePreference::default()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn save(&self, theme: ThemePreference) -> io::Result<()> {
        let directory = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(directory)?;
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer_pretty(&mut file, &UiPreferences { theme })?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|error| error.error)?;
        #[cfg(unix)]
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_preferences_follow_system_and_every_choice_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui").join("ui-preferences.json");
        let store = UiPreferencesStore::new(path.clone());
        assert_eq!(store.load().unwrap(), ThemePreference::FollowSystem);
        assert!(!path.exists());
        for (theme, encoded) in [
            (ThemePreference::Light, "light"),
            (ThemePreference::Dark, "dark"),
            (ThemePreference::FollowSystem, "follow-system"),
        ] {
            store.save(theme).unwrap();
            let reopened = UiPreferencesStore::new(path.clone());
            assert_eq!(reopened.load().unwrap(), theme);
            let json: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(json, serde_json::json!({"theme": encoded}));
        }
    }

    #[test]
    fn bad_preferences_report_error_and_missing_field_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui-preferences.json");
        let store = UiPreferencesStore::new(path.clone());
        fs::write(&path, b"not json").unwrap();
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        fs::write(&path, b"{}").unwrap();
        assert_eq!(store.load().unwrap(), ThemePreference::FollowSystem);
    }
}
