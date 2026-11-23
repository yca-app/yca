//! Looking for a newer release of the app, and putting it in place of this
//! one.
//!
//! Only a released app does this. Where to ask, and the key the answer has
//! to be signed with, are added to the app's configuration when a release
//! is built (see `scripts/release.sh`). An app built from source has
//! neither: it makes no connection of its own and says that it cannot
//! update itself.
//!
//! Nothing is fetched or installed unasked. The window asks whether there
//! is a newer version, and a person says that it is to be installed. What
//! was downloaded is checked against the key built into this app before
//! any of it is used, and the app that is running stays where it is until
//! the new one is in its place.

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, MenuItemKind};
use tauri::{App, AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::{KeyLock, timestamp};

/// Sent to the window while a new version comes in: how much of it is
/// here, and once it is all here, that it is being put in place.
const PROGRESS_EVENT: &str = "yca://update-progress";

/// Sent to the window when "Check for Updates…" is chosen in the menu.
const ASKED_EVENT: &str = "yca://check-for-updates";

const MENU_ITEM: &str = "check-for-updates";

/// How long the question whether there is a newer version may take.
const PATIENCE: Duration = Duration::from_secs(20);

/// The newer version that was found last, kept for when it is installed:
/// what a person agreed to is then what they get.
#[derive(Default)]
pub(crate) struct Found(Mutex<Option<Update>>);

/// Whether this app was built to update itself.
fn enabled(app: &AppHandle) -> bool {
    app.config().plugins.0.contains_key("updater")
}

/// Sets the updater up in an app that was built with one, and puts
/// "Check for Updates…" into the menu, under About.
pub(crate) fn setup(app: &App) -> tauri::Result<()> {
    app.manage(Found::default());
    if !enabled(app.handle()) {
        return Ok(());
    }
    app.handle()
        .plugin(tauri_plugin_updater::Builder::new().build())?;

    let menu = Menu::default(app.handle())?;
    if let Some(MenuItemKind::Submenu(of_the_app)) = menu.items()?.into_iter().next() {
        let item = MenuItem::with_id(
            app.handle(),
            MENU_ITEM,
            "Check for Updates…",
            true,
            None::<&str>,
        )?;
        of_the_app.insert(&item, 1)?;
    }
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        if event.id() == MENU_ITEM {
            let _ = app.emit(ASKED_EVENT, ());
        }
    });
    Ok(())
}

/// What the window is told about updates before it asks for one.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    /// This app can look for a newer version and install it.
    available: bool,
    /// The version that is running.
    version: String,
}

#[tauri::command]
pub fn update_status(app: AppHandle) -> UpdateStatus {
    UpdateStatus {
        available: enabled(&app),
        version: app.package_info().version.to_string(),
    }
}

/// A newer version than the one that is running.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewVersion {
    version: String,
    /// What changed, as the release says it.
    notes: Option<String>,
    /// When it was released.
    date: Option<String>,
}

/// Asks whether there is a newer version. Makes one request, to where the
/// releases are published, and changes nothing.
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<Option<NewVersion>, String> {
    if !enabled(&app) {
        return Err("this app was not built to update itself".to_owned());
    }
    let update = app
        .updater_builder()
        .timeout(PATIENCE)
        .build()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?;

    let found = update.as_ref().map(|update| NewVersion {
        version: update.version.clone(),
        notes: update.body.clone().filter(|notes| !notes.trim().is_empty()),
        date: update.date.map(timestamp),
    });
    *app.state::<Found>()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = update;
    Ok(found)
}

/// How far a download has come.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    /// Bytes that are here.
    downloaded: u64,
    /// Bytes in all, if the server said.
    total: Option<u64>,
    /// Everything is here and checked, and is being put in place.
    installing: bool,
}

/// Downloads the version that was found, checks its signature, puts it in
/// place of this app and starts it. `version` is the one the person was
/// shown: nothing else is installed in its name.
///
/// Does not come back when it works: the app is started anew.
#[tauri::command]
pub async fn install_update(app: AppHandle, version: String) -> Result<(), String> {
    let update = app
        .state::<Found>()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .filter(|update| update.version == version)
        .ok_or_else(|| "that version is not the one that was found; look again".to_owned())?;

    let mut downloaded = 0;
    let progress = app.clone();
    let finished = app.clone();
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = progress.emit(
                    PROGRESS_EVENT,
                    Progress {
                        downloaded,
                        total,
                        installing: false,
                    },
                );
            },
            move || {
                let _ = finished.emit(
                    PROGRESS_EVENT,
                    Progress {
                        downloaded: 0,
                        total: None,
                        installing: true,
                    },
                );
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    // The new app is in place. This one makes way for it, once nothing is
    // talking to a YubiKey any more.
    let lock = app.state::<KeyLock>();
    let _idle = lock.wait();
    app.restart();
}
