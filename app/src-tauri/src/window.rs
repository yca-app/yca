//! How large the window opens.
//!
//! The configuration gives the window a size that fits a 13" laptop with
//! the Dock showing. A larger screen has room for more, and there the
//! window opens larger, tall enough for the longest dialog to fit without
//! scrolling. The size is worked out afresh on every launch; nothing is
//! remembered.

use tauri::{LogicalPosition, LogicalSize, WebviewWindow};

/// The size in the configuration, in points: what a 13" laptop has room
/// for.
const BASE: (f64, f64) = (1280.0, 800.0);

/// The most the window grows to by itself. Beyond this it would only be
/// emptier.
const MOST: (f64, f64) = (1520.0, 960.0);

/// Room left above and below the window, so that it does not look
/// squeezed between the menu bar and the Dock.
const MARGIN: f64 = 40.0;

/// The size to open with on a screen with this much room, in points; the
/// room is what the menu bar and the Dock leave.
pub(crate) fn opening_size(available: (f64, f64)) -> (f64, f64) {
    let width = (available.0 * 0.6).clamp(BASE.0, MOST.0);
    let height = (available.1 - MARGIN).clamp(BASE.1, MOST.1);
    // A screen smaller than the base size gets what it has.
    (width.min(available.0), height.min(available.1))
}

/// Sizes the window for the screen it is on and shows it. The window
/// starts hidden, so that it does not appear in one size and jump to
/// another.
pub(crate) fn open(window: &WebviewWindow) {
    let monitor = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten());
    if let Some(monitor) = monitor {
        let scale = monitor.scale_factor();
        let area = monitor.work_area();
        let room = (
            f64::from(area.size.width) / scale,
            f64::from(area.size.height) / scale,
        );
        let (width, height) = opening_size(room);
        if (width, height) != BASE {
            // The middle of the room is worked out here: asked to centre
            // itself right after a resize, the window still goes by the
            // size it had. Not being able to resize or move is no reason
            // not to open.
            let left = f64::from(area.position.x) / scale + (room.0 - width) / 2.0;
            let top = f64::from(area.position.y) / scale + (room.1 - height) / 2.0;
            let _ = window.set_size(LogicalSize::new(width, height));
            let _ = window.set_position(LogicalPosition::new(left, top));
        }
    }
    let _ = window.show();
    let _ = window.set_focus();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_laptop_gets_the_base_size_and_a_large_screen_more() {
        // 13" MacBook Air, Dock showing.
        assert_eq!(opening_size((1470.0, 840.0)), (1280.0, 800.0));
        // 14" MacBook Pro: a little taller.
        assert_eq!(opening_size((1512.0, 870.0)), (1280.0, 830.0));
        // 16" MacBook Pro: tall enough for the longest dialog.
        assert_eq!(opening_size((1728.0, 1005.0)), (1280.0, 960.0));
        // A 27" display: wider as well, and no larger than the most.
        assert_eq!(opening_size((2560.0, 1409.0)), (1520.0, 960.0));
        assert_eq!(opening_size((3840.0, 2100.0)), (1520.0, 960.0));
    }

    #[test]
    fn a_screen_smaller_than_the_base_size_is_not_overrun() {
        assert_eq!(opening_size((1152.0, 650.0)), (1152.0, 650.0));
    }
}
