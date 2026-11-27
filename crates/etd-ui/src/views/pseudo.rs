//! A pseudo-locale for the Fluent gallery: when it is on, the labels the
//! gallery's controls show are accented and padded to 140 % of their
//! length, so truncation, overflow and fixed widths show up the way a
//! longer translation would expose them (doc#24's i18n rules). It is off
//! unless the gallery turns it on; the product never does.

use std::cell::Cell;

use gpui_kit::SharedString;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
}

/// Turns the pseudo-locale on or off for this UI thread.
pub fn set(on: bool) {
    ON.with(|flag| flag.set(on));
}

/// Whether the pseudo-locale is on.
pub fn is_on() -> bool {
    ON.with(Cell::get)
}

/// `text` as the pseudo-locale shows it, or unchanged when it is off.
pub fn t(text: impl Into<SharedString>) -> SharedString {
    let text = text.into();
    if is_on() { expand(&text).into() } else { text }
}

/// Accents every ASCII letter and pads to 140 % of the length, inside
/// brackets that show where the string starts and ends.
fn expand(text: &str) -> String {
    const UPPER: [char; 26] = [
        'Å', 'Ɓ', 'Ç', 'Ð', 'Ë', 'Ƒ', 'Ĝ', 'Ĥ', 'Î', 'Ĵ', 'Ķ', 'Ļ', 'Ṁ', 'Ñ', 'Ö', 'Þ', 'Ǫ', 'Ŕ',
        'Š', 'Ŧ', 'Û', 'Ṽ', 'Ŵ', 'Ẋ', 'Ý', 'Ž',
    ];
    const LOWER: [char; 26] = [
        'å', 'ƀ', 'ç', 'ð', 'ë', 'ƒ', 'ĝ', 'ĥ', 'î', 'ĵ', 'ķ', 'ļ', 'ṁ', 'ñ', 'ö', 'þ', 'ǫ', 'ŕ',
        'š', 'ŧ', 'û', 'ṽ', 'ŵ', 'ẋ', 'ý', 'ž',
    ];
    let len = text.chars().count();
    let mut out = String::with_capacity(text.len() * 2 + 4);
    out.push('[');
    for c in text.chars() {
        out.push(match c {
            'A'..='Z' => UPPER[(c as u8 - b'A') as usize],
            'a'..='z' => LOWER[(c as u8 - b'a') as usize],
            other => other,
        });
    }
    // Brackets count towards the 40 %; dots make up the rest.
    let pad = (len * 2).div_ceil(5).saturating_sub(2);
    out.extend(std::iter::repeat_n('·', pad));
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_text_is_accented_and_at_least_forty_percent_longer() {
        set(false);
        assert_eq!(t("Save"), "Save");
        set(true);
        let long = t("Save changes");
        assert!(long.starts_with("[Šåṽë çĥåñĝëš"));
        assert!(long.chars().count() * 10 >= "Save changes".len() * 14);
        set(false);
    }
}
