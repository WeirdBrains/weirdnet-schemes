//! OS handler registration for an app's own schemes.
//!
//! These build what each platform needs; apps put them in their packaging (Info.plist,
//! AndroidManifest.xml) or apply them at install or first run (Linux, Windows; user level,
//! no admin). `weirdnet://` is refused everywhere: it is never registered with the OS.

use crate::error::{Error, Result};
use crate::names;

fn check(schemes: &[&str]) -> Result<()> {
    if schemes.is_empty() {
        return Err(Error::Invalid("no schemes".into()));
    }
    for s in schemes {
        names::check_scheme(s)?;
    }
    Ok(())
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A freedesktop `.desktop` entry handling `schemes` (`Exec=<exec> %u`).
pub fn linux_desktop_entry(name: &str, exec: &str, schemes: &[&str]) -> Result<String> {
    check(schemes)?;
    if name.contains('\n') || exec.contains('\n') {
        return Err(Error::Invalid("newline in the desktop entry".into()));
    }
    let mime: String = schemes.iter().map(|s| format!("x-scheme-handler/{s};")).collect();
    Ok(format!("[Desktop Entry]\nType=Application\nName={name}\nExec={exec} %u\nTerminal=false\nMimeType={mime}\n"))
}

/// The `xdg-mime` commands making `desktop_id` (such as `org.weirdbrains.morph.desktop`) the
/// default handler for `schemes`.
pub fn linux_default_commands(desktop_id: &str, schemes: &[&str]) -> Result<Vec<Vec<String>>> {
    check(schemes)?;
    Ok(schemes.iter().map(|s| vec!["xdg-mime".into(), "default".into(), desktop_id.into(), format!("x-scheme-handler/{s}")]).collect())
}

/// Writes the desktop entry to `<data_home>/applications/<desktop_id>` (user level; the
/// data home is usually `$XDG_DATA_HOME` or `~/.local/share`).
pub fn linux_install(data_home: &std::path::Path, desktop_id: &str, entry: &str) -> Result<std::path::PathBuf> {
    if desktop_id.contains('/') || !desktop_id.ends_with(".desktop") {
        return Err(Error::Invalid("bad desktop id".into()));
    }
    let dir = data_home.join("applications");
    std::fs::create_dir_all(&dir).map_err(|e| Error::Invalid(e.to_string()))?;
    let path = dir.join(desktop_id);
    std::fs::write(&path, entry).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(path)
}

/// Runs the [`linux_default_commands`] (the user's `mimeapps.list` changes). Returns false
/// if `xdg-mime` is missing or one failed.
pub fn linux_set_default(desktop_id: &str, schemes: &[&str]) -> Result<bool> {
    let mut ok = true;
    for c in linux_default_commands(desktop_id, schemes)? {
        match std::process::Command::new(&c[0]).args(&c[1..]).status() {
            Ok(s) if s.success() => {}
            _ => ok = false,
        }
    }
    Ok(ok)
}

/// One registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    /// The key under `HKEY_CURRENT_USER`.
    pub key: String,
    /// The value name (empty for the default value).
    pub name: String,
    /// The string data.
    pub data: String,
}

/// The per-user registry values (`HKCU\Software\Classes\<scheme>`) handling `schemes` with
/// `exe "%1"`.
pub fn windows_registry(app_name: &str, exe: &str, schemes: &[&str]) -> Result<Vec<RegValue>> {
    check(schemes)?;
    let mut v = Vec::new();
    for s in schemes {
        let base = format!(r"Software\Classes\{s}");
        v.push(RegValue { key: base.clone(), name: String::new(), data: format!("URL:{app_name}") });
        v.push(RegValue { key: base.clone(), name: "URL Protocol".into(), data: String::new() });
        v.push(RegValue { key: format!(r"{base}\shell\open\command"), name: String::new(), data: format!("\"{exe}\" \"%1\"") });
    }
    Ok(v)
}

/// The same as a `.reg` file.
pub fn windows_reg_file(app_name: &str, exe: &str, schemes: &[&str]) -> Result<String> {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::from("Windows Registry Editor Version 5.00\r\n");
    let mut last = String::new();
    for r in windows_registry(app_name, exe, schemes)? {
        if r.key != last {
            out.push_str(&format!("\r\n[HKEY_CURRENT_USER\\{}]\r\n", r.key));
            last = r.key.clone();
        }
        let name = if r.name.is_empty() { "@".to_string() } else { format!("\"{}\"", esc(&r.name)) };
        out.push_str(&format!("{name}=\"{}\"\r\n", esc(&r.data)));
    }
    Ok(out)
}

/// The `CFBundleURLTypes` entry for an Info.plist (macOS and iOS).
pub fn apple_url_types(bundle_id: &str, schemes: &[&str]) -> Result<String> {
    check(schemes)?;
    let list: String = schemes.iter().map(|s| format!("\t\t\t\t<string>{}</string>\n", xml(s))).collect();
    Ok(format!(
        "\t<key>CFBundleURLTypes</key>\n\t<array>\n\t\t<dict>\n\t\t\t<key>CFBundleURLName</key>\n\t\t\t<string>{}</string>\n\t\t\t<key>CFBundleURLSchemes</key>\n\t\t\t<array>\n{list}\t\t\t</array>\n\t\t</dict>\n\t</array>\n",
        xml(bundle_id)
    ))
}

/// The `<intent-filter>` for an Android activity.
pub fn android_intent_filter(schemes: &[&str]) -> Result<String> {
    check(schemes)?;
    let data: String = schemes.iter().map(|s| format!("    <data android:scheme=\"{}\" />\n", xml(s))).collect();
    Ok(format!(
        "<intent-filter>\n    <action android:name=\"android.intent.action.VIEW\" />\n    <category android:name=\"android.intent.category.DEFAULT\" />\n    <category android:name=\"android.intent.category.BROWSABLE\" />\n{data}</intent-filter>\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifacts() {
        let e = linux_desktop_entry("Morph", "/usr/bin/morph", &["weirdnet-morph"]).unwrap();
        assert!(e.contains("MimeType=x-scheme-handler/weirdnet-morph;\n") && e.contains("Exec=/usr/bin/morph %u\n"));
        assert_eq!(linux_default_commands("org.weirdbrains.morph.desktop", &["weirdnet-morph"]).unwrap()[0][3], "x-scheme-handler/weirdnet-morph");
        let r = windows_reg_file("Morph", r"C:\Program Files\Morph\morph.exe", &["weirdnet-morph"]).unwrap();
        assert!(r.contains("[HKEY_CURRENT_USER\\Software\\Classes\\weirdnet-morph]\r\n@=\"URL:Morph\"\r\n\"URL Protocol\"=\"\""));
        assert!(r.contains("[HKEY_CURRENT_USER\\Software\\Classes\\weirdnet-morph\\shell\\open\\command]\r\n@=\"\\\"C:\\\\Program Files\\\\Morph\\\\morph.exe\\\" \\\"%1\\\"\""));
        assert!(apple_url_types("org.weirdbrains.morph", &["weirdnet-morph"]).unwrap().contains("<string>weirdnet-morph</string>"));
        assert!(android_intent_filter(&["weirdnet-morph"]).unwrap().contains("android:scheme=\"weirdnet-morph\""));
        // weirdnet:// is never registered.
        assert!(linux_desktop_entry("x", "x", &["weirdnet"]).is_err());
        assert!(windows_registry("x", "x", &["weirdnet-morph", "weirdnet"]).is_err());
        assert!(apple_url_types("x", &["weirdnet"]).is_err());
        assert!(android_intent_filter(&["weirdnet"]).is_err());
        assert!(android_intent_filter(&[]).is_err());
    }

    #[test]
    fn linux_install_writes_the_entry() {
        let d = tempfile::tempdir().unwrap();
        let e = linux_desktop_entry("Morph", "/usr/bin/morph", &["weirdnet-morph"]).unwrap();
        let p = linux_install(d.path(), "org.weirdbrains.morph.desktop", &e).unwrap();
        assert_eq!(p, d.path().join("applications/org.weirdbrains.morph.desktop"));
        assert_eq!(std::fs::read_to_string(d.path().join("applications/org.weirdbrains.morph.desktop")).unwrap(), e);
        assert!(linux_install(d.path(), "../x.desktop", &e).is_err());
        assert!(linux_set_default("x.desktop", &["weirdnet"]).is_err());
    }
}
