//! Serialize service arguments as data, including paths with spaces/metacharacters.
#[cfg(any(target_os = "linux", test))]
pub fn systemd_executable(path: &str) -> Result<String, String> {
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(
            "Service executable must be an absolute path without control characters".into(),
        );
    }
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

#[cfg(any(target_os = "macos", test))]
pub fn launch_agent(path: &str) -> Result<Vec<u8>, String> {
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(
            "Service executable must be an absolute path without control characters".into(),
        );
    }
    use plist::Value;
    let mut values = plist::Dictionary::new();
    values.insert(
        "Label".into(),
        Value::String("com.appguard.watchdog".into()),
    );
    values.insert(
        "AssociatedBundleIdentifiers".into(),
        Value::Array(vec![Value::String("com.appguard.desktop".into())]),
    );
    values.insert(
        "ProgramArguments".into(),
        Value::Array(vec![
            Value::String(path.into()),
            Value::String("--minimized".into()),
        ]),
    );
    values.insert("KeepAlive".into(), Value::Boolean(true));
    values.insert("RunAtLoad".into(), Value::Boolean(false));
    values.insert("ProcessType".into(), Value::String("Interactive".into()));
    let mut bytes = Vec::new();
    Value::Dictionary(values)
        .to_writer_xml(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_agent_roundtrips_paths_that_would_break_raw_xml() {
        let path = "/Applications/Work & <Personal>/AppGuard.app/Contents/MacOS/appguard";
        let bytes = launch_agent(path).unwrap();
        let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).unwrap();
        let args = value.as_dictionary().unwrap()["ProgramArguments"]
            .as_array()
            .unwrap();
        assert_eq!(args[0].as_string(), Some(path));
        assert_eq!(args[1].as_string(), Some("--minimized"));
    }
    #[test]
    fn systemd_paths_are_quoted_and_cannot_inject_directives() {
        assert_eq!(
            systemd_executable("/opt/My App/%name/$file\"\\guard").unwrap(),
            "\"/opt/My App/%%name/$$file\\\"\\\\guard\""
        );
        assert!(systemd_executable("/opt/app\nUser=root").is_err());
        assert!(systemd_executable("relative/path").is_err());
    }
}
