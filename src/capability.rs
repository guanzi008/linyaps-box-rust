use caps::Capability;

pub(crate) fn parse_index(value: &str) -> Option<u8> {
    let visible = value.split('\0').next().unwrap_or_default();
    let first = visible.as_bytes().first().copied()?;
    if first.is_ascii_digit() {
        let mut bytes = visible.as_bytes().to_vec();
        bytes.push(0);
        let parsed = unsafe {
            libc::strtoul(
                bytes.as_ptr().cast::<libc::c_char>(),
                std::ptr::null_mut(),
                0,
            )
        };
        return (parsed < 64).then_some(parsed as u8);
    }

    visible
        .to_ascii_uppercase()
        .parse::<Capability>()
        .ok()
        .map(|capability| capability.index())
}

pub(crate) fn canonical_name(index: u8) -> Option<String> {
    caps::all()
        .into_iter()
        .find(|capability| capability.index() == index)
        .map(|capability| capability.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_libcap_name_rules() {
        for (value, expected) in [
            ("cap_chown", Some(0)),
            ("CAP_CHOWN", Some(0)),
            ("CaP_ChOwN", Some(0)),
            ("00", Some(0)),
            ("01", Some(1)),
            ("08", Some(0)),
            ("010", Some(8)),
            ("0x10", Some(16)),
            ("42", Some(42)),
            ("63suffix", Some(63)),
            ("chown", None),
            ("CAP_0", None),
            ("64", None),
            ("-1", None),
            ("cap_unknown", None),
        ] {
            assert_eq!(parse_index(value), expected, "{value}");
        }
    }

    #[test]
    fn canonicalizes_kernel_capabilities_only() {
        assert_eq!(canonical_name(0).as_deref(), Some("CAP_CHOWN"));
        assert_eq!(
            canonical_name(40).as_deref(),
            Some("CAP_CHECKPOINT_RESTORE")
        );
        assert_eq!(canonical_name(41), None);
    }
}
