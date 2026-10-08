use semver::Version;

pub const VERSION: &str = crate::build::PKG_VERSION;
pub const VERSION_HEADER: &str = "x-kmesh-version";
pub const SOURCE_REF: &str = if !crate::build::BRANCH.is_empty() {
    crate::build::BRANCH
} else if !crate::build::TAG.is_empty() {
    crate::build::TAG
} else {
    "detached"
};
pub const CLI_LONG_VERSION: &str = shadow_rs::formatcp!(
    "{}\nsource_ref:{}",
    crate::build::CLAP_LONG_VERSION,
    SOURCE_REF
);

pub fn mismatch(client_version: Option<&str>) -> Option<String> {
    let Some(client_version) = client_version else {
        return Some(format!(
            "The client did not identify its kmesh version. The server runs kmesh {VERSION}. Update the client or agent."
        ));
    };
    let client = match Version::parse(client_version) {
        Ok(version) => version,
        Err(_) => {
            return Some(format!(
                "The client sent an invalid kmesh version: {client_version:?}. The server runs kmesh {VERSION}."
            ));
        }
    };
    let server = Version::parse(VERSION).expect("Cargo package version must be valid SemVer");
    if compatible(&client, &server) {
        return None;
    }
    Some(format!(
        "Client kmesh {client} and server kmesh {server} are incompatible. Stable releases must have the same major version. Versions 0.x must also have the same minor version. For prereleases, the major, minor, patch, and prerelease values must match. Update the client or agent."
    ))
}

fn compatible(client: &Version, server: &Version) -> bool {
    if client.major != server.major || (server.major == 0 && client.minor != server.minor) {
        return false;
    }
    if client.pre.is_empty() && server.pre.is_empty() {
        return true;
    }
    client.minor == server.minor && client.patch == server.patch && client.pre == server.pre
}

#[cfg(test)]
mod tests {
    use super::{Version, compatible, mismatch};

    fn version(value: &str) -> Version {
        Version::parse(value).expect("valid test version")
    }

    #[test]
    fn stable_versions_follow_semver_compatibility_by_major() {
        assert!(compatible(&version("1.2.0"), &version("1.9.4")));
        assert!(!compatible(&version("2.0.0"), &version("1.9.4")));
        assert!(compatible(&version("0.1.9"), &version("0.1.4")));
        assert!(!compatible(&version("0.2.0"), &version("0.1.4")));
    }

    #[test]
    fn prereleases_require_matching_base_version_and_identifier() {
        assert!(compatible(
            &version("1.0.0-rc.1+client"),
            &version("1.0.0-rc.1+server")
        ));
        assert!(!compatible(&version("1.0.0-rc.2"), &version("1.0.0-rc.1")));
        assert!(!compatible(&version("1.2.0-rc.1"), &version("1.1.0-rc.1")));
        assert!(!compatible(&version("1.0.0"), &version("1.0.0-rc.1")));
        assert!(!compatible(&version("0.1.0-rc.1"), &version("0.2.0-rc.1")));
    }

    #[test]
    fn mismatch_reports_missing_and_invalid_versions() {
        assert!(
            mismatch(None)
                .expect("missing version rejected")
                .contains("did not identify")
        );
        assert!(
            mismatch(Some("0.1"))
                .expect("invalid version rejected")
                .contains("invalid kmesh version")
        );
        assert!(mismatch(Some("0.3.1")).is_some());
    }
}
