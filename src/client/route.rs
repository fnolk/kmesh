use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::{
    protocol::{RouteMode, TransportInfo},
    transport::{QadPlan, RelayChoice},
};

pub(super) const SSH_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const DIRECT_PUNCH_TIMEOUT: Duration = Duration::from_secs(8);
pub(super) const PRIVATE_DIRECT_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const PUBLIC_DIRECT_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const PRIVATE_RELAY_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) fn attempt_timeout(route_mode: RouteMode) -> Duration {
    match route_mode {
        RouteMode::PrivateDirect => PRIVATE_DIRECT_TIMEOUT,
        RouteMode::PublicDirect => PUBLIC_DIRECT_TIMEOUT,
        RouteMode::PrivateRelay => PRIVATE_RELAY_TIMEOUT,
    }
}

pub(super) struct RouteTransportPlan {
    pub(super) relay_choice: RelayChoice,
    pub(super) qad_plan: Option<QadPlan>,
}

pub(super) fn route_transport_plan(
    route_mode: RouteMode,
    info: &TransportInfo,
    issuer: &str,
) -> Result<RouteTransportPlan> {
    match route_mode {
        RouteMode::PrivateDirect => {
            let (server_url, udp_port) = private_relay(info, issuer)?;
            Ok(RouteTransportPlan {
                relay_choice: RelayChoice::DirectOnly,
                qad_plan: Some(QadPlan::PrivateAndOfficial {
                    server_url,
                    udp_port,
                }),
            })
        }
        RouteMode::PublicDirect => Ok(RouteTransportPlan {
            relay_choice: RelayChoice::DirectOnly,
            qad_plan: Some(QadPlan::OfficialDefault),
        }),
        RouteMode::PrivateRelay => {
            let (url, quic_port) = private_relay(info, issuer)?;
            Ok(RouteTransportPlan {
                relay_choice: RelayChoice::Private { url, quic_port },
                qad_plan: None,
            })
        }
    }
}

fn private_relay(info: &TransportInfo, issuer: &str) -> Result<(reqwest::Url, u16)> {
    let url = reqwest::Url::parse(
        info.private_relay_url
            .as_deref()
            .context("private relay route requested without a configured private relay")?,
    )
    .context("parse private Iroh relay URL")?;
    let control_origin =
        reqwest::Url::parse(issuer).context("parse configured kmesh server URL")?;
    ensure!(
        url == control_origin,
        "private Iroh relay URL differs from the configured kmesh server"
    );
    Ok((url, info.qad_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(private_relay_url: Option<&str>) -> TransportInfo {
        TransportInfo {
            private_relay_url: private_relay_url.map(str::to_owned),
            qad_port: 3478,
        }
    }

    #[test]
    fn direct_routes_have_no_data_relay_and_distinct_qad_plans() {
        let private = route_transport_plan(
            RouteMode::PrivateDirect,
            &info(Some("https://kmesh.test:9443")),
            "https://kmesh.test:9443",
        )
        .unwrap();
        assert_eq!(private.relay_choice, RelayChoice::DirectOnly);
        assert_eq!(
            private.qad_plan,
            Some(QadPlan::PrivateAndOfficial {
                server_url: "https://kmesh.test:9443".parse().unwrap(),
                udp_port: 3478,
            })
        );

        let public = route_transport_plan(
            RouteMode::PublicDirect,
            &info(None),
            "https://kmesh.test:9443",
        )
        .unwrap();
        assert_eq!(public.relay_choice, RelayChoice::DirectOnly);
        assert_eq!(public.qad_plan, Some(QadPlan::OfficialDefault));
    }

    #[test]
    fn private_relay_route_has_only_the_configured_relay_and_skips_qad() {
        let plan = route_transport_plan(
            RouteMode::PrivateRelay,
            &info(Some("https://kmesh.test:9443")),
            "https://kmesh.test:9443",
        )
        .unwrap();
        assert_eq!(
            plan.relay_choice,
            RelayChoice::Private {
                url: "https://kmesh.test:9443".parse().unwrap(),
                quic_port: 3478,
            }
        );
        assert_eq!(plan.qad_plan, None);
    }

    #[test]
    fn private_routes_require_the_authenticated_control_origin() {
        assert!(
            route_transport_plan(
                RouteMode::PrivateDirect,
                &info(Some("https://other.example:9443")),
                "https://kmesh.test:9443",
            )
            .is_err()
        );
        assert!(
            route_transport_plan(
                RouteMode::PrivateRelay,
                &info(None),
                "https://kmesh.test:9443",
            )
            .is_err()
        );
    }
}
