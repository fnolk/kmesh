use anyhow::{Context, Result};

use crate::{
    client::route::route_transport_plan,
    protocol::{RouteMode, TransportInfo},
    transport::{HandoffOptions, IrohEndpointOptions},
};

use super::ClientContext;

pub(super) fn endpoint_options(
    context: &ClientContext,
    info: &TransportInfo,
    route_mode: RouteMode,
    handoff: Option<HandoffOptions>,
) -> Result<IrohEndpointOptions> {
    let plan = route_transport_plan(route_mode, info, context.api.issuer())
        .context("build agent route transport plan")?;
    Ok(IrohEndpointOptions {
        relay_choice: plan.relay_choice,
        handoff,
    })
}
