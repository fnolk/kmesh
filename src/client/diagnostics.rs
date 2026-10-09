use anyhow::{Result, bail};
use serde::Serialize;

use super::{ClientContext, api::ApiFailure, auth, output::cell, proxy};
use crate::protocol::{
    AccessExplanation, AdminOperation, AdminRequest, AdminResponse, MeView, SystemRole,
};

#[derive(Serialize)]
struct Check {
    stage: &'static str,
    status: &'static str,
    detail: String,
    next_action: String,
}

#[derive(Serialize)]
struct Report {
    server: String,
    profile: String,
    client_version: &'static str,
    user: Option<String>,
    platform_role: Option<SystemRole>,
    target: Option<String>,
    checks: Vec<Check>,
}

impl Report {
    fn new(context: &ClientContext, target: Option<String>) -> Self {
        Self {
            server: context.api.issuer().to_owned(),
            profile: context.config.profile.clone(),
            client_version: crate::version::VERSION,
            user: None,
            platform_role: None,
            target,
            checks: Vec::new(),
        }
    }

    fn add(
        &mut self,
        stage: &'static str,
        status: &'static str,
        detail: impl Into<String>,
        next: impl Into<String>,
    ) {
        self.checks.push(Check {
            stage,
            status,
            detail: detail.into(),
            next_action: next.into(),
        });
    }

    fn finish(mut self, json: bool, stages: &[&'static str]) -> Result<()> {
        for stage in stages {
            if !self.checks.iter().any(|check| check.stage == *stage) {
                self.add(
                    stage,
                    "not_checked",
                    "An earlier check failed.",
                    "Correct the failure. Run this command again.",
                );
            }
        }
        self.checks
            .sort_by_key(|check| stages.iter().position(|stage| *stage == check.stage));
        let failed = self.checks.iter().any(|check| check.status == "failed");
        if json {
            println!("{}", serde_json::to_string_pretty(&self)?);
        } else {
            println!(
                "Server: {}\nProfile: {}\nClient version: {}",
                cell(&self.server),
                cell(&self.profile),
                self.client_version
            );
            if let Some(user) = &self.user {
                println!("User: {}", cell(user));
            }
            if let Some(role) = self.platform_role {
                println!("Platform role: {}", role.as_str());
            }
            if let Some(target) = &self.target {
                println!("Target: {}", cell(target));
            }
            for check in &self.checks {
                println!("{}: {}. {}", check.stage, check.status, cell(&check.detail));
                if !check.next_action.is_empty() {
                    println!("Next: {}", cell(&check.next_action));
                }
            }
        }
        if failed {
            bail!("A check failed. Follow the next action in the report.");
        }
        Ok(())
    }
}

fn failure_action(error: &anyhow::Error) -> (&'static str, &'static str) {
    match error.downcast_ref::<ApiFailure>() {
        Some(ApiFailure::IncompatibleVersion(_)) => (
            "The client and server versions are incompatible.",
            "Install compatible client and server versions.",
        ),
        Some(ApiFailure::Network(_)) => (
            "The server connection failed.",
            "Check the server address, HTTPS port, service, and certificates.",
        ),
        Some(ApiFailure::Authentication(_)) => (
            "Server authentication failed.",
            "Check the certificates and saved credentials.",
        ),
        Some(ApiFailure::Server { status: 401, .. }) => (
            "The login is not valid.",
            "Run kmesh login with a valid credential.",
        ),
        Some(ApiFailure::Server { status: 403, .. }) => (
            "Access is not permitted.",
            "Ask an administrator to check your account and access groups.",
        ),
        _ => (
            "The check could not complete.",
            "Check the configuration and credentials. Run kmesh login if necessary.",
        ),
    }
}

async fn identity(context: &ClientContext, report: &mut Report) -> Option<(String, MeView)> {
    match context.api.transport_info().await {
        Ok(info) => {
            report.add("server", "passed", "The HTTPS service responded.", "");
            report.add(
                "version",
                "passed",
                "The server accepted the client version.",
                "",
            );
            report.add(
                "routes",
                "passed",
                if info.private_relay_url.is_some() {
                    "Available routes: PrivateDirect, PublicDirect, PrivateRelay."
                } else {
                    "Available route: PublicDirect. The private relay is disabled."
                },
                "",
            );
        }
        Err(error) => {
            let (detail, next) = failure_action(&error);
            let stage = if matches!(
                error.downcast_ref::<ApiFailure>(),
                Some(ApiFailure::IncompatibleVersion(_))
            ) {
                "version"
            } else {
                "server"
            };
            report.add(stage, "failed", detail, next);
            return None;
        }
    }
    let result = async {
        let token = auth::valid_access_token(context).await?;
        let me = context.api.me(&token).await?;
        Ok::<_, anyhow::Error>((token, me))
    }
    .await;
    match result {
        Ok((token, me)) => {
            report.user = Some(me.user_id.clone());
            report.platform_role = Some(me.system_role);
            report.add(
                "login",
                "passed",
                "The server accepted the current login.",
                "",
            );
            Some((token, me))
        }
        Err(error) => {
            let (detail, next) = failure_action(&error);
            report.add("login", "failed", detail, next);
            None
        }
    }
}

pub(super) async fn status(context: &ClientContext, json: bool) -> Result<()> {
    let mut report = Report::new(context, None);
    identity(context, &mut report).await;
    report.finish(json, &["server", "version", "routes", "login"])
}

fn blocker_action(blocker: &str) -> &'static str {
    match blocker {
        "user_disabled" => "Enable the user account.",
        "target_disabled" => "Enable the target.",
        "target_unavailable" => "Check the target ID. Create the target if necessary.",
        "no_access_groups" => "Add the user to an access group.",
        "no_ssh_connect_grant" => {
            "Give a user's access group the ssh_connect permission for this target."
        }
        _ => "Ask an administrator to check access.",
    }
}

pub(super) fn render_access(view: &AccessExplanation) -> String {
    let list = |values: &[String]| {
        if values.is_empty() {
            "none".to_owned()
        } else {
            cell(&values.join(", "))
        }
    };
    let mut text = format!(
        "User: {}\nTarget: {}\nAccess groups: {}\nGranting groups: {}\nAuthorized: {}\nAgent online: {}\n",
        cell(&view.user_id),
        cell(&view.target_id),
        list(&view.access_groups),
        list(&view.granting_groups),
        view.authorized,
        view.online
    );
    for blocker in &view.blockers {
        text.push_str(&format!(
            "Blocked: {}. {}\n",
            cell(blocker),
            blocker_action(blocker)
        ));
    }
    if !view.online {
        text.push_str("Start the target agent. Check its server connection.\n");
    }
    text.push_str("Platform roles do not give SSH access.\nSSH account authentication and host-key checks remain separate.\n");
    text
}

async fn access(
    context: &ClientContext,
    token: &str,
    user: &str,
    target: &str,
) -> Result<AccessExplanation> {
    match context
        .api
        .admin(
            token,
            &AdminRequest {
                operation: AdminOperation::ExplainAccess {
                    user_id: user.trim().to_ascii_lowercase(),
                    target_id: target.trim().to_ascii_lowercase(),
                },
            },
        )
        .await?
    {
        AdminResponse::AccessExplanation(view) => Ok(view),
        _ => bail!("The server returned an invalid access report. Update the server."),
    }
}

pub(super) async fn explain(
    context: &ClientContext,
    user: &str,
    target: &str,
    json: bool,
) -> Result<()> {
    let token = auth::valid_access_token(context).await?;
    let me = context.api.me(&token).await?;
    anyhow::ensure!(
        me.system_role == SystemRole::Admin,
        "The current user does not have the admin platform role."
    );
    let view = access(context, &token, user, target).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        print!("{}", render_access(&view));
    }
    Ok(())
}

pub(super) async fn doctor(context: &ClientContext, target: &str, json: bool) -> Result<()> {
    let target = target.trim().to_ascii_lowercase();
    let mut report = Report::new(context, Some(target.clone()));
    let stages = &[
        "server", "version", "routes", "login", "access", "agent", "network", "sshd",
    ];
    let Some((token, me)) = identity(context, &mut report).await else {
        return report.finish(json, stages);
    };
    let availability = if me.system_role == SystemRole::Admin {
        match access(context, &token, &me.user_id, &target).await {
            Ok(view) => {
                if !view.authorized {
                    report.add(
                        "access",
                        "failed",
                        "The account cannot access this target.",
                        view.blockers
                            .iter()
                            .map(|b| blocker_action(b))
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    return report.finish(json, stages);
                }
                Ok(Some(view.online))
            }
            Err(error) => Err(error),
        }
    } else {
        context.api.targets(&token).await.map(|targets| {
            targets
                .into_iter()
                .find(|t| t.target_id == target)
                .map(|t| t.online)
        })
    };
    let online = match availability {
        Ok(Some(online)) => online,
        Ok(None) => {
            report.add(
                "access",
                "failed",
                "The target is not available to this account.",
                "Check the target ID. Ask an administrator to run kmesh access explain.",
            );
            return report.finish(json, stages);
        }
        Err(error) => {
            let (detail, next) = failure_action(&error);
            report.add("access", "failed", detail, next);
            return report.finish(json, stages);
        }
    };
    report.add("access", "passed", "The account has target access.", "");
    if !online {
        report.add(
            "agent",
            "failed",
            "The target agent is offline.",
            "Start the target agent. Check its server connection.",
        );
        return report.finish(json, stages);
    }
    report.add("agent", "passed", "The target agent is online.", "");
    match proxy::probe(context, target).await {
        Ok((mode, ssh)) => {
            report.add(
                "network",
                "passed",
                format!("Selected route: {mode:?}."),
                "",
            );
            match ssh {
                Ok(()) => report.add(
                    "sshd",
                    "passed",
                    "The SSH service returned a valid identification.",
                    "Use OpenSSH to check the host key and SSH account authentication.",
                ),
                Err(_) => report.add(
                    "sshd",
                    "failed",
                    "No valid SSH identification was received within the check limits.",
                    "Check the agent's SSH address, local SSH service, and agent logs.",
                ),
            }
        }
        Err(error) => {
            eprintln!("Connection check failed: {}", super::format_error(&error));
            report.add(
                "network",
                "failed",
                "The connection could not be established. See the route errors on stderr.",
                "Check access again. Check the agent logs, UDP paths, and private relay.",
            );
        }
    }
    report.finish(json, stages)
}
