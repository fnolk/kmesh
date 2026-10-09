use std::io::{IsTerminal, Write};

use super::{ClientContext, auth, cli::GroupChangeOptions, output::cell};
use crate::protocol::{AdminOperation, AdminRequest, AdminResponse, GroupChange, GroupChangeMode};
use anyhow::{Result, bail};

pub(super) fn render(change: &GroupChange, applied: bool) -> String {
    let list = |items: &[String]| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            cell(&items.join(", "))
        }
    };
    format!(
        "{}\nUser: {}\nGroups before: {}\nGroups after: {}\nTarget access removed: {}\nTarget access added: {}\nExisting SSH connections can continue.\n",
        if applied {
            "Access groups changed."
        } else {
            "Preview only. No changes were applied."
        },
        cell(&change.user_id),
        list(&change.before),
        list(&change.after),
        list(&change.lost_target_ids),
        list(&change.gained_target_ids),
    )
}

pub(super) async fn run(
    context: &ClientContext,
    user_id: String,
    group_ids: Vec<String>,
    mode: GroupChangeMode,
    options: GroupChangeOptions,
    json: bool,
) -> Result<()> {
    let token = auth::valid_access_token(context).await?;
    let user_id = user_id.trim().to_ascii_lowercase();
    let group_ids = group_ids
        .into_iter()
        .map(|id| id.trim().to_ascii_lowercase())
        .collect();
    let mut operation = AdminOperation::ChangeUserAccessGroups {
        user_id,
        group_ids,
        mode,
        dry_run: true,
        expected: None,
    };
    let preview = context
        .api
        .admin(
            &token,
            &AdminRequest {
                operation: operation.clone(),
            },
        )
        .await?;
    let AdminResponse::GroupChange { ref change, .. } = preview else {
        bail!("The server returned an invalid group preview. Update the server.");
    };
    if options.dry_run {
        if json {
            println!("{}", serde_json::to_string_pretty(&preview)?);
        } else {
            print!("{}", render(change, false));
        }
        return Ok(());
    }
    if !json {
        eprint!("{}", render(change, false));
    }
    if !change.before.is_empty() && change.after.is_empty() && !options.yes {
        if json || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            bail!(
                "This change removes all access groups. Use --dry-run to inspect it. Use --yes to apply it."
            );
        }
        eprint!("Remove all access groups? Type yes to continue: ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != "yes" {
            println!("No changes were applied.");
            return Ok(());
        }
    }
    if let AdminOperation::ChangeUserAccessGroups {
        dry_run, expected, ..
    } = &mut operation
    {
        *dry_run = false;
        *expected = Some(change.clone());
    }
    let response = context
        .api
        .admin(&token, &AdminRequest { operation })
        .await?;
    let AdminResponse::GroupChange {
        change,
        applied,
        access_groups,
    } = &response
    else {
        bail!("The server returned an invalid group result. Check the user's access groups.");
    };
    if json {
        // Preserve the existing replacement command's result and data fields.
        let value = if mode == GroupChangeMode::Replace {
            let mut value =
                serde_json::to_value(AdminResponse::UserAccessGroups(access_groups.clone()))?;
            value["change"] = serde_json::to_value(change)?;
            value["applied"] = (*applied).into();
            value
        } else {
            serde_json::to_value(&response)?
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print!("{}", render(change, *applied));
    }
    Ok(())
}
