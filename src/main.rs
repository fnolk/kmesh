use clap::Parser;
use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, layer::SubscriberExt, util::SubscriberInitExt,
};

#[tokio::main]
async fn main() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(filter_fn(|metadata| {
            if metadata.target() == "noq_proto::connection::paths" {
                let fields = metadata.fields();
                let static_path_message =
                    fields.field("message").is_some() && fields.iter().count() == 1;
                let amplification_budget = fields.field("network_path").is_some()
                    && fields.field("anti_amplification_budget").is_some()
                    && fields.field("message").is_some()
                    && fields.iter().count() == 3;
                let path_status = fields.field("status").is_some()
                    && fields.field("seq").is_some()
                    && fields.field("message").is_some()
                    && fields.iter().count() == 3;
                return static_path_message || amplification_budget || path_status;
            }
            if metadata.target() != "noq_proto::connection" {
                return !metadata.target().starts_with("noq_proto::connection::");
            }
            let fields = metadata.fields();
            let off_path_nat_probe = fields.field("dst").is_some()
                && fields.field("len").is_some()
                && fields.field("message").is_some()
                && fields.iter().count() == 3
                && metadata.fields().field("src").is_none();
            let off_path_response = fields.field("dst").is_some()
                && fields.field("src").is_some()
                && fields.field("len").is_some()
                && fields.field("message").is_some()
                && fields.iter().count() == 4;
            let nat_traversal_negotiated = fields.field("max_remote_addresses").is_some()
                && fields.field("max_local_addresses").is_some()
                && fields.field("message").is_some()
                && fields.iter().count() == 3;
            // The root connection target also has a message-only `got frame {f}` fallback;
            // suppress that unbounded formatted frame event and keep only explicit safe schemas.
            off_path_nat_probe || off_path_response || nat_traversal_negotiated
        }));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    let cli = kmesh::client::Cli::parse();
    let proxy = matches!(&cli.command, kmesh::client::Command::Proxy { .. });
    match kmesh::client::run(cli).await {
        Ok(()) if proxy => std::process::exit(0),
        Ok(()) => {}
        Err(error) => {
            eprintln!("执行失败：{error:#}");
            std::process::exit(1);
        }
    }
}
