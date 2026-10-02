use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = match kmesh::client::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = error.exit_code();
            let rendered = error.render().to_string();
            let text = rendered;
            if error.use_stderr() {
                eprint!("{text}");
            } else {
                print!("{text}");
            }
            std::process::exit(exit_code);
        }
    };
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
