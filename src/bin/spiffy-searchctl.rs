#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match spiffy_search::cli::run().await {
        Ok(0) => std::process::ExitCode::SUCCESS,
        Ok(code) => std::process::ExitCode::from(code.clamp(1, 255) as u8),
        Err(error) => {
            eprintln!("spiffy-searchctl: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
