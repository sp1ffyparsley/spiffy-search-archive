#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::process::ExitCode {
    match spiffy_search::agent::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Spiffy Search agent failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
