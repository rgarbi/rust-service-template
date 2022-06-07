use {{ tmplr.project_name | snake_case }}::configuration::get_configuration;
use {{ tmplr.project_name | snake_case }}::startup::Application;
use {{ tmplr.project_name | snake_case }}::telemetry::{get_subscriber, init_subscriber};


#[tokio::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber(
        "{{ tmplr.project_name }}".into(),
        "info".into(),
        std::io::stdout,
    );
    init_subscriber(subscriber);

    let configuration = get_configuration().expect("Failed to read configuration.");
    let application = Application::build(configuration).await?;
    application.run_until_stopped().await?;
    Ok(())
}
