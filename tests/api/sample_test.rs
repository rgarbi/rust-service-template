use uuid::Uuid;
use {{ tmplr.project_name | snake_case }}::domain::sample_model::Sample;

use crate::helper::spawn_app;

#[tokio::test]
async fn post_sample_works() {
    let app = spawn_app().await;

    let sample = Sample {
        id: Uuid::new_v4(),
        string: Uuid::new_v4().to_string(),
        number: 123123123,
        small_number: 12
    };

    let response = app.post_sample(sample.to_json()).await;

    // Assert
    assert!(response.status().is_success());
}
