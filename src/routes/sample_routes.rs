use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;

use crate::db::sample_broker::insert_user;
use crate::domain::sample_model::Sample;


#[tracing::instrument(
name = "Post a sample model",
skip(sample, pool),
fields(
id = % sample.id,
)
)]
pub async fn post_sample(sample: web::Json<Sample>, pool: web::Data<PgPool>) -> impl Responder {
    match insert_user(sample.0, &pool).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
