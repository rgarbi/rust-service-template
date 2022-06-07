use sqlx::{Error, PgPool};
use crate::domain::sample_model::Sample;


#[tracing::instrument(
    name = "Saving new sample",
    skip(sample, _pool)
)]
pub async fn insert_user(
    sample: Sample,
    _pool: &PgPool,
) -> Result<String, Error> {
    // Commenting out so that we dop not have to create a fake migration
    //sqlx::query!(
    //    r#"INSERT
    //        INTO sample (id, string, number, small_number)
    //        VALUES ($1, $2, $3, $4)"#,
    //    sample.id,
    //    sample.string,
    //    sample.number,
    //    sample.small_number,
    //)
    //    .execute(pool)
    //    .await
    //    .map_err(|e: Error| {
    //        tracing::error!("{:?}", e);
    //        e
    //    })?;

    Ok(sample.id.to_string())
}




