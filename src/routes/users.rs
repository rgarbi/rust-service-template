use crate::auth::authorization::is_authorized_admin_only;
use actix_web::web::Data;
use actix_web::{web, HttpResponse, Responder};
use chrono::{Duration, Utc};
use reqwest::Error;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::password_hashing::{hash_password, validate_password};
use crate::auth::token::{generate_token, get_expires_at, Claims, LoginResponse};
use crate::configuration::get_configuration;
use crate::db::otp_db_broker::{get_otp_by_otp, insert_otp, set_to_used_by_otp};
use crate::db::subscribers_db_broker::insert_subscriber;
use crate::db::users::{
    count_users_with_email_address, get_user_by_email_address, get_user_by_user_id, insert_user,
    update_password,
};
use crate::domain::otp_models::OneTimePasscode;
use crate::domain::subscriber_models::NewSubscriber;
use crate::domain::user_models::{
    ForgotPassword, LogIn, ResetPassword, ResetPasswordFromForgotPassword, SignUp, UserGroup,
};
use crate::domain::valid_email::ValidEmail;
use crate::domain::valid_name::ValidName;
use crate::email_client::EmailClient;
use crate::util::{generate_random_token, standardize_email};

impl TryFrom<SignUp> for NewSubscriber {
    type Error = String;
    fn try_from(sign_up: SignUp) -> Result<Self, Self::Error> {
        let name = ValidName::parse(sign_up.name)?;
        let email_address = ValidEmail::parse(standardize_email(&sign_up.email_address))?;
        Ok(NewSubscriber {
            name,
            email_address,
            user_id: String::new(),
        })
    }
}

#[tracing::instrument(
    name = "Singing up a new user",
    skip(sign_up, pool),
    fields(
        user_username = %sign_up.email_address,
    )
)]
pub async fn sign_up(sign_up: web::Json<SignUp>, pool: web::Data<PgPool>) -> impl Responder {
    let transformed_email = standardize_email(&sign_up.email_address.clone());
    match count_users_with_email_address(&transformed_email, &pool).await {
        Ok(count) => {
            if count > 0 {
                return HttpResponse::Conflict().finish();
            }

            let mut new_subscriber: NewSubscriber = match sign_up.clone().try_into() {
                Ok(subscriber) => subscriber,
                Err(_) => return HttpResponse::BadRequest().finish(),
            };

            let mut transaction = match pool.begin().await {
                Ok(transaction) => transaction,
                Err(_) => return HttpResponse::InternalServerError().finish(),
            };

            let hashed_password = hash_password(sign_up.clone().password).await;
            let login_response = match insert_user(
                &transformed_email,
                &hashed_password,
                UserGroup::USER,
                &mut transaction,
            )
            .await
            {
                Ok(user_id) => LoginResponse {
                    user_id: user_id.clone(),
                    token: generate_token(user_id, UserGroup::USER),
                    expires_on: get_expires_at(Option::None),
                },
                Err(_) => {
                    transaction.rollback().await.unwrap();
                    return HttpResponse::InternalServerError().finish();
                }
            };

            new_subscriber.user_id = login_response.user_id.clone();
            match insert_subscriber(&new_subscriber, &mut transaction).await {
                Ok(_) => {
                    if transaction.commit().await.is_err() {
                        HttpResponse::InternalServerError().finish();
                    }
                    HttpResponse::Ok().json(&login_response)
                }
                Err(_) => {
                    transaction.rollback().await.unwrap();
                    HttpResponse::InternalServerError().finish()
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[tracing::instrument(
    name = "Login user",
    skip(log_in, pool),
    fields(
        user_username = %log_in.email_address,
    )
)]
pub async fn login(log_in: web::Json<LogIn>, pool: web::Data<PgPool>) -> impl Responder {
    let transformed_email = standardize_email(&log_in.email_address.clone());
    match get_user_by_email_address(&transformed_email, &pool).await {
        Ok(user) => {
            let hashed_passwords_match =
                validate_password(log_in.password.clone(), user.password).await;
            if !hashed_passwords_match {
                return HttpResponse::BadRequest().finish();
            }

            HttpResponse::Ok().json(LoginResponse {
                user_id: user.user_id.to_string(),
                token: generate_token(user.user_id.to_string(), UserGroup::USER),
                expires_on: get_expires_at(Option::None),
            })
        }
        Err(_) => HttpResponse::BadRequest().finish(),
    }
}

#[tracing::instrument(
    name = "Check token",
    skip(user_id, user),
    fields(
        user_id = %user_id,
    )
)]
pub async fn check_token(user_id: web::Path<String>, user: Claims) -> impl Responder {
    if user_id.clone() != user.user_id {
        return HttpResponse::Unauthorized().finish();
    }

    HttpResponse::Ok().json(json!({}))
}

#[tracing::instrument(
    name = "Check Admin token",
    skip(user_id, user),
    fields(
        user_id = %user_id,
    )
)]
pub async fn check_admin_token(user_id: web::Path<String>, user: Claims) -> impl Responder {
    if is_authorized_admin_only(user_id.into_inner(), user) {
        return HttpResponse::Ok().json(json!({}));
    }

    HttpResponse::Unauthorized().finish()
}

#[tracing::instrument(
    name = "Reset password",
    skip(reset_password, pool, user_claim),
    fields(
        user_username = %reset_password.email_address,
    )
)]
pub async fn reset_password(
    reset_password: web::Json<ResetPassword>,
    pool: web::Data<PgPool>,
    user_claim: Claims,
) -> impl Responder {
    match get_user_by_email_address(&reset_password.email_address, &pool).await {
        Ok(user) => {
            if user_claim.user_id != user.user_id.to_string() {
                return HttpResponse::Unauthorized().finish();
            }

            let hashed_passwords_match =
                validate_password(reset_password.old_password.clone(), user.password).await;
            if !hashed_passwords_match {
                return HttpResponse::BadRequest().finish();
            }

            let new_hashed_password = hash_password(reset_password.new_password.clone()).await;

            match update_password(&reset_password.email_address, &new_hashed_password, &pool).await
            {
                Ok(_) => HttpResponse::Ok().finish(),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::BadRequest().finish(),
    }
}

#[tracing::instrument(
    name = "Forgot password",
    skip(forgot_password, pool, email_client),
    fields(
        user_username = %forgot_password.email_address,
    )
)]
pub async fn forgot_password(
    forgot_password: web::Json<ForgotPassword>,
    pool: web::Data<PgPool>,
    email_client: web::Data<EmailClient>,
) -> impl Responder {
    let email = standardize_email(&forgot_password.email_address);
    match get_user_by_email_address(email.as_str(), &pool).await {
        Ok(user) => {
            let passcode = generate_random_token();
            let otp = OneTimePasscode {
                id: Uuid::new_v4(),
                user_id: user.user_id.to_string(),
                one_time_passcode: passcode.clone(),
                issued_on: Utc::now(),
                expires_on: Utc::now() + Duration::days(1),
                used: false,
            };
            match insert_otp(otp, &pool).await {
                Ok(_) => {
                    if email_user(email, passcode, email_client).await.is_err() {
                        return HttpResponse::InternalServerError().finish();
                    }
                    HttpResponse::Ok().json(json!({}))
                }
                Err(err) => {
                    tracing::error!(
                        "Something happened while saving the one time passcode. {:?}",
                        err
                    );
                    HttpResponse::Ok().json(json!({}))
                }
            }
        }
        Err(_) => HttpResponse::Ok().json(json!({})),
    }
}

#[tracing::instrument(
    name = "Forgot password login",
    skip(one_time_passcode, pool),
    fields(
        one_time_passcode = %one_time_passcode,
    )
)]
pub async fn forgot_password_login(
    one_time_passcode: web::Path<String>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    match get_otp_by_otp(one_time_passcode.into_inner().clone().as_str(), &pool).await {
        Ok(passcode) => {
            if is_invalid_one_time_passcode(&passcode) {
                return HttpResponse::BadRequest().finish();
            }

            //set it to used
            match set_to_used_by_otp(passcode.one_time_passcode.as_str(), &pool).await {
                Ok(_) => HttpResponse::Ok().json(LoginResponse {
                    user_id: passcode.user_id.clone(),
                    token: generate_token(passcode.user_id.clone(), UserGroup::USER),
                    expires_on: get_expires_at(Option::None),
                }),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::BadRequest().finish(),
    }
}

#[tracing::instrument(
    name = "Reset password from forgot password",
    skip(reset_password, pool, user_claim),
    fields(
        user_user_id = %reset_password.user_id,
    )
)]
pub async fn reset_password_from_forgot_password(
    reset_password: web::Json<ResetPasswordFromForgotPassword>,
    pool: web::Data<PgPool>,
    user_claim: Claims,
) -> impl Responder {
    if user_claim.user_id != reset_password.user_id {
        return HttpResponse::Unauthorized().finish();
    }
    match get_user_by_user_id(&reset_password.user_id, &pool).await {
        Ok(user) => {
            if user_claim.user_id != user.user_id.to_string() {
                return HttpResponse::Unauthorized().finish();
            }

            let new_hashed_password = hash_password(reset_password.new_password.clone()).await;

            match update_password(&user.email_address, &new_hashed_password, &pool).await {
                Ok(_) => HttpResponse::Ok().json(json!({})),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::BadRequest().finish(),
    }
}

pub async fn email_user(
    email: String,
    passcode: String,
    email_client: Data<EmailClient>,
) -> Result<(), Error> {
    let web_app_hostname = get_configuration().unwrap().application.web_app_host;
    let link = format!("{}/reset-password?otp={}", web_app_hostname, passcode);

    email_client
        .send_email(
            ValidEmail::parse(email).unwrap(),
            "Password Reset",
            format!(
                "Here is a <a href=\"{}\">link</a> that will enable you to reset your password!",
                link
            )
            .as_str(),
            format!(
                "Here is a link that will enable you to reset your password! {}",
                link
            )
            .as_str(),
        )
        .await
}

fn is_invalid_one_time_passcode(one_time_passcode: &OneTimePasscode) -> bool {
    let is_expired: bool = one_time_passcode.expires_on.lt(&Utc::now());

    is_expired || one_time_passcode.used
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::domain::otp_models::OneTimePasscode;
    use crate::routes::users::is_invalid_one_time_passcode;

    #[test]
    fn expired_passcodes_are_invalid() {
        let otp = OneTimePasscode {
            id: Default::default(),
            user_id: "".to_string(),
            one_time_passcode: "".to_string(),
            issued_on: Utc::now() - Duration::seconds(100),
            expires_on: Utc::now() - Duration::seconds(100),
            used: false,
        };

        assert_eq!(true, is_invalid_one_time_passcode(&otp))
    }

    #[test]
    fn used_passcodes_are_invalid() {
        let otp = OneTimePasscode {
            id: Default::default(),
            user_id: "".to_string(),
            one_time_passcode: "".to_string(),
            issued_on: Utc::now() + Duration::seconds(100),
            expires_on: Utc::now() + Duration::seconds(100),
            used: true,
        };

        assert_eq!(true, is_invalid_one_time_passcode(&otp))
    }

    #[test]
    fn used_and_expired_passcodes_are_invalid() {
        let otp = OneTimePasscode {
            id: Default::default(),
            user_id: "".to_string(),
            one_time_passcode: "".to_string(),
            issued_on: Utc::now() - Duration::seconds(100),
            expires_on: Utc::now() - Duration::seconds(100),
            used: true,
        };

        assert_eq!(true, is_invalid_one_time_passcode(&otp))
    }

    #[test]
    fn not_used_and_not_expired_passcodes_are_not_invalid() {
        let otp = OneTimePasscode {
            id: Default::default(),
            user_id: "".to_string(),
            one_time_passcode: "".to_string(),
            issued_on: Utc::now() + Duration::seconds(100),
            expires_on: Utc::now() + Duration::seconds(100),
            used: false,
        };

        assert_eq!(false, is_invalid_one_time_passcode(&otp))
    }
}
