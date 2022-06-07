use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::{FromRequest, HttpRequest, ResponseError};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtokens as jwt;
use jsonwebtokens::encode;
use jwt::{Algorithm, AlgorithmID, Verifier};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::configuration::get_configuration;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Claims {
    pub user_id: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
}

#[derive(Deserialize, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub token: String,
    pub expires_on: u64,
}

#[derive(Debug, Clone)]
pub enum TokenError {
    AuthError,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "A an error was encountered while trying evaluate a user token."
        )
    }
}

impl ResponseError for TokenError {
    fn status_code(&self) -> StatusCode {
        match self {
            TokenError::AuthError => StatusCode::UNAUTHORIZED,
        }
    }
}

impl FromRequest for Claims {
    type Error = TokenError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let extractor = BearerAuth::extract(req);

        Box::pin(async move {
            let credentials = extractor.await.map_err(|_| TokenError::AuthError)?;
            validate_token(String::from(credentials.token()))
        })
    }
}

pub fn generate_token(user_id: String) -> String {
    let auth_config = get_configuration().unwrap().auth_config;
    let now = get_now_in_seconds();
    let claims: Claims = Claims {
        user_id: user_id.clone(),
        iss: auth_config.issuer,
        aud: auth_config.audience,
        sub: user_id,
        iat: now,
        exp: get_expires_at(Option::Some(now)),
    };
    let alg = Algorithm::new_hmac(
        AlgorithmID::HS512,
        auth_config.signing_key.expose_secret().as_bytes(),
    )
    .unwrap();
    let header = json!({ "alg": alg.name() });
    let claims = serde_json::to_value(claims).unwrap();
    encode(&header, &claims, &alg).unwrap()
}

pub fn validate_token(token: String) -> Result<Claims, TokenError> {
    let auth_config = get_configuration().unwrap().auth_config;
    let alg = Algorithm::new_hmac(
        AlgorithmID::HS512,
        auth_config.signing_key.expose_secret().as_bytes(),
    )
    .unwrap();
    let verifier = Verifier::create()
        .issuer(auth_config.issuer)
        .audience(auth_config.audience)
        .build()
        .unwrap();
    let result = verifier.verify(&token, &alg);
    let value: Value = match result {
        Ok(value) => value,
        Err(_) => return Err(TokenError::AuthError),
    };
    let claims: Claims = serde_json::from_value(value).unwrap();
    Ok(claims)
}

pub fn get_now_in_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn get_expires_at(now_in_seconds: Option<u64>) -> u64 {
    let now = now_in_seconds.unwrap_or_else(get_now_in_seconds);
    now + 3600
}

#[cfg(test)]
mod tests {
    use claim::{assert_err, assert_ok};
    use uuid::Uuid;

    use crate::auth::token::{generate_token, validate_token};

    #[test]
    fn given_a_user_id_i_can_generate_a_token() {
        let user_id = Uuid::new_v4().to_string();
        let token = generate_token(user_id.clone());
        println!("{}", user_id.clone());
        println!("{}", token);
    }

    #[test]
    fn given_a_valid_token_i_can_get_claims() {
        let user_id = Uuid::new_v4().to_string();
        let token = generate_token(user_id.clone());
        let claims = validate_token(token);
        assert_ok!(&claims);
        assert_eq!(user_id.clone(), *claims.unwrap().user_id)
    }

    #[test]
    fn given_an_expired_token_it_is_deemed_invalid() {
        let token = "eyJhbGciOiJIUzUxMiJ9.eyJhdWQiOiJodHRwczovL2hlbGxvLXdvcmxkLmV4YW1wbGUuY29tIiwiZXhwIjoxNjQ3MzU1ODI2LCJpYXQiOjE2NDczNTU4MjUsImlzcyI6ImRldi00aXk1OS1pbS51cy5hdXRoMC5jb20iLCJzdWIiOiJmNWYwZGI3Yy04ZWY2LTRlNTItOWJjMy02NDBjYzE1MTJlZmMiLCJ1c2VyX2lkIjoiZjVmMGRiN2MtOGVmNi00ZTUyLTliYzMtNjQwY2MxNTEyZWZjIn0.Tyy52KqX0-gh40rKK8yH_5uwqQPpnUoCVcAcm7gQlMY69a9ZEMPHuauupMCX1UNAg_-eIES9OMTh1p2lfP7wAA";
        let claims = validate_token(String::from(token));
        assert_err!(claims);
    }
}
