use crate::auth::token::Claims;
use crate::domain::user_models::UserGroup;
use tracing::Level;

pub fn is_authorized_admin_only(user_id: String, token: Claims) -> bool {
    if (user_id == token.user_id) && token.group == UserGroup::ADMIN {
        return true;
    }
    tracing::event!(
        Level::ERROR,
        "User ID: {} is not authorized on an admin API",
        user_id
    );
    false
}

pub fn is_authorized_user_or_admin(user_id: String, token: Claims) -> bool {
    if (user_id == token.user_id)
        && (token.group == UserGroup::ADMIN || token.group == UserGroup::USER)
    {
        return true;
    }
    tracing::event!(
        Level::ERROR,
        "User ID: {} is not authorized on an admin API",
        user_id
    );
    false
}

pub fn is_authorized_user_only(user_id: String, token: Claims) -> bool {
    if (user_id == token.user_id) && token.group == UserGroup::USER {
        return true;
    }
    tracing::event!(
        Level::ERROR,
        "User ID: {} is not authorized on an admin API",
        user_id
    );
    false
}

#[cfg(test)]
mod tests {
    use crate::auth::authorization::{
        is_authorized_admin_only, is_authorized_user_only, is_authorized_user_or_admin,
    };
    use crate::auth::token::Claims;
    use crate::domain::user_models::UserGroup;
    use uuid::Uuid;
    use UserGroup::USER;

    #[test]
    fn is_authorized_admin_only_passes() {
        let user_id = Uuid::new_v4().to_string();

        let claims = Claims {
            user_id: user_id.clone(),
            group: UserGroup::ADMIN,
            iss: "".to_string(),
            aud: "".to_string(),
            sub: "".to_string(),
            exp: 0,
            iat: 0,
        };

        assert_eq!(true, is_authorized_admin_only(user_id, claims));
    }

    #[test]
    fn is_authorized_admin_only_does_not_pass() {
        let user_id = Uuid::new_v4().to_string();

        assert_eq!(
            false,
            is_authorized_admin_only(
                user_id.clone(),
                Claims {
                    user_id: user_id.clone(),
                    group: USER,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );

        assert_eq!(
            false,
            is_authorized_admin_only(
                user_id.clone(),
                Claims {
                    user_id: Uuid::new_v4().to_string(),
                    group: UserGroup::ADMIN,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );

        assert_eq!(
            false,
            is_authorized_admin_only(
                user_id.clone(),
                Claims {
                    user_id: Uuid::new_v4().to_string(),
                    group: UserGroup::USER,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );
    }

    #[test]
    fn is_authorized_admin_or_user_passes() {
        let user_id = Uuid::new_v4().to_string();

        assert_eq!(
            true,
            is_authorized_user_or_admin(
                user_id.clone(),
                Claims {
                    user_id: user_id.clone(),
                    group: UserGroup::ADMIN,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );

        assert_eq!(
            true,
            is_authorized_user_or_admin(
                user_id.clone(),
                Claims {
                    user_id: user_id.clone(),
                    group: UserGroup::USER,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );
    }

    #[test]
    fn is_authorized_admin_or_user_does_not_pass() {
        let user_id = Uuid::new_v4().to_string();

        assert_eq!(
            false,
            is_authorized_user_or_admin(
                user_id.clone(),
                Claims {
                    user_id: Uuid::new_v4().to_string(),
                    group: UserGroup::ADMIN,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );
    }

    #[test]
    fn is_authorized_user_only_passes() {
        let user_id = Uuid::new_v4().to_string();

        assert_eq!(
            true,
            is_authorized_user_only(
                user_id.clone(),
                Claims {
                    user_id: user_id.clone(),
                    group: UserGroup::USER,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );
    }

    #[test]
    fn is_authorized_user_only_does_not_pass() {
        let user_id = Uuid::new_v4().to_string();

        assert_eq!(
            false,
            is_authorized_user_only(
                user_id.clone(),
                Claims {
                    user_id: user_id.clone(),
                    group: UserGroup::ADMIN,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );

        assert_eq!(
            false,
            is_authorized_user_only(
                user_id.clone(),
                Claims {
                    user_id: Uuid::new_v4().to_string(),
                    group: UserGroup::USER,
                    iss: "".to_string(),
                    aud: "".to_string(),
                    sub: "".to_string(),
                    exp: 0,
                    iat: 0,
                }
            )
        );
    }
}
