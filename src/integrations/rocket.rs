// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! rocket 0.5 集成。
//!
//! 用 `manage` 注册，处理器把它写在参数里：
//!
//! ```no_run
//! # mod demo {
//! use rocket::{get, routes, Build, Rocket};
//! use encryption::guard::Guard;
//!
//! #[get("/")]
//! fn store_phone(guard: Guard) -> String {
//!     guard.encrypt("13800138000".as_bytes()).unwrap().len().to_string()
//! }
//!
//! # fn main() {
//! let guard: Guard = todo!();
//! let rocket: Rocket<Build> = rocket::build().manage(guard).mount("/", routes![store_phone]);
//! # let _ = rocket;
//! # }
//! # }
//! ```
//!
//! rocket 的请求守卫走 `Outcome`，且 trait 是 `#[rocket::async_trait]` 的
//! （rocket 自己 re-export 了那个宏，所以不必额外依赖 `async-trait`）。
//!
//! # 托管状态里放的是 [`Guard`] 本身
//!
//! [`Guard`] 内部已经是 `Arc`，克隆一次只是引用计数递增，所以这里是
//! `manage(guard)` 而不是 `manage(Arc::new(guard))` —— rocket 的守卫拿到的是
//! 借用，本来也不需要外面再套一层共享。

use rocket::State;
use rocket::http::Status;
// 注意是 `request::Outcome`（两参数别名 = `outcome::Outcome<S, (Status, E), Status>`），
// 不是 `outcome::Outcome`（三参数）。守卫的返回值用的就是这个别名。
use rocket::request::{FromRequest, Outcome, Request};

use super::GuardNotConfigured;
use crate::guard::Guard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Guard {
    type Error = GuardNotConfigured;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.guard::<&State<Guard>>().await {
            Outcome::Success(state) => Outcome::Success(state.inner().clone()),
            // 忘了 manage(...)：装配错误 → 500，不 Forward（没有别的路由能处理它）。
            // 别名的 Error 分支装的是 `(Status, E)` 而不是裸的 E。
            Outcome::Error(_) | Outcome::Forward(_) => {
                Outcome::Error((Status::InternalServerError, GuardNotConfigured))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::local::blocking::Client;
    use rocket::{get, routes};

    fn guard() -> Guard {
        Guard::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap()
    }

    #[get("/encrypt")]
    fn encrypt_route(guard: Guard) -> String {
        let blob = guard.encrypt("13800138000".as_bytes()).unwrap();
        crate::internal::hex_encode(&blob)
    }

    #[get("/decrypt/<payload>")]
    fn decrypt_route(guard: Guard, payload: &str) -> String {
        let blob = crate::internal::hex_decode(payload).unwrap_or_default();
        guard
            .decrypt(&blob)
            .map(|plain| String::from_utf8_lossy(&plain).into_owned())
            .unwrap_or_else(|_| "解不开".into())
    }

    #[test]
    fn guard_is_injectable_end_to_end() {
        let rocket = rocket::build()
            .manage(guard())
            .mount("/", routes![encrypt_route, decrypt_route]);
        let client = Client::tracked(rocket).expect("rocket 应当能启动");

        let res = client.get("/encrypt").dispatch();
        assert_eq!(res.status(), Status::Ok);
        let cipher = res.into_string().unwrap();
        assert!(cipher.len() > 20, "应当拿到一段密文，实际 {cipher:?}");

        // 拿刚加密出来的密文再解回去 —— 证明两个请求用的是同一把密钥
        let res = client.get(format!("/decrypt/{cipher}")).dispatch();
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.into_string().unwrap(), "13800138000");
    }

    /// 忘了 `manage(...)` 时是 500，不是 panic。
    #[test]
    fn missing_managed_state_is_a_500() {
        let rocket = rocket::build().mount("/", routes![encrypt_route]);
        let client = Client::tracked(rocket).expect("rocket 应当能启动");

        let res = client.get("/encrypt").dispatch();
        assert_eq!(res.status(), Status::InternalServerError);
    }
}
