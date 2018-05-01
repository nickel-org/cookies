#[macro_use] extern crate nickel;
extern crate nickel_cookies;
extern crate cookie;

use nickel_cookies::{Cookies, KeyProvider};
use nickel::{Nickel, HttpRouter, QueryString, Request, Response, MiddlewareResult};
#[cfg(feature = "secure")]
use cookie::{Cookie, Key};
#[cfg(not(feature = "secure"))]
use cookie::Cookie;

#[cfg(feature = "secure")]
fn secure_middleware<'mw, 'conn, D: KeyProvider>(req: &mut Request<'mw, 'conn, D>, mut res: Response<'mw, D>) -> MiddlewareResult<'mw, D> {
    let old_value = { // block for borrow management
        let server_key = res.server_data().key();
        let key = Key::from_master(&server_key.0);
        let mut jar = res.cookies_mut()
            .private(&key);

        let new_value = req.query().get("value")
            .unwrap_or("no value")
            .to_owned();

        let cookie = Cookie::new("SecureCookie".to_owned(),
                                 new_value);
        jar.add(cookie);

        // Old value from the request's Cookies
        req.cookies_mut()
            .private(&key)
            .get("SecureCookie")
            .map(|c| c.value().to_owned())
    };
    res.send(format!("Old value was {:?}", old_value))
}

#[cfg(not(feature = "secure"))]
fn secure_middleware<'mw, 'conn, D: KeyProvider>(_: &mut Request<'mw, 'conn, D>, res: Response<'mw, D>) -> MiddlewareResult<'mw, D> {
    res.next_middleware()
}

fn main() {
    let mut server = Nickel::new();

    // Try curl -b MyCookie=bar localhost:6767
    server.get("/", middleware! { |req|
        let cookie = req.cookies().get("MyCookie");
        format!("MyCookie={:?}", cookie.map(|c| c.value()))
    });

    // Note: Don't use get for login in real applications ;)
    // Try http://localhost:6767/login?name=foo
    server.get("/login", middleware! {
        |req, mut res|
        let jar = res.cookies_mut();

        let name = req.query().get("name")
            .unwrap_or("default_name");
        let mut cookie = Cookie::new("MyCookie".to_owned(),
                                 name.to_owned());
        cookie.make_permanent(); // long life cookie!

        jar.add(cookie);

        "Cookie set!"
    });

    // Try `curl -c /tmp/cookie -b /tmp/cookie http://localhost:6767/secure?value=foobar`
    // when the `secure_cookies` feature is enabled
    // i.e. `cargo run --example cookies_example --features secure_cookies
    if cfg!(feature = "secure") {
        server.get("/secure", secure_middleware);
    }

    server.listen("127.0.0.1:6767").unwrap();
}
