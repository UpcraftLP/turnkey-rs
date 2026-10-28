use http::Uri;
use url::Url;

#[extension(pub trait UrlToUri)]
impl Url {
    fn to_uri(&self) -> Uri {
        self.to_string().parse().expect("Url to Uri is infallible")
    }
}
