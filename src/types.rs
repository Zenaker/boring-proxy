use std::error::Error as StdError;
use http_body_util::{Empty, Full, combinators::BoxBody};
use rquest::Impersonate;
use std::convert::Infallible;
use bytes::Bytes;

pub type Error = Box<dyn StdError + Send + Sync + 'static>;
pub type ResponseBody = BoxBody<Bytes, Infallible>;
pub type ResponseResult = Result<hyper::Response<ResponseBody>, Error>;

// Helper functions for body conversion
pub fn empty() -> ResponseBody {
    BoxBody::new(Empty::<Bytes>::new())
}

pub fn full<T: Into<Bytes>>(data: T) -> ResponseBody {
    BoxBody::new(Full::new(data.into()))
}

// Available browser profiles for rotation
pub const PROFILES: &[Impersonate] = &[
    // Chrome versions
    Impersonate::Chrome131,
    Impersonate::Chrome130,
    Impersonate::Chrome129,
    Impersonate::Chrome128,
    Impersonate::Chrome127,
    Impersonate::Chrome126,
    Impersonate::Chrome124,
    Impersonate::Chrome123,
    Impersonate::Chrome120,
    Impersonate::Chrome119,
    Impersonate::Chrome118,
    Impersonate::Chrome117,
    Impersonate::Chrome116,
    Impersonate::Chrome114,
    Impersonate::Chrome109,
    Impersonate::Chrome108,
    Impersonate::Chrome107,
    Impersonate::Chrome106,
    Impersonate::Chrome105,
    Impersonate::Chrome104,
    Impersonate::Chrome101,
    Impersonate::Chrome100,

    // Safari versions
    Impersonate::Safari18_2,
    Impersonate::Safari18,
    Impersonate::Safari17_5,
    Impersonate::Safari17_4_1,
    Impersonate::Safari17_2_1,
    Impersonate::Safari17_0,
    Impersonate::Safari16_5,
    Impersonate::Safari16,
    Impersonate::Safari15_6_1,
    Impersonate::Safari15_5,
    Impersonate::Safari15_3,
    
    // Safari iOS versions
    Impersonate::SafariIos18_1_1,
    Impersonate::SafariIos17_4_1,
    Impersonate::SafariIos17_2,
    Impersonate::SafariIos16_5,
    Impersonate::SafariIPad18,

    // Edge versions
    Impersonate::Edge131,
    Impersonate::Edge127,
    Impersonate::Edge122,
    Impersonate::Edge101,

    // Firefox versions
    Impersonate::Firefox133,
    Impersonate::Firefox117,
    Impersonate::Firefox109,

    // OkHttp versions
    Impersonate::OkHttp5,
    Impersonate::OkHttp4_10,
    Impersonate::OkHttp4_9,
    Impersonate::OkHttp3_14,
    Impersonate::OkHttp3_13,
    Impersonate::OkHttp3_11,
    Impersonate::OkHttp3_9,
];

pub fn log(component: &str, message: &str) {
    use std::time::{SystemTime, UNIX_EPOCH, Duration};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    println!("[{}][{}] {}", timestamp, component, message);
}
