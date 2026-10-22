use axum::http::{HeaderMap, HeaderValue, StatusCode};
use day2::web::page_preparation_refusal;

fn navigation(site: &str, user: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("sec-fetch-site", HeaderValue::from_str(site).unwrap());
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    if let Some(user) = user {
        headers.insert("sec-fetch-user", HeaderValue::from_str(user).unwrap());
    }
    headers
}

#[test]
fn preparation_accepts_navigation_and_same_origin_html_refresh_not_forged_or_speculative_requests()
{
    assert_eq!(
        page_preparation_refusal(&navigation("cross-site", Some("?1"))),
        None
    );
    assert_eq!(
        page_preparation_refusal(&navigation("same-origin", Some("?1"))),
        None
    );
    assert_eq!(page_preparation_refusal(&navigation("none", None)), None);

    let mut headers = navigation("cross-site", None);
    assert_eq!(
        page_preparation_refusal(&headers),
        Some(StatusCode::FORBIDDEN),
        "uninitiated cross-site navigation is not trusted"
    );
    headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    assert_eq!(
        page_preparation_refusal(&headers),
        Some(StatusCode::FORBIDDEN),
        "fetch metadata cannot masquerade as navigation"
    );

    headers.clear();
    assert_eq!(
        page_preparation_refusal(&headers),
        Some(StatusCode::FORBIDDEN),
        "missing metadata is not a safe navigation"
    );

    let mut speculative = navigation("cross-site", Some("?1"));
    speculative.insert("sec-purpose", HeaderValue::from_static("prefetch"));
    assert_eq!(
        page_preparation_refusal(&speculative),
        Some(StatusCode::SERVICE_UNAVAILABLE)
    );

    let mut refresh = HeaderMap::new();
    refresh.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    refresh.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    refresh.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    refresh.insert("accept", HeaderValue::from_static("text/html"));
    assert_eq!(page_preparation_refusal(&refresh), None);
    refresh.insert("sec-fetch-site", HeaderValue::from_static("same-site"));
    assert_eq!(
        page_preparation_refusal(&refresh),
        Some(StatusCode::FORBIDDEN)
    );
    refresh.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    refresh.insert("accept", HeaderValue::from_static("*/*"));
    assert_eq!(
        page_preparation_refusal(&refresh),
        Some(StatusCode::FORBIDDEN)
    );
    let mut duplicate_user = navigation("none", Some("?1"));
    duplicate_user.append("sec-fetch-user", HeaderValue::from_static("?1"));
    assert_eq!(
        page_preparation_refusal(&duplicate_user),
        Some(StatusCode::FORBIDDEN)
    );

    let mut duplicate = navigation("same-origin", Some("?1"));
    duplicate.append("sec-fetch-mode", HeaderValue::from_static("navigate"));
    assert_eq!(
        page_preparation_refusal(&duplicate),
        Some(StatusCode::FORBIDDEN),
        "ambiguous duplicated fetch metadata is rejected"
    );
}
