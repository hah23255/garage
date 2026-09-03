use std::sync::Arc;

use http::header::{
	HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
	ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_REQUEST_HEADERS,
	ACCESS_CONTROL_REQUEST_METHOD, VARY,
};
use hyper::{body::Body, body::Incoming as IncomingBody, Request, Response, StatusCode};

use garage_model::bucket_table::{BucketParams, CorsRule as GarageCorsRule};
use garage_model::garage::Garage;

use crate::common_error::{CommonError, OkOrBadRequest, OkOrInternalError};
use crate::helpers::*;

// Return both the matching rule and the parsed Origin header so callers that
// apply CORS headers don't have to repeat Origin lookup and validation.
pub fn find_matching_cors_rule<'a, B>(
	bucket_params: &'a BucketParams,
	req: &'a Request<B>,
) -> Result<Option<(&'a GarageCorsRule, &'a str)>, CommonError> {
	if let Some(cors_config) = bucket_params.cors_config.get().inner() {
		if let Some(origin) = req.headers().get("Origin") {
			let origin = origin.to_str()?;
			let request_headers = match req.headers().get(ACCESS_CONTROL_REQUEST_HEADERS) {
				Some(h) => h.to_str()?.split(',').map(|h| h.trim()).collect::<Vec<_>>(),
				None => vec![],
			};
			return Ok(cors_config
				.iter()
				.find(|rule| {
					cors_rule_matches(rule, origin, req.method().as_ref(), request_headers.iter())
				})
				.map(|rule| (rule, origin)));
		}
	}
	Ok(None)
}

pub fn cors_rule_matches<'a, HI, S>(
	rule: &GarageCorsRule,
	origin: &'a str,
	method: &'a str,
	mut request_headers: HI,
) -> bool
where
	HI: Iterator<Item = S>,
	S: AsRef<str>,
{
	rule.allow_origins.iter().any(|x| wildcard_match(x, origin))
		&& rule.allow_methods.iter().any(|x| x == "*" || x == method)
		&& request_headers.all(|h| {
			rule.allow_headers
				.iter()
				.any(|x| wildcard_match(x, h.as_ref()))
		})
}

/// Checks whether `candidate` matches the pattern `allowed_wildcard`.
#[inline]
fn wildcard_match(allowed_wildcard: &String, candidate: &str) -> bool {
	if allowed_wildcard.contains("*") {
		let parts = allowed_wildcard.split("*").collect::<Vec<&str>>();
		parts.len() == 2 && candidate.starts_with(parts[0]) && candidate.ends_with(parts[1])
	} else {
		candidate == allowed_wildcard
	}
}

pub fn add_cors_headers(
	resp: &mut Response<impl Body>,
	rule: &GarageCorsRule,
	request_origin: &str,
) -> Result<(), http::header::InvalidHeaderValue> {
	let h = resp.headers_mut();
	let is_wildcard_origin = rule.allow_origins.iter().any(|origin| origin == "*");
	let allow_origin = if is_wildcard_origin {
		"*"
	} else {
		request_origin
	};
	h.insert(ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin.parse()?);
	h.insert(
		ACCESS_CONTROL_ALLOW_METHODS,
		rule.allow_methods.join(", ").parse()?,
	);
	h.insert(
		ACCESS_CONTROL_ALLOW_HEADERS,
		rule.allow_headers.join(", ").parse()?,
	);
	h.insert(
		ACCESS_CONTROL_EXPOSE_HEADERS,
		rule.expose_headers.join(", ").parse()?,
	);
	// When ACAO reflects the request origin instead of returning "*",
	// caches must vary on the Origin request header to avoid reusing
	// a response generated for one origin when serving another origin.
	if !is_wildcard_origin {
		h.insert(VARY, HeaderValue::from_static("Origin"));
	}
	Ok(())
}

pub fn handle_options_api(
	garage: Arc<Garage>,
	req: &Request<IncomingBody>,
	bucket_name: Option<String>,
) -> Result<Response<EmptyBody>, CommonError> {
	// FIXME: CORS rules of buckets with local aliases are
	// not taken into account.

	// If the bucket name is a global bucket name,
	// we try to apply the CORS rules of that bucket.
	// If a user has a local bucket name that has
	// the same name, its CORS rules won't be applied
	// and will be shadowed by the rules of the globally
	// existing bucket (but this is inevitable because
	// OPTIONS calls are not authenticated).
	if let Some(bn) = bucket_name {
		let helper = garage.bucket_helper();
		let bucket_opt = helper.resolve_global_bucket_fast(&bn)?;
		if let Some(bucket) = bucket_opt {
			let bucket_params = bucket.state.into_option().unwrap();
			handle_options_for_bucket(req, &bucket_params)
		} else {
			// If there is a bucket name in the request, but that name
			// does not correspond to a global alias for a bucket,
			// then it's either a non-existing bucket or a local bucket.
			// We have no way of knowing, because the request is not
			// authenticated and thus we can't resolve local aliases.
			// We take the permissive approach of allowing everything,
			// because we don't want to prevent web apps that use
			// local bucket names from making API calls.
			Ok(Response::builder()
				.header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
				.header(ACCESS_CONTROL_ALLOW_METHODS, "*")
				.header(ACCESS_CONTROL_ALLOW_HEADERS, "*")
				.status(StatusCode::OK)
				.body(EmptyBody::new())?)
		}
	} else {
		// If there is no bucket name in the request,
		// we are doing a ListBuckets call, which we want to allow
		// for all origins.
		Ok(Response::builder()
			.header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
			.header(ACCESS_CONTROL_ALLOW_METHODS, "GET")
			.status(StatusCode::OK)
			.body(EmptyBody::new())?)
	}
}

pub fn handle_options_for_bucket<B>(
	req: &Request<B>,
	bucket_params: &BucketParams,
) -> Result<Response<EmptyBody>, CommonError> {
	let origin = req
		.headers()
		.get("Origin")
		.ok_or_bad_request("Missing Origin header")?
		.to_str()?;
	let request_method = req
		.headers()
		.get(ACCESS_CONTROL_REQUEST_METHOD)
		.ok_or_bad_request("Missing Access-Control-Request-Method header")?
		.to_str()?;
	let request_headers = match req.headers().get(ACCESS_CONTROL_REQUEST_HEADERS) {
		Some(h) => h.to_str()?.split(',').map(|h| h.trim()).collect::<Vec<_>>(),
		None => vec![],
	};

	if let Some(cors_config) = bucket_params.cors_config.get().inner() {
		let matching_rule = cors_config
			.iter()
			.find(|rule| cors_rule_matches(rule, origin, request_method, request_headers.iter()));
		if let Some(rule) = matching_rule {
			let mut resp = Response::builder()
				.status(StatusCode::OK)
				.body(EmptyBody::new())?;
			add_cors_headers(&mut resp, rule, origin)
				.ok_or_internal_error("Invalid CORS configuration")?;
			// Preflight responses vary not only on Origin but also on the
			// requested method and requested headers, so caches must not
			// reuse one preflight decision for a different preflight input.
			resp.headers_mut().insert(
				VARY,
				"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
					.parse()
					.expect("static vary header"),
			);
			return Ok(resp);
		}
	}

	Err(CommonError::Forbidden(
		"This CORS request is not allowed.".into(),
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cors_rule(
		allow_origins: &[&str],
		allow_methods: &[&str],
		allow_headers: &[&str],
	) -> GarageCorsRule {
		GarageCorsRule {
			id: None,
			max_age_seconds: None,
			allow_origins: allow_origins.iter().map(|s| s.to_string()).collect(),
			allow_methods: allow_methods.iter().map(|s| s.to_string()).collect(),
			allow_headers: allow_headers.iter().map(|s| s.to_string()).collect(),
			expose_headers: vec![],
		}
	}

	#[test]
	fn matches_when_origin_method_and_headers_are_explicitly_allowed() {
		let rule = cors_rule(
			&["https://app.example.test"],
			&["GET", "PUT"],
			&["content-type", "x-custom"],
		);
		let headers = vec!["content-type", "x-custom"];

		assert!(cors_rule_matches(
			&rule,
			"https://app.example.test",
			"PUT",
			headers.iter(),
		));
	}

	#[test]
	fn does_not_match_when_origin_is_not_allowed() {
		let rule = cors_rule(&["https://app.example.test"], &["GET"], &["*"]);

		assert!(!cors_rule_matches(
			&rule,
			"https://evil.example.test",
			"GET",
			std::iter::empty::<&str>(),
		));
	}

	#[test]
	fn does_not_match_when_method_is_not_allowed() {
		let rule = cors_rule(&["*"], &["GET"], &["*"]);

		assert!(!cors_rule_matches(
			&rule,
			"https://app.example.test",
			"DELETE",
			std::iter::empty::<&str>(),
		));
	}

	#[test]
	fn does_not_match_when_a_requested_header_is_not_allowed() {
		let rule = cors_rule(&["*"], &["GET"], &["content-type"]);
		let headers = vec!["content-type", "x-not-allowed"];

		assert!(!cors_rule_matches(
			&rule,
			"https://app.example.test",
			"GET",
			headers.iter(),
		));
	}

	#[test]
	fn wildcard_origin_method_and_headers_match_anything() {
		let rule = cors_rule(&["*"], &["*"], &["*"]);
		let headers = vec!["x-anything"];

		assert!(cors_rule_matches(
			&rule,
			"https://app.example.test",
			"DELETE",
			headers.iter(),
		));
	}

	#[test]
	fn wildcard_origin_regex() {
		let rule = cors_rule(&["https://*.localhost.com"], &["*"], &["*"]);
		let headers = vec!["x-anything"];

		assert!(cors_rule_matches(
			&rule,
			"https://s3.localhost.com",
			"DELETE",
			headers.iter(),
		));
	}

	#[test]
	fn origin_matching_cases() {
		// (allow_origins, origin, expect_match)
		let cases: &[(&[&str], &str, bool)] = &[
			// exact match
			(
				&["https://app.example.test"],
				"https://app.example.test",
				true,
			),
			(
				&["https://app.example.test"],
				"https://other.example.test",
				false,
			),
			// full wildcard
			(&["*"], "https://anything.example.test", true),
			// subdomain glob
			(
				&["https://*.example.test"],
				"https://foo.example.test",
				true,
			),
			(&["https://*.example.test"], "https://example.test", false),
			(
				&["https://*.example.test"],
				"http://foo.example.test",
				false,
			),
			// multiple allowed origins, at least one should match
			(
				&["https://a.example.test", "https://b.example.test"],
				"https://b.example.test",
				true,
			),
			// match multiple origins
			(
				&["https://a*.example.test", "https://ab*.example.test"],
				"https://abc.example.test",
				true,
			),
			(
				&["https://a.example.test", "https://b.example.test"],
				"https://c.example.test",
				false,
			),
			// at most one '*' in a pattern is allowed
			(&["https://*.example.*"], "https://a.example.test", false),
			// domain changed with wildcard
			(
				&["https://*example.test"],
				"https://garageexample.test",
				true,
			),
			// trailing '*' matches any suffix, including the empty string,
			// so this also matches origins with anything (or nothing) after
			// "example."
			(&["https://example.*"], "https://example.test", true),
			(&["https://*example.test"], "https://example.test", true),
			(&["https://example.*"], "https://example.", true),
		];

		for (allow_origins, origin, expect_match) in cases {
			let rule = cors_rule(allow_origins, &["GET"], &["*"]);
			let got = cors_rule_matches(&rule, origin, "GET", std::iter::empty::<&str>());
			assert_eq!(
				got, *expect_match,
				"allow_origins={allow_origins:?}, origin={origin:?}: expected match={expect_match}, got {got}"
			);
		}
	}

	#[test]
	fn header_matching_cases() {
		// (allow_headers, requested_headers, expect_match)
		let cases: &[(&[&str], &[&str], bool)] = &[
			// exact match
			(&["content-type"], &["content-type"], true),
			(&["content-type"], &["x-custom"], false),
			// full wildcard
			(&["*"], &["x-anything"], true),
			// no headers requested always matches, regardless of allow_headers
			(&["content-type"], &[], true),
			(&[], &[], true),
			// prefix glob
			(&["x-amz-*"], &["x-amz-meta-foo"], true),
			(&["x-amz-*"], &["x-amz-"], true),
			(&["x-amz-*"], &["x-other"], false),
			// suffix glob
			(&["*-meta"], &["foo-meta"], true),
			(&["*-meta"], &["-meta"], true),
			(&["*-meta"], &["foo-meta-bar"], false),
			// multiple allowed headers, at least one should match per requested header
			(
				&["content-type", "x-amz-*"],
				&["content-type", "x-amz-meta-foo"],
				true,
			),
			(&["content-type", "x-amz-*"], &["x-other"], false),
			// all requested headers must be covered
			(&["content-type"], &["content-type", "x-custom"], false),
			// at most one '*' in a pattern is allowed
			(&["x-*-*"], &["x-a-b"], false),
		];

		for (allow_headers, requested_headers, expect_match) in cases {
			let rule = cors_rule(&["*"], &["GET"], allow_headers);
			let got = cors_rule_matches(
				&rule,
				"https://app.example.test",
				"GET",
				requested_headers.iter(),
			);
			assert_eq!(
				got, *expect_match,
				"allow_headers={allow_headers:?}, requested_headers={requested_headers:?}: expected match={expect_match}, got {got}"
			);
		}
	}

	fn bucket_params_with_rule(allow_origins: Vec<&str>) -> BucketParams {
		let mut bucket_params = BucketParams::default();
		bucket_params.cors_config.update(
			Some(vec![GarageCorsRule {
				id: Some("cors-test".into()),
				max_age_seconds: None,
				allow_origins: allow_origins.into_iter().map(str::to_string).collect(),
				allow_methods: vec!["GET".into(), "PUT".into()],
				allow_headers: vec!["*".into()],
				expose_headers: vec![],
			}])
			.into(),
		);
		bucket_params
	}

	fn preflight_request(origin: &str) -> Request<()> {
		Request::builder()
			.method("OPTIONS")
			.uri("http://example.test/bucket")
			.header("Origin", origin)
			.header(ACCESS_CONTROL_REQUEST_METHOD, "PUT")
			.body(())
			.unwrap()
	}

	#[test]
	fn preflight_with_single_allowed_origin_returns_request_origin() {
		let bucket_params = bucket_params_with_rule(vec!["https://app.example.test"]);
		let req = preflight_request("https://app.example.test");

		let resp = handle_options_for_bucket(&req, &bucket_params).unwrap();

		assert_eq!(
			resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
			"https://app.example.test"
		);
		let vary_values: Vec<_> = resp
			.headers()
			.get_all(VARY)
			.iter()
			.map(|value| value.to_str().unwrap())
			.collect();
		assert_eq!(
			vary_values,
			vec!["Origin, Access-Control-Request-Method, Access-Control-Request-Headers",]
		);
	}

	#[test]
	fn preflight_with_multiple_allowed_origins_reflects_request_origin() {
		let bucket_params = bucket_params_with_rule(vec![
			"https://app.example.test",
			"https://admin.example.test",
		]);
		let req = preflight_request("https://app.example.test");

		let resp = handle_options_for_bucket(&req, &bucket_params).unwrap();

		// This assertion documents the behavior browsers expect:
		// even if multiple origins are allowed by configuration, the
		// response should reflect the request origin rather than emit
		// a comma-separated list. It currently fails and is meant to
		// turn green once header generation is corrected.
		assert_eq!(
			resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
			"https://app.example.test"
		);
	}

	#[test]
	fn preflight_with_wildcard_allowed_origin_returns_wildcard() {
		let bucket_params = bucket_params_with_rule(vec!["*"]);
		let req = preflight_request("https://app.example.test");

		let resp = handle_options_for_bucket(&req, &bucket_params).unwrap();

		assert_eq!(
			resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
			"*"
		);
		let vary_values: Vec<_> = resp
			.headers()
			.get_all(VARY)
			.iter()
			.map(|value| value.to_str().unwrap())
			.collect();
		assert_eq!(
			vary_values,
			vec!["Origin, Access-Control-Request-Method, Access-Control-Request-Headers",]
		);
	}
}
