//! Utility functions for DevDocs Pro

use std::collections::HashMap;

/// Parse query parameters from a query string
pub fn parse_query_params(query: &str) -> HashMap<String, String> {
    if query.is_empty() {
        return HashMap::new();
    }

    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.split('=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => Some((
                    urlencoding::decode(key).unwrap_or_default().to_string(),
                    urlencoding::decode(value).unwrap_or_default().to_string(),
                )),
                _ => None,
            }
        })
        .collect()
}

/// Extract endpoint pattern from a path by replacing IDs with placeholders
pub fn extract_endpoint_pattern(path: &str) -> String {
    let uuid_pattern = regex::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .unwrap();
    let numeric_pattern = regex::Regex::new(r"/\d+(/|$)").unwrap();

    let mut pattern = path.to_string();
    pattern = uuid_pattern.replace_all(&pattern, "{id}").to_string();
    pattern = numeric_pattern.replace_all(&pattern, "/{id}$1").to_string();

    pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_params() {
        let params = parse_query_params("page=1&limit=10&sort=name");
        assert_eq!(params.len(), 3);
        assert_eq!(params.get("page"), Some(&"1".to_string()));
        assert_eq!(params.get("limit"), Some(&"10".to_string()));
        assert_eq!(params.get("sort"), Some(&"name".to_string()));
    }

    #[test]
    fn test_extract_endpoint_pattern() {
        assert_eq!(extract_endpoint_pattern("/users/123"), "/users/{id}");
        assert_eq!(
            extract_endpoint_pattern("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{id}"
        );
        assert_eq!(extract_endpoint_pattern("/api/v1/posts"), "/api/v1/posts");
    }
}
