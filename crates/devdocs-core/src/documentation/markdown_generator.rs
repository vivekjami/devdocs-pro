//! Markdown documentation generator
//!
//! This module generates clean Markdown documentation that can be used
//! in README files, wikis, or converted to other formats.

use crate::documentation::DocumentationConfig;
use crate::errors::DevDocsError;
use crate::models::ApiEndpoint;
use serde_json::Value;
use std::collections::HashMap;

/// Markdown documentation generator
pub struct MarkdownGenerator {
    config: DocumentationConfig,
}

impl MarkdownGenerator {
    /// Create a new Markdown generator
    pub fn new(config: &DocumentationConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Generate comprehensive Markdown documentation
    pub async fn generate_markdown(
        &self,
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, Value>,
        ai_documentation: Option<&str>,
    ) -> Result<String, DevDocsError> {
        let mut markdown = String::new();

        // Title and description
        markdown.push_str(&format!("# {}\n\n", self.config.title));

        if let Some(description) = &self.config.description {
            markdown.push_str(&format!("{}\n\n", description));
        }

        // Version and contact info
        markdown.push_str(&format!("**Version:** {}\n\n", self.config.version));

        if let Some(contact) = &self.config.contact {
            if let Some(email) = &contact.email {
                markdown.push_str(&format!("**Contact:** {}\n\n", email));
            }
        }

        // Base URL
        if let Some(base_url) = &self.config.base_url {
            markdown.push_str(&format!("**Base URL:** `{}`\n\n", base_url));
        }

        // Table of contents
        markdown.push_str("## Table of Contents\n\n");
        markdown.push_str("- [Overview](#overview)\n");
        if ai_documentation.is_some() {
            markdown.push_str("- [AI-Generated Documentation](#ai-generated-documentation)\n");
        }
        markdown.push_str("- [Authentication](#authentication)\n");
        markdown.push_str("- [Endpoints](#endpoints)\n");
        if !schemas.is_empty() {
            markdown.push_str("- [Data Models](#data-models)\n");
        }
        markdown.push_str("- [Error Handling](#error-handling)\n");
        markdown.push_str("\n");

        // Overview section
        markdown.push_str("## Overview\n\n");
        markdown.push_str(&self.generate_overview_section(endpoints));

        // AI documentation section
        if let Some(ai_docs) = ai_documentation {
            markdown.push_str("## AI-Generated Documentation\n\n");
            markdown.push_str(ai_docs);
            markdown.push_str("\n\n");
        }

        // Authentication section
        markdown.push_str("## Authentication\n\n");
        markdown.push_str(&self.generate_authentication_section(endpoints));

        // Endpoints section
        markdown.push_str("## Endpoints\n\n");
        markdown.push_str(&self.generate_endpoints_section(endpoints));

        // Data models section
        if !schemas.is_empty() {
            markdown.push_str("## Data Models\n\n");
            markdown.push_str(&self.generate_schemas_section(schemas));
        }

        // Error handling section
        markdown.push_str("## Error Handling\n\n");
        markdown.push_str(&self.generate_error_handling_section(endpoints));

        Ok(markdown)
    }

    /// Generate overview section
    fn generate_overview_section(&self, endpoints: &[ApiEndpoint]) -> String {
        let mut overview = String::new();

        overview.push_str("This API provides the following functionality:\n\n");

        // Group endpoints by resource
        let mut resource_groups: HashMap<String, Vec<&ApiEndpoint>> = HashMap::new();
        for endpoint in endpoints {
            let resource = self.extract_resource_name(&endpoint.path_pattern);
            resource_groups.entry(resource).or_default().push(endpoint);
        }

        for (resource, resource_endpoints) in resource_groups {
            overview.push_str(&format!("### {} Operations\n\n", resource));

            for endpoint in resource_endpoints {
                let operation_desc = self.describe_operation(endpoint);
                overview.push_str(&format!("- **{}** - {}\n", endpoint.method, operation_desc));
            }

            overview.push_str("\n");
        }

        // API statistics
        overview.push_str("### API Statistics\n\n");
        overview.push_str(&format!("- **Total Endpoints:** {}\n", endpoints.len()));

        let total_requests: u64 = endpoints.iter().map(|e| e.request_count).sum();
        overview.push_str(&format!(
            "- **Total Requests Analyzed:** {}\n",
            total_requests
        ));

        let avg_response_time: f64 = endpoints
            .iter()
            .map(|e| e.avg_response_time_ms)
            .sum::<f64>()
            / endpoints.len() as f64;
        overview.push_str(&format!(
            "- **Average Response Time:** {:.1}ms\n",
            avg_response_time
        ));

        let overall_success_rate: f64 =
            endpoints.iter().map(|e| e.success_rate()).sum::<f64>() / endpoints.len() as f64;
        overview.push_str(&format!(
            "- **Overall Success Rate:** {:.1}%\n\n",
            overall_success_rate
        ));

        overview
    }

    /// Extract resource name from path pattern
    fn extract_resource_name(&self, path: &str) -> String {
        let parts: Vec<&str> = path
            .split('/')
            .filter(|p| !p.is_empty() && !p.starts_with('{'))
            .collect();

        if parts.is_empty() {
            "Root".to_string()
        } else {
            parts
                .last()
                .map_or("Unknown", |v| v)
                .to_string()
                .to_title_case()
        }
    }

    /// Describe what an operation does
    fn describe_operation(&self, endpoint: &ApiEndpoint) -> String {
        match endpoint.method.as_str() {
            "GET" => {
                if endpoint.path_pattern.contains("{id}") {
                    "Retrieve a specific resource".to_string()
                } else {
                    "List resources".to_string()
                }
            }
            "POST" => "Create a new resource".to_string(),
            "PUT" => "Update a resource completely".to_string(),
            "PATCH" => "Update a resource partially".to_string(),
            "DELETE" => "Delete a resource".to_string(),
            _ => format!("{} operation", endpoint.method),
        }
    }

    /// Generate authentication section
    fn generate_authentication_section(&self, _endpoints: &[ApiEndpoint]) -> String {
        let mut auth = String::new();

        auth.push_str("This API uses the following authentication methods:\n\n");

        // This is a placeholder - in a real implementation, we'd analyze headers
        // from the traffic samples to detect authentication patterns
        auth.push_str("- **API Key**: Include your API key in the `Authorization` header\n");
        auth.push_str(
            "- **Bearer Token**: Use `Authorization: Bearer <token>` for JWT authentication\n\n",
        );

        auth.push_str("### Example Authentication\n\n");
        auth.push_str("```bash\n");
        auth.push_str("curl -H \"Authorization: Bearer YOUR_TOKEN\" \\\n");
        if let Some(base_url) = &self.config.base_url {
            auth.push_str(&format!("  {}/api/endpoint\n", base_url));
        } else {
            auth.push_str("  https://api.example.com/endpoint\n");
        }
        auth.push_str("```\n\n");

        auth
    }

    /// Generate endpoints section
    fn generate_endpoints_section(&self, endpoints: &[ApiEndpoint]) -> String {
        let mut endpoints_doc = String::new();

        // Group by path pattern
        let mut path_groups: HashMap<String, Vec<&ApiEndpoint>> = HashMap::new();
        for endpoint in endpoints {
            path_groups
                .entry(endpoint.path_pattern.clone())
                .or_default()
                .push(endpoint);
        }

        for (path_pattern, path_endpoints) in path_groups {
            endpoints_doc.push_str(&format!("### `{}`\n\n", path_pattern));

            for endpoint in path_endpoints {
                endpoints_doc.push_str(&self.generate_endpoint_documentation(endpoint));
            }
        }

        endpoints_doc
    }

    /// Generate documentation for a single endpoint
    fn generate_endpoint_documentation(&self, endpoint: &ApiEndpoint) -> String {
        let mut doc = String::new();

        // Method and summary
        doc.push_str(&format!(
            "#### {} {}\n\n",
            endpoint.method, endpoint.path_pattern
        ));

        let operation_desc = self.describe_operation(endpoint);
        doc.push_str(&format!("{}\n\n", operation_desc));

        // Statistics
        doc.push_str("**Statistics:**\n");
        doc.push_str(&format!(
            "- Requests analyzed: {}\n",
            endpoint.request_count
        ));
        doc.push_str(&format!(
            "- Average response time: {:.1}ms\n",
            endpoint.avg_response_time_ms
        ));
        doc.push_str(&format!(
            "- Success rate: {:.1}%\n\n",
            endpoint.success_rate()
        ));

        // Parameters
        let path_params = self.extract_path_parameters(&endpoint.path_pattern);
        if !path_params.is_empty() {
            doc.push_str("**Path Parameters:**\n\n");
            doc.push_str("| Parameter | Type | Description |\n");
            doc.push_str("|-----------|------|--------------|\n");

            for param in path_params {
                doc.push_str(&format!(
                    "| `{}` | string | The {} identifier |\n",
                    param, param
                ));
            }
            doc.push_str("\n");
        }

        // Query parameters for GET requests
        if endpoint.method == "GET" && !endpoint.path_pattern.contains("{id}") {
            doc.push_str("**Query Parameters:**\n\n");
            doc.push_str("| Parameter | Type | Required | Description |\n");
            doc.push_str("|-----------|------|----------|-------------|\n");
            doc.push_str("| `page` | integer | No | Page number for pagination (default: 1) |\n");
            doc.push_str("| `limit` | integer | No | Number of items per page (default: 20) |\n");
            doc.push_str("\n");
        }

        // Request body for POST/PUT/PATCH
        if matches!(endpoint.method.as_str(), "POST" | "PUT" | "PATCH") {
            doc.push_str("**Request Body:**\n\n");
            doc.push_str("```json\n");
            doc.push_str("{\n");
            doc.push_str("  \"data\": {\n");
            doc.push_str("    // Request data based on the resource\n");
            doc.push_str("  }\n");
            doc.push_str("}\n");
            doc.push_str("```\n\n");
        }

        // Response examples
        doc.push_str("**Response Examples:**\n\n");

        // Success response
        doc.push_str("**Success (200 OK):**\n");
        doc.push_str("```json\n");
        doc.push_str("{\n");
        doc.push_str("  \"data\": {\n");
        doc.push_str("    // Response data\n");
        doc.push_str("  },\n");
        doc.push_str("  \"message\": \"Success\"\n");
        doc.push_str("}\n");
        doc.push_str("```\n\n");

        // Error response
        doc.push_str("**Error (4xx/5xx):**\n");
        doc.push_str("```json\n");
        doc.push_str("{\n");
        doc.push_str("  \"error\": \"ERROR_CODE\",\n");
        doc.push_str("  \"message\": \"Error description\",\n");
        doc.push_str("  \"details\": {}\n");
        doc.push_str("}\n");
        doc.push_str("```\n\n");

        // cURL example
        doc.push_str("**cURL Example:**\n\n");
        doc.push_str("```bash\n");
        doc.push_str(&self.generate_curl_example(endpoint));
        doc.push_str("```\n\n");

        doc.push_str("---\n\n");
        doc
    }

    /// Extract path parameters from path pattern
    fn extract_path_parameters(&self, path: &str) -> Vec<String> {
        let param_regex = regex::Regex::new(r"\{([^}]+)\}").unwrap();
        param_regex
            .captures_iter(path)
            .map(|cap| cap[1].to_string())
            .collect()
    }

    /// Generate cURL example for endpoint
    fn generate_curl_example(&self, endpoint: &ApiEndpoint) -> String {
        let mut curl = String::new();

        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or("https://api.example.com");
        let path = endpoint.path_pattern.replace("{id}", "123");

        curl.push_str(&format!("curl -X {} \\\n", endpoint.method));
        curl.push_str("  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n");
        curl.push_str("  -H \"Content-Type: application/json\" \\\n");

        if matches!(endpoint.method.as_str(), "POST" | "PUT" | "PATCH") {
            curl.push_str("  -d '{\n");
            curl.push_str("    \"data\": {\n");
            curl.push_str("      // Your request data\n");
            curl.push_str("    }\n");
            curl.push_str("  }' \\\n");
        }

        curl.push_str(&format!("  {}{}\n", base_url, path));

        curl
    }

    /// Generate schemas section
    fn generate_schemas_section(&self, schemas: &HashMap<String, Value>) -> String {
        let mut schemas_doc = String::new();

        schemas_doc.push_str("The following data models are used by this API:\n\n");

        for (schema_name, schema) in schemas {
            schemas_doc.push_str(&format!("### {}\n\n", schema_name));

            if let Some(description) = schema.get("description") {
                schemas_doc.push_str(&format!("{}\n\n", description.as_str().unwrap_or("")));
            }

            schemas_doc.push_str("```json\n");
            schemas_doc.push_str(&serde_json::to_string_pretty(schema).unwrap_or_default());
            schemas_doc.push_str("\n```\n\n");
        }

        schemas_doc
    }

    /// Generate error handling section
    fn generate_error_handling_section(&self, endpoints: &[ApiEndpoint]) -> String {
        let mut error_doc = String::new();

        error_doc.push_str(
            "This API uses conventional HTTP response codes to indicate success or failure:\n\n",
        );

        // Collect all status codes from endpoints
        let mut all_status_codes = std::collections::HashSet::new();
        for endpoint in endpoints {
            for &status_code in endpoint.status_codes.keys() {
                all_status_codes.insert(status_code);
            }
        }

        let mut status_codes: Vec<u16> = all_status_codes.into_iter().collect();
        status_codes.sort();

        error_doc.push_str("| Status Code | Description |\n");
        error_doc.push_str("|-------------|-------------|\n");

        for status_code in status_codes {
            let description = self.get_status_description(status_code);
            error_doc.push_str(&format!("| {} | {} |\n", status_code, description));
        }

        error_doc.push_str("\n### Error Response Format\n\n");
        error_doc.push_str("All error responses follow this format:\n\n");
        error_doc.push_str("```json\n");
        error_doc.push_str("{\n");
        error_doc.push_str("  \"error\": \"ERROR_CODE\",\n");
        error_doc.push_str("  \"message\": \"Human-readable error message\",\n");
        error_doc.push_str("  \"details\": {\n");
        error_doc.push_str("    // Additional error context (optional)\n");
        error_doc.push_str("  }\n");
        error_doc.push_str("}\n");
        error_doc.push_str("```\n\n");

        error_doc
    }

    /// Get description for HTTP status code
    fn get_status_description(&self, status_code: u16) -> String {
        match status_code {
            200 => "OK - Request successful".to_string(),
            201 => "Created - Resource created successfully".to_string(),
            204 => "No Content - Request successful, no content returned".to_string(),
            400 => "Bad Request - Invalid request parameters".to_string(),
            401 => "Unauthorized - Authentication required".to_string(),
            403 => "Forbidden - Access denied".to_string(),
            404 => "Not Found - Resource not found".to_string(),
            409 => "Conflict - Resource conflict".to_string(),
            422 => "Unprocessable Entity - Validation error".to_string(),
            500 => "Internal Server Error - Server error".to_string(),
            _ => format!("HTTP {}", status_code),
        }
    }

    /// Update configuration
    pub fn update_config(&mut self, config: &DocumentationConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        Ok(())
    }
}

/// Extension trait for string title case conversion
trait ToTitleCase {
    fn to_title_case(&self) -> String;
}

impl ToTitleCase for str {
    fn to_title_case(&self) -> String {
        let mut result = String::new();
        let mut capitalize_next = true;

        for ch in self.chars() {
            if ch.is_alphabetic() {
                if capitalize_next {
                    result.push(ch.to_uppercase().next().unwrap_or(ch));
                    capitalize_next = false;
                } else {
                    result.push(ch.to_lowercase().next().unwrap_or(ch));
                }
            } else {
                result.push(ch);
                capitalize_next = true;
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_markdown_generator_creation() {
        let config = DocumentationConfig::default();
        let generator = MarkdownGenerator::new(&config);
        assert!(generator.is_ok());
    }

    #[tokio::test]
    async fn test_markdown_generation() {
        let config = DocumentationConfig::default();
        let generator = MarkdownGenerator::new(&config).unwrap();

        let endpoints = vec![
            ApiEndpoint::new("/users".to_string(), "GET".to_string()),
            ApiEndpoint::new("/users/{id}".to_string(), "GET".to_string()),
        ];

        let schemas = HashMap::new();
        let markdown = generator
            .generate_markdown(&endpoints, &schemas, None)
            .await
            .unwrap();

        assert!(markdown.contains("# API Documentation"));
        assert!(markdown.contains("## Table of Contents"));
        assert!(markdown.contains("## Endpoints"));
        assert!(markdown.contains("/users"));
        assert!(markdown.contains("GET"));
    }

    #[test]
    fn test_resource_name_extraction() {
        let config = DocumentationConfig::default();
        let generator = MarkdownGenerator::new(&config).unwrap();

        assert_eq!(generator.extract_resource_name("/users"), "Users");
        assert_eq!(generator.extract_resource_name("/api/v1/posts"), "Posts");
        assert_eq!(
            generator.extract_resource_name("/users/{id}/comments"),
            "Comments"
        );
    }

    #[test]
    fn test_path_parameter_extraction() {
        let config = DocumentationConfig::default();
        let generator = MarkdownGenerator::new(&config).unwrap();

        let params = generator.extract_path_parameters("/users/{id}/posts/{postId}");
        assert_eq!(params, vec!["id", "postId"]);

        let params = generator.extract_path_parameters("/api/v1/users");
        assert!(params.is_empty());
    }

    #[test]
    fn test_title_case_conversion() {
        assert_eq!("hello world".to_title_case(), "Hello World");
        assert_eq!("API_ENDPOINT".to_title_case(), "Api_Endpoint");
        assert_eq!("users".to_title_case(), "Users");
    }
}
