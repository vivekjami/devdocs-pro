//! OpenAPI 3.1 specification generator
//!
//! This module generates comprehensive OpenAPI specifications from analyzed
//! API traffic and inferred schemas.

use crate::documentation::DocumentationConfig;
use crate::errors::DevDocsError;
use crate::models::ApiEndpoint;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// OpenAPI specification generator
pub struct OpenApiGenerator {
    config: DocumentationConfig,
}

impl OpenApiGenerator {
    /// Create a new OpenAPI generator
    pub fn new(config: &DocumentationConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Generate complete OpenAPI 3.1 specification
    pub async fn generate_spec(
        &self,
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, Value>,
    ) -> Result<Value, DevDocsError> {
        let mut spec = Map::new();

        // OpenAPI version
        spec.insert("openapi".to_string(), json!("3.1.0"));

        // Info section
        spec.insert("info".to_string(), self.generate_info_section());

        // Servers section
        if let Some(base_url) = &self.config.base_url {
            spec.insert(
                "servers".to_string(),
                json!([{
                    "url": base_url,
                    "description": "API Server"
                }]),
            );
        }

        // Paths section
        spec.insert(
            "paths".to_string(),
            self.generate_paths_section(endpoints, schemas).await?,
        );

        // Components section
        spec.insert(
            "components".to_string(),
            self.generate_components_section(schemas),
        );

        // Tags section
        spec.insert("tags".to_string(), self.generate_tags_section(endpoints));

        Ok(Value::Object(spec))
    }

    /// Generate info section of OpenAPI spec
    fn generate_info_section(&self) -> Value {
        let mut info = Map::new();

        info.insert("title".to_string(), json!(self.config.title));
        info.insert("version".to_string(), json!(self.config.version));

        if let Some(description) = &self.config.description {
            info.insert("description".to_string(), json!(description));
        }

        if let Some(contact) = &self.config.contact {
            let mut contact_obj = Map::new();
            if let Some(name) = &contact.name {
                contact_obj.insert("name".to_string(), json!(name));
            }
            if let Some(email) = &contact.email {
                contact_obj.insert("email".to_string(), json!(email));
            }
            if let Some(url) = &contact.url {
                contact_obj.insert("url".to_string(), json!(url));
            }
            if !contact_obj.is_empty() {
                info.insert("contact".to_string(), Value::Object(contact_obj));
            }
        }

        if let Some(license) = &self.config.license {
            let mut license_obj = Map::new();
            license_obj.insert("name".to_string(), json!(license.name));
            if let Some(url) = &license.url {
                license_obj.insert("url".to_string(), json!(url));
            }
            info.insert("license".to_string(), Value::Object(license_obj));
        }

        Value::Object(info)
    }

    /// Generate paths section of OpenAPI spec
    async fn generate_paths_section(
        &self,
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, Value>,
    ) -> Result<Value, DevDocsError> {
        let mut paths = Map::new();

        // Group endpoints by path pattern
        let mut path_groups: HashMap<String, Vec<&ApiEndpoint>> = HashMap::new();
        for endpoint in endpoints {
            path_groups
                .entry(endpoint.path_pattern.clone())
                .or_default()
                .push(endpoint);
        }

        for (path_pattern, path_endpoints) in path_groups {
            let mut path_obj = Map::new();

            for endpoint in path_endpoints {
                let method = endpoint.method.to_lowercase();
                let operation = self.generate_operation(endpoint, schemas).await?;
                path_obj.insert(method, operation);
            }

            paths.insert(path_pattern, Value::Object(path_obj));
        }

        Ok(Value::Object(paths))
    }

    /// Generate operation object for an endpoint
    async fn generate_operation(
        &self,
        endpoint: &ApiEndpoint,
        schemas: &HashMap<String, Value>,
    ) -> Result<Value, DevDocsError> {
        let mut operation = Map::new();

        // Generate operation ID
        let operation_id = self.generate_operation_id(endpoint);
        operation.insert("operationId".to_string(), json!(operation_id));

        // Generate summary and description
        let (summary, description) = self.generate_operation_summary_description(endpoint);
        operation.insert("summary".to_string(), json!(summary));
        operation.insert("description".to_string(), json!(description));

        // Generate tags
        let tags = self.generate_operation_tags(endpoint);
        if !tags.is_empty() {
            operation.insert("tags".to_string(), json!(tags));
        }

        // Generate parameters
        let parameters = self.generate_parameters(endpoint);
        if !parameters.is_empty() {
            operation.insert("parameters".to_string(), json!(parameters));
        }

        // Generate request body
        if let Some(request_body) = self.generate_request_body(endpoint, schemas) {
            operation.insert("requestBody".to_string(), request_body);
        }

        // Generate responses
        operation.insert(
            "responses".to_string(),
            self.generate_responses(endpoint, schemas),
        );

        Ok(Value::Object(operation))
    }

    /// Generate operation ID from endpoint
    fn generate_operation_id(&self, endpoint: &ApiEndpoint) -> String {
        let method = endpoint.method.to_lowercase();
        let path_parts: Vec<&str> = endpoint
            .path_pattern
            .split('/')
            .filter(|part| !part.is_empty() && !part.starts_with('{'))
            .collect();

        if path_parts.is_empty() {
            format!("{}Root", method)
        } else {
            let resource = path_parts.join("_");
            format!("{}_{}", method, resource)
        }
    }

    /// Generate summary and description for operation
    fn generate_operation_summary_description(&self, endpoint: &ApiEndpoint) -> (String, String) {
        let method = &endpoint.method;
        let path = &endpoint.path_pattern;

        let summary = match method.as_str() {
            "GET" => {
                if path.contains("{id}") {
                    format!("Get a specific resource")
                } else {
                    format!("List resources")
                }
            }
            "POST" => format!("Create a new resource"),
            "PUT" => format!("Update a resource"),
            "PATCH" => format!("Partially update a resource"),
            "DELETE" => format!("Delete a resource"),
            _ => format!("{} operation", method),
        };

        let description = format!(
            "{} {} - {} requests processed, {:.1}ms average response time, {:.1}% success rate",
            method,
            path,
            endpoint.request_count,
            endpoint.avg_response_time_ms,
            endpoint.success_rate()
        );

        (summary, description)
    }

    /// Generate tags for operation
    fn generate_operation_tags(&self, endpoint: &ApiEndpoint) -> Vec<String> {
        let path_parts: Vec<&str> = endpoint
            .path_pattern
            .split('/')
            .filter(|part| !part.is_empty() && !part.starts_with('{'))
            .collect();

        if let Some(first_part) = path_parts.first() {
            vec![first_part.to_string()]
        } else {
            vec!["default".to_string()]
        }
    }

    /// Generate parameters for operation
    fn generate_parameters(&self, endpoint: &ApiEndpoint) -> Vec<Value> {
        let mut parameters = Vec::new();

        // Extract path parameters
        let path_params = self.extract_path_parameters(&endpoint.path_pattern);
        for param in path_params {
            parameters.push(json!({
                "name": param,
                "in": "path",
                "required": true,
                "schema": {
                    "type": "string"
                },
                "description": format!("The {} identifier", param)
            }));
        }

        // Add common query parameters based on method
        match endpoint.method.as_str() {
            "GET" => {
                if !endpoint.path_pattern.contains("{id}") {
                    // List endpoint - add pagination parameters
                    parameters.push(json!({
                        "name": "page",
                        "in": "query",
                        "required": false,
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 1
                        },
                        "description": "Page number for pagination"
                    }));

                    parameters.push(json!({
                        "name": "limit",
                        "in": "query",
                        "required": false,
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 20
                        },
                        "description": "Number of items per page"
                    }));
                }
            }
            _ => {}
        }

        parameters
    }

    /// Extract path parameters from path pattern
    fn extract_path_parameters(&self, path: &str) -> Vec<String> {
        let param_regex = regex::Regex::new(r"\{([^}]+)\}").unwrap();
        param_regex
            .captures_iter(path)
            .map(|cap| cap[1].to_string())
            .collect()
    }

    /// Generate request body specification
    fn generate_request_body(
        &self,
        endpoint: &ApiEndpoint,
        schemas: &HashMap<String, Value>,
    ) -> Option<Value> {
        // Only certain methods typically have request bodies
        if !matches!(endpoint.method.as_str(), "POST" | "PUT" | "PATCH") {
            return None;
        }

        // Look for request schema
        let schema_key = format!("{}_request", endpoint.path_pattern);
        let schema_ref = if schemas.contains_key(&schema_key) {
            format!(
                "#/components/schemas/{}",
                schema_key
                    .replace('/', "_")
                    .replace("{", "")
                    .replace("}", "")
            )
        } else {
            // Default schema
            "#/components/schemas/DefaultRequest".to_string()
        };

        Some(json!({
            "required": true,
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": schema_ref
                    }
                }
            }
        }))
    }

    /// Generate responses specification
    fn generate_responses(
        &self,
        endpoint: &ApiEndpoint,
        schemas: &HashMap<String, Value>,
    ) -> Value {
        let mut responses = Map::new();

        // Analyze status codes from endpoint statistics
        for (status_code, _count) in &endpoint.status_codes {
            let status_str = status_code.to_string();
            let description = self.get_status_description(*status_code);

            let mut response_obj = Map::new();
            response_obj.insert("description".to_string(), json!(description));

            // Add content for successful responses
            if (200..300).contains(status_code) {
                let schema_key = format!("{}_response", endpoint.path_pattern);
                let schema_ref = if schemas.contains_key(&schema_key) {
                    format!(
                        "#/components/schemas/{}",
                        schema_key
                            .replace('/', "_")
                            .replace("{", "")
                            .replace("}", "")
                    )
                } else {
                    "#/components/schemas/DefaultResponse".to_string()
                };

                response_obj.insert(
                    "content".to_string(),
                    json!({
                        "application/json": {
                            "schema": {
                                "$ref": schema_ref
                            }
                        }
                    }),
                );
            }

            responses.insert(status_str, Value::Object(response_obj));
        }

        // Add default response if no responses were found
        if responses.is_empty() {
            responses.insert(
                "200".to_string(),
                json!({
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/DefaultResponse"
                            }
                        }
                    }
                }),
            );
        }

        Value::Object(responses)
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

    /// Generate components section
    fn generate_components_section(&self, schemas: &HashMap<String, Value>) -> Value {
        let mut components = Map::new();
        let mut schemas_obj = Map::new();

        // Add inferred schemas
        for (schema_name, schema) in schemas {
            let component_name = schema_name
                .replace('/', "_")
                .replace("{", "")
                .replace("}", "");
            schemas_obj.insert(component_name, schema.clone());
        }

        // Add default schemas if none exist
        if schemas_obj.is_empty() {
            schemas_obj.insert(
                "DefaultRequest".to_string(),
                json!({
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "object",
                            "description": "Request data"
                        }
                    }
                }),
            );

            schemas_obj.insert(
                "DefaultResponse".to_string(),
                json!({
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "object",
                            "description": "Response data"
                        },
                        "message": {
                            "type": "string",
                            "description": "Response message"
                        }
                    }
                }),
            );
        }

        // Add error schemas
        schemas_obj.insert(
            "Error".to_string(),
            json!({
                "type": "object",
                "required": ["error", "message"],
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "Error code"
                    },
                    "message": {
                        "type": "string",
                        "description": "Error message"
                    },
                    "details": {
                        "type": "object",
                        "description": "Additional error details"
                    }
                }
            }),
        );

        components.insert("schemas".to_string(), Value::Object(schemas_obj));

        Value::Object(components)
    }

    /// Generate tags section
    fn generate_tags_section(&self, endpoints: &[ApiEndpoint]) -> Value {
        let mut tags_set = std::collections::HashSet::new();

        for endpoint in endpoints {
            let tags = self.generate_operation_tags(endpoint);
            for tag in tags {
                tags_set.insert(tag);
            }
        }

        let tags: Vec<Value> = tags_set
            .into_iter()
            .map(|tag| {
                json!({
                    "name": tag,
                    "description": format!("Operations related to {}", tag)
                })
            })
            .collect();

        json!(tags)
    }

    /// Update configuration
    pub fn update_config(&mut self, config: &DocumentationConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ApiEndpoint;

    #[tokio::test]
    async fn test_openapi_generator_creation() {
        let config = DocumentationConfig::default();
        let generator = OpenApiGenerator::new(&config);
        assert!(generator.is_ok());
    }

    #[test]
    fn test_operation_id_generation() {
        let config = DocumentationConfig::default();
        let generator = OpenApiGenerator::new(&config).unwrap();

        let endpoint = ApiEndpoint::new("/users/{id}".to_string(), "GET".to_string());
        let operation_id = generator.generate_operation_id(&endpoint);
        assert_eq!(operation_id, "get_users");

        let endpoint = ApiEndpoint::new("/api/v1/posts".to_string(), "POST".to_string());
        let operation_id = generator.generate_operation_id(&endpoint);
        assert_eq!(operation_id, "post_api_v1_posts");
    }

    #[test]
    fn test_path_parameter_extraction() {
        let config = DocumentationConfig::default();
        let generator = OpenApiGenerator::new(&config).unwrap();

        let params = generator.extract_path_parameters("/users/{id}/posts/{postId}");
        assert_eq!(params, vec!["id", "postId"]);

        let params = generator.extract_path_parameters("/api/v1/users");
        assert!(params.is_empty());
    }

    #[test]
    fn test_operation_tags_generation() {
        let config = DocumentationConfig::default();
        let generator = OpenApiGenerator::new(&config).unwrap();

        let endpoint = ApiEndpoint::new("/users/{id}".to_string(), "GET".to_string());
        let tags = generator.generate_operation_tags(&endpoint);
        assert_eq!(tags, vec!["users"]);

        let endpoint = ApiEndpoint::new("/api/v1/posts".to_string(), "POST".to_string());
        let tags = generator.generate_operation_tags(&endpoint);
        assert_eq!(tags, vec!["api"]);
    }

    #[tokio::test]
    async fn test_openapi_spec_generation() {
        let config = DocumentationConfig::default();
        let generator = OpenApiGenerator::new(&config).unwrap();

        let endpoints = vec![
            ApiEndpoint::new("/users".to_string(), "GET".to_string()),
            ApiEndpoint::new("/users/{id}".to_string(), "GET".to_string()),
        ];

        let schemas = HashMap::new();
        let spec = generator.generate_spec(&endpoints, &schemas).await.unwrap();

        assert!(spec.is_object());
        let spec_obj = spec.as_object().unwrap();
        assert!(spec_obj.contains_key("openapi"));
        assert!(spec_obj.contains_key("info"));
        assert!(spec_obj.contains_key("paths"));
        assert!(spec_obj.contains_key("components"));
    }
}
