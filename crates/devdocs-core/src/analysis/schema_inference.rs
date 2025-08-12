//! Schema inference engine for automatic API schema generation
//!
//! This module analyzes HTTP request and response data to automatically
//! infer JSON schemas, parameter types, and validation rules.

use crate::analysis::AnalysisConfig;
use crate::errors::DevDocsError;
use crate::models::TrafficSample;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

/// Inferred field information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldInfo {
    /// Field name
    pub name: String,
    /// Inferred type
    pub field_type: FieldType,
    /// Whether field is nullable
    pub nullable: bool,
    /// Confidence in type inference (0.0-1.0)
    pub confidence: f64,
    /// Example values seen
    pub examples: Vec<Value>,
    /// Validation constraints
    pub constraints: Option<ValidationConstraints>,
}

/// Inferred field types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FieldType {
    String,
    Number,
    Integer,
    Boolean,
    Array(Box<FieldType>),
    Object,
    Enum(Vec<String>),
    Union(Vec<FieldType>),
}

/// Validation constraints for fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationConstraints {
    /// Minimum length for strings
    pub min_length: Option<usize>,
    /// Maximum length for strings
    pub max_length: Option<usize>,
    /// Pattern for string validation
    pub pattern: Option<String>,
    /// Minimum value for numbers
    pub minimum: Option<f64>,
    /// Maximum value for numbers
    pub maximum: Option<f64>,
    /// Enum values
    pub enum_values: Option<Vec<String>>,
}

/// Schema inference engine
pub struct SchemaInferrer {
    config: AnalysisConfig,
    type_frequency: HashMap<String, HashMap<FieldType, usize>>,
    value_examples: HashMap<String, Vec<Value>>,
}

impl SchemaInferrer {
    /// Create a new schema inferrer
    pub fn new(config: &AnalysisConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
            type_frequency: HashMap::new(),
            value_examples: HashMap::new(),
        })
    }

    /// Infer schemas from traffic samples
    pub async fn infer_schemas(
        &mut self,
        samples: &[TrafficSample],
    ) -> Result<HashMap<String, Value>, DevDocsError> {
        let mut schemas = HashMap::new();

        // Group samples by endpoint
        let grouped_samples = self.group_samples_by_endpoint(samples);

        for (endpoint, endpoint_samples) in grouped_samples {
            // Analyze request schemas
            if let Some(request_schema) = self.infer_request_schema(&endpoint_samples).await? {
                schemas.insert(format!("{}_request", endpoint), request_schema);
            }

            // Analyze response schemas
            if let Some(response_schema) = self.infer_response_schema(&endpoint_samples).await? {
                schemas.insert(format!("{}_response", endpoint), response_schema);
            }
        }

        Ok(schemas)
    }

    /// Group samples by endpoint pattern
    fn group_samples_by_endpoint<'a>(
        &self,
        samples: &'a [TrafficSample],
    ) -> HashMap<String, Vec<&'a TrafficSample>> {
        let mut grouped = HashMap::new();

        for sample in samples {
            let endpoint_key = self.extract_endpoint_pattern(&sample.request.path);
            grouped
                .entry(endpoint_key)
                .or_insert_with(Vec::new)
                .push(sample);
        }

        grouped
    }

    /// Extract endpoint pattern from path (e.g., /users/123 -> /users/{id})
    fn extract_endpoint_pattern(&self, path: &str) -> String {
        let uuid_pattern = regex::Regex::new(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )
        .unwrap();
        let number_pattern = regex::Regex::new(r"/\d+").unwrap();

        let mut pattern = uuid_pattern.replace_all(path, "/{id}").to_string();
        pattern = number_pattern.replace_all(&pattern, "/{id}").to_string();

        pattern
    }

    /// Infer request schema from samples
    async fn infer_request_schema(
        &mut self,
        samples: &[&TrafficSample],
    ) -> Result<Option<Value>, DevDocsError> {
        let mut request_bodies = Vec::new();

        for sample in samples {
            if let Some(body) = &sample.request.body {
                if let Ok(json_body) = serde_json::from_slice::<Value>(&body.as_bytes()) {
                    request_bodies.push(json_body);
                }
            }
        }

        if request_bodies.is_empty() {
            return Ok(None);
        }

        let schema = self.infer_json_schema(&request_bodies).await?;
        Ok(Some(schema))
    }

    /// Infer response schema from samples
    async fn infer_response_schema(
        &mut self,
        samples: &[&TrafficSample],
    ) -> Result<Option<Value>, DevDocsError> {
        let mut response_bodies = Vec::new();

        for sample in samples {
            if let Some(response) = &sample.response {
                if let Some(body) = &response.body {
                    if let Ok(json_body) = serde_json::from_slice::<Value>(&body.as_bytes()) {
                        response_bodies.push(json_body);
                    }
                }
            }
        }

        if response_bodies.is_empty() {
            return Ok(None);
        }

        let schema = self.infer_json_schema(&response_bodies).await?;
        Ok(Some(schema))
    }

    /// Infer JSON schema from multiple JSON values
    async fn infer_json_schema(&mut self, values: &[Value]) -> Result<Value, DevDocsError> {
        if values.is_empty() {
            return Ok(Value::Object(Map::new()));
        }

        // Analyze all values to build field information
        let mut field_analysis = HashMap::new();
        for value in values {
            self.analyze_value("", value, &mut field_analysis);
        }

        // Convert field analysis to JSON schema
        let schema = self.build_json_schema(&field_analysis);
        Ok(schema)
    }

    /// Analyze a JSON value recursively
    fn analyze_value(
        &self,
        path: &str,
        value: &Value,
        analysis: &mut HashMap<String, Vec<FieldType>>,
    ) {
        match value {
            Value::Null => {
                analysis
                    .entry(path.to_string())
                    .or_default()
                    .push(FieldType::String);
            }
            Value::Bool(_) => {
                analysis
                    .entry(path.to_string())
                    .or_default()
                    .push(FieldType::Boolean);
            }
            Value::Number(n) => {
                if n.is_i64() {
                    analysis
                        .entry(path.to_string())
                        .or_default()
                        .push(FieldType::Integer);
                } else {
                    analysis
                        .entry(path.to_string())
                        .or_default()
                        .push(FieldType::Number);
                }
            }
            Value::String(s) => {
                // Check if string looks like an enum value
                if self.is_likely_enum_value(s) {
                    analysis
                        .entry(path.to_string())
                        .or_default()
                        .push(FieldType::Enum(vec![s.clone()]));
                } else {
                    analysis
                        .entry(path.to_string())
                        .or_default()
                        .push(FieldType::String);
                }
            }
            Value::Array(arr) => {
                if let Some(first) = arr.first() {
                    let element_path = format!("{}[]", path);
                    self.analyze_value(&element_path, first, analysis);
                }
                analysis
                    .entry(path.to_string())
                    .or_default()
                    .push(FieldType::Array(Box::new(FieldType::String)));
            }
            Value::Object(obj) => {
                for (key, val) in obj {
                    let field_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    self.analyze_value(&field_path, val, analysis);
                }
                analysis
                    .entry(path.to_string())
                    .or_default()
                    .push(FieldType::Object);
            }
        }
    }

    /// Check if a string value is likely an enum
    fn is_likely_enum_value(&self, value: &str) -> bool {
        // Simple heuristics for enum detection
        value.len() < 50
            && !value.contains(' ')
            && (value.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                || value.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
    }

    /// Build JSON schema from field analysis
    fn build_json_schema(&self, analysis: &HashMap<String, Vec<FieldType>>) -> Value {
        let mut schema = Map::new();
        schema.insert("type".to_string(), Value::String("object".to_string()));

        let mut properties = Map::new();
        let mut required = Vec::new();

        for (field_path, types) in analysis {
            if field_path.is_empty() || field_path.contains('.') || field_path.contains('[') {
                continue; // Skip nested fields for now
            }

            let field_type = self.determine_most_likely_type(types);
            let field_schema = self.type_to_json_schema(&field_type);
            properties.insert(field_path.clone(), field_schema);

            // Mark as required if seen in most samples
            if types.len() > analysis.len() / 2 {
                required.push(Value::String(field_path.clone()));
            }
        }

        schema.insert("properties".to_string(), Value::Object(properties));
        if !required.is_empty() {
            schema.insert("required".to_string(), Value::Array(required));
        }

        Value::Object(schema)
    }

    /// Determine the most likely type from observed types
    fn determine_most_likely_type(&self, types: &[FieldType]) -> FieldType {
        let mut type_counts = HashMap::new();
        for field_type in types {
            *type_counts.entry(field_type.clone()).or_insert(0) += 1;
        }

        type_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(field_type, _)| field_type)
            .unwrap_or(FieldType::String)
    }

    /// Convert FieldType to JSON schema
    fn type_to_json_schema(&self, field_type: &FieldType) -> Value {
        let mut schema = Map::new();

        match field_type {
            FieldType::String => {
                schema.insert("type".to_string(), Value::String("string".to_string()));
            }
            FieldType::Number => {
                schema.insert("type".to_string(), Value::String("number".to_string()));
            }
            FieldType::Integer => {
                schema.insert("type".to_string(), Value::String("integer".to_string()));
            }
            FieldType::Boolean => {
                schema.insert("type".to_string(), Value::String("boolean".to_string()));
            }
            FieldType::Array(element_type) => {
                schema.insert("type".to_string(), Value::String("array".to_string()));
                schema.insert("items".to_string(), self.type_to_json_schema(element_type));
            }
            FieldType::Object => {
                schema.insert("type".to_string(), Value::String("object".to_string()));
            }
            FieldType::Enum(values) => {
                schema.insert("type".to_string(), Value::String("string".to_string()));
                schema.insert(
                    "enum".to_string(),
                    Value::Array(values.iter().map(|v| Value::String(v.clone())).collect()),
                );
            }
            FieldType::Union(types) => {
                let type_schemas: Vec<Value> =
                    types.iter().map(|t| self.type_to_json_schema(t)).collect();
                schema.insert("anyOf".to_string(), Value::Array(type_schemas));
            }
        }

        Value::Object(schema)
    }

    /// Update configuration
    pub fn update_config(&mut self, config: &AnalysisConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_capture::{BodyStorage, CapturedBody, CompressionType, ContentPriority};
    use crate::models::{HttpRequest, HttpResponse};

    #[tokio::test]
    async fn test_schema_inferrer_creation() {
        let config = AnalysisConfig::default();
        let inferrer = SchemaInferrer::new(&config);
        assert!(inferrer.is_ok());
    }

    #[test]
    fn test_endpoint_pattern_extraction() {
        let config = AnalysisConfig::default();
        let inferrer = SchemaInferrer::new(&config).unwrap();

        assert_eq!(
            inferrer.extract_endpoint_pattern("/users/123"),
            "/users/{id}"
        );
        assert_eq!(
            inferrer.extract_endpoint_pattern("/api/v1/posts/456/comments"),
            "/api/v1/posts/{id}/comments"
        );
    }

    #[test]
    fn test_enum_detection() {
        let config = AnalysisConfig::default();
        let inferrer = SchemaInferrer::new(&config).unwrap();

        assert!(inferrer.is_likely_enum_value("ACTIVE"));
        assert!(inferrer.is_likely_enum_value("pending"));
        assert!(!inferrer.is_likely_enum_value("This is a long description"));
    }

    #[tokio::test]
    async fn test_json_schema_inference() {
        let config = AnalysisConfig::default();
        let mut inferrer = SchemaInferrer::new(&config).unwrap();

        let values = vec![
            serde_json::json!({"name": "John", "age": 30, "active": true}),
            serde_json::json!({"name": "Jane", "age": 25, "active": false}),
        ];

        let schema = inferrer.infer_json_schema(&values).await.unwrap();
        assert!(schema.is_object());

        let schema_obj = schema.as_object().unwrap();
        assert!(schema_obj.contains_key("properties"));
        assert!(schema_obj.contains_key("type"));
    }

    #[tokio::test]
    async fn test_traffic_sample_schema_inference() {
        let config = AnalysisConfig::default();
        let mut inferrer = SchemaInferrer::new(&config).unwrap();

        // Create sample with JSON body
        let json_body = serde_json::json!({"user_id": 123, "name": "Test User"});
        let body_bytes = serde_json::to_vec(&json_body).unwrap();

        let captured_body = CapturedBody {
            content_type: Some("application/json".to_string()),
            compression: CompressionType::None,
            priority: ContentPriority::High,
            original_size: body_bytes.len(),
            storage: BodyStorage::Memory(body_bytes),
        };

        let request = HttpRequest::new(
            "POST".to_string(),
            "/users".to_string(),
            "corr-123".to_string(),
        )
        .with_body(captured_body);

        let response_body = serde_json::json!({"id": 123, "status": "created"});
        let response_bytes = serde_json::to_vec(&response_body).unwrap();

        let response_captured_body = CapturedBody {
            content_type: Some("application/json".to_string()),
            compression: CompressionType::None,
            priority: ContentPriority::High,
            original_size: response_bytes.len(),
            storage: BodyStorage::Memory(response_bytes),
        };

        let response = HttpResponse::new(request.id, 201).with_body(response_captured_body);

        let sample = TrafficSample::new(request, "/users".to_string()).with_response(response);

        let samples = vec![sample];
        let schemas = inferrer.infer_schemas(&samples).await.unwrap();

        // Should have both request and response schemas
        assert!(schemas.contains_key("/users_request"));
        assert!(schemas.contains_key("/users_response"));
    }
}
