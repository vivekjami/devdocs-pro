//! JSON Schema inference from captured HTTP bodies

use serde_json::Value;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::body_capture::{CapturedBody, ContentPriority};
use crate::errors::{DevDocsError, Result};

#[derive(Debug, Clone)]
pub struct SchemaInferrer {
    sample_limit: usize,
    min_samples_for_required: usize,
}

impl SchemaInferrer {
    pub fn new() -> Self {
        Self { 
            sample_limit: 5,
            min_samples_for_required: 3,
        }
    }
    
    pub async fn infer_from_json_bodies(&self, bodies: &[&CapturedBody]) -> Result<JsonSchema> {
        let mut schema_builder = JsonSchemaBuilder::new();
        let mut samples_processed = 0;
        
        // Process high-priority bodies first (JSON/XML API responses)
        for body in bodies.iter()
            .filter(|b| b.priority == ContentPriority::High)
            .take(self.sample_limit) 
        {
            if let Ok(text) = body.get_text().await {
                if let Ok(json) = serde_json::from_str::<Value>(&text) {
                    schema_builder.analyze_sample(&json);
                    samples_processed += 1;
                }
            }
        }
        
        if samples_processed == 0 {
            return Err(DevDocsError::InvalidRequest("No valid JSON samples found".into()));
        }
        
        Ok(schema_builder.build(self.min_samples_for_required))
    }
    
    pub async fn extract_json_examples(&self, bodies: &[&CapturedBody], limit: usize) -> Vec<String> {
        let mut examples = Vec::new();
        
        for body in bodies.iter()
            .filter(|b| b.priority == ContentPriority::High)
            .take(limit) 
        {
            if let Ok(text) = body.get_text().await {
                if serde_json::from_str::<Value>(&text).is_ok() {
                    examples.push(text);
                }
            }
        }
        
        examples
    }
}

impl Default for SchemaInferrer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct JsonSchemaBuilder {
    property_types: HashMap<String, TypeCounter>,
    property_values: HashMap<String, Vec<Value>>,
    required_fields: HashMap<String, usize>,
    total_samples: usize,
}

impl JsonSchemaBuilder {
    fn new() -> Self {
        Self::default()
    }
    
    fn analyze_sample(&mut self, json: &Value) {
        self.total_samples += 1;
        self.analyze_object("", json);
    }
    
    fn analyze_object(&mut self, prefix: &str, value: &Value) {
        match value {
            Value::Object(obj) => {
                for (key, val) in obj {
                    let field_path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    
                    // Track field presence
                    *self.required_fields.entry(field_path.clone()).or_insert(0) += 1;
                    
                    // Track field type
                    self.property_types.entry(field_path.clone())
                        .or_insert_with(TypeCounter::new)
                        .add_value(val);
                    
                    // Store sample values (limited)
                    let values = self.property_values.entry(field_path.clone())
                        .or_insert_with(Vec::new);
                    if values.len() < 5 {
                        values.push(val.clone());
                    }
                    
                    // Recursively analyze nested objects
                    self.analyze_object(&field_path, val);
                }
            }
            Value::Array(arr) => {
                if let Some(first_item) = arr.first() {
                    // Analyze array item structure
                    let item_prefix = format!("{}[]", prefix);
                    self.analyze_object(&item_prefix, first_item);
                }
            }
            _ => {} // Primitive values are handled by type counting
        }
    }
    
    fn build(&self, min_samples_for_required: usize) -> JsonSchema {
        let mut properties = HashMap::new();
        let mut required = Vec::new();
        
        // Only include top-level properties (no dots in path)
        let top_level_props: HashMap<_, _> = self.property_types.iter()
            .filter(|(path, _)| !path.contains('.') && !path.contains("[]"))
            .collect();
        
        for (field_path, counter) in top_level_props {
            // Calculate probability this field is required
            let presence_count = self.required_fields.get(field_path).unwrap_or(&0);
            let presence_ratio = *presence_count as f64 / self.total_samples as f64;
                
            // Fields present in most samples are considered required
            if *presence_count >= min_samples_for_required && presence_ratio > 0.6 {
                required.push(field_path.clone());
            }
            
            // Determine most likely type
            let property_type = counter.most_common_type();
            
            // Get example values
            let examples = self.property_values.get(field_path)
                .map(|v| v.clone())
                .unwrap_or_default();
            
            properties.insert(field_path.clone(), PropertySchema {
                property_type,
                description: None, // Will be filled by AI
                format: Self::detect_format(&examples),
                enum_values: Self::detect_enum(&examples),
                nullable: counter.contains_null,
                examples: examples.into_iter().take(3).collect(),
            });
        }
        
        JsonSchema {
            schema_type: "object".to_string(),
            properties,
            required,
            examples: Vec::new(), // Full examples added separately
        }
    }
    
    fn detect_format(examples: &[Value]) -> Option<String> {
        // Detect common formats like date-time, email, etc.
        for example in examples {
            if let Value::String(s) = example {
                // Basic format detection
                if s.contains('@') && s.contains('.') {
                    return Some("email".to_string());
                }
                if s.contains('T') && s.contains('Z') {
                    return Some("date-time".to_string());
                }
                if s.starts_with("http") {
                    return Some("uri".to_string());
                }
            }
        }
        None
    }
    
    fn detect_enum(examples: &[Value]) -> Option<Vec<String>> {
        if examples.len() < 2 {
            return None;
        }
        
        // If all examples are strings and there are few unique values, might be enum
        let string_values: Vec<_> = examples.iter()
            .filter_map(|v| v.as_str())
            .collect();
            
        if string_values.len() == examples.len() && string_values.len() <= 5 {
            let unique_values: std::collections::HashSet<_> = string_values.into_iter().collect();
            if unique_values.len() <= 3 {
                return Some(unique_values.into_iter().map(|s| s.to_string()).collect());
            }
        }
        
        None
    }
}

#[derive(Debug, Default)]
struct TypeCounter {
    string_count: usize,
    number_count: usize,
    boolean_count: usize,
    object_count: usize,
    array_count: usize,
    null_count: usize,
    contains_null: bool,
}

impl TypeCounter {
    fn new() -> Self {
        Self::default()
    }
    
    fn add_value(&mut self, value: &Value) {
        match value {
            Value::String(_) => self.string_count += 1,
            Value::Number(_) => self.number_count += 1,
            Value::Bool(_) => self.boolean_count += 1,
            Value::Object(_) => self.object_count += 1,
            Value::Array(_) => self.array_count += 1,
            Value::Null => {
                self.null_count += 1;
                self.contains_null = true;
            }
        }
    }
    
    fn most_common_type(&self) -> String {
        let counts = [
            ("string", self.string_count),
            ("number", self.number_count),
            ("boolean", self.boolean_count),
            ("object", self.object_count),
            ("array", self.array_count),
        ];
        
        counts.iter()
            .max_by_key(|(_, count)| count)
            .map(|(type_name, _)| type_name.to_string())
            .unwrap_or_else(|| "string".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    pub properties: HashMap<String, PropertySchema>,
    pub required: Vec<String>,
    pub examples: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySchema {
    #[serde(rename = "type")]
    pub property_type: String,
    pub description: Option<String>,   // Will be filled by AI
    pub format: Option<String>,
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    pub nullable: bool,
    pub examples: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_schema_inference() {
        let mut builder = JsonSchemaBuilder::new();
        
        // Add sample JSON objects
        builder.analyze_sample(&json!({
            "id": 1,
            "name": "John Doe",
            "email": "john@example.com",
            "active": true
        }));
        
        builder.analyze_sample(&json!({
            "id": 2,
            "name": "Jane Smith", 
            "email": "jane@example.com",
            "active": false,
            "phone": "555-1234"
        }));
        
        let schema = builder.build(1);
        
        assert_eq!(schema.schema_type, "object");
        assert!(schema.properties.contains_key("id"));
        assert!(schema.properties.contains_key("name"));
        assert!(schema.properties.contains_key("email"));
        assert!(schema.required.contains(&"id".to_string()));
        assert!(schema.required.contains(&"name".to_string()));
    }
}
