//! Schema data structures for API documentation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an inferred API schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Schema version
    pub version: String,

    /// Schema type (object, array, primitive)
    pub schema_type: SchemaType,

    /// Fields in the schema (for object types)
    pub fields: HashMap<String, SchemaField>,

    /// Array item type (for array types)
    pub items: Option<Box<Schema>>,

    /// Whether the schema is required
    pub required: bool,

    /// Example values observed
    pub examples: Vec<serde_json::Value>,

    /// Description of the schema
    pub description: Option<String>,
}

/// Represents a field within a schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    /// Field name
    pub name: String,

    /// Field type
    pub field_type: SchemaType,

    /// Whether the field is required
    pub required: bool,

    /// Whether the field can be null
    pub nullable: bool,

    /// Nested schema for complex types
    pub schema: Option<Box<Schema>>,

    /// Validation constraints
    pub constraints: FieldConstraints,

    /// Example values observed
    pub examples: Vec<serde_json::Value>,

    /// Description of the field
    pub description: Option<String>,
}

/// Validation constraints for schema fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConstraints {
    /// Minimum length (for strings)
    pub min_length: Option<usize>,

    /// Maximum length (for strings)
    pub max_length: Option<usize>,

    /// Minimum value (for numbers)
    pub min_value: Option<f64>,

    /// Maximum value (for numbers)
    pub max_value: Option<f64>,

    /// Pattern (regex) for string validation
    pub pattern: Option<String>,

    /// Enum values (for constrained strings)
    pub enum_values: Option<Vec<String>>,

    /// Format specification (email, date, etc.)
    pub format: Option<String>,
}

/// Schema data types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaType {
    /// String type
    String,

    /// Number type (integer or float)
    Number,

    /// Integer type
    Integer,

    /// Boolean type
    Boolean,

    /// Array type
    Array,

    /// Object type
    Object,

    /// Null type
    Null,

    /// Unknown or mixed type
    Unknown,
}

impl Schema {
    /// Create a new schema with the specified type
    #[must_use]
    pub fn new(schema_type: SchemaType) -> Self {
        Self {
            version: "1.0.0".to_string(),
            schema_type,
            fields: HashMap::new(),
            items: None,
            required: false,
            examples: Vec::new(),
            description: None,
        }
    }

    /// Add a field to the schema
    pub fn with_field(mut self, name: String, field: SchemaField) -> Self {
        self.fields.insert(name, field);
        self
    }

    /// Set the array item type
    pub fn with_items(mut self, items: Schema) -> Self {
        self.items = Some(Box::new(items));
        self
    }

    /// Add an example value
    pub fn with_example(mut self, example: serde_json::Value) -> Self {
        self.examples.push(example);
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

impl SchemaField {
    /// Create a new schema field
    #[must_use]
    pub fn new(name: String, field_type: SchemaType) -> Self {
        Self {
            name,
            field_type,
            required: false,
            nullable: false,
            schema: None,
            constraints: FieldConstraints::default(),
            examples: Vec::new(),
            description: None,
        }
    }

    /// Set the field as required
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Set the field as nullable
    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    /// Set nested schema
    pub fn with_schema(mut self, schema: Schema) -> Self {
        self.schema = Some(Box::new(schema));
        self
    }

    /// Set field constraints
    pub fn with_constraints(mut self, constraints: FieldConstraints) -> Self {
        self.constraints = constraints;
        self
    }
}

impl Default for FieldConstraints {
    fn default() -> Self {
        Self {
            min_length: None,
            max_length: None,
            min_value: None,
            max_value: None,
            pattern: None,
            enum_values: None,
            format: None,
        }
    }
}

impl std::fmt::Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaType::String => write!(f, "string"),
            SchemaType::Number => write!(f, "number"),
            SchemaType::Integer => write!(f, "integer"),
            SchemaType::Boolean => write!(f, "boolean"),
            SchemaType::Array => write!(f, "array"),
            SchemaType::Object => write!(f, "object"),
            SchemaType::Null => write!(f, "null"),
            SchemaType::Unknown => write!(f, "unknown"),
        }
    }
}
