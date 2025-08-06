//! Traffic analysis modules for AI-powered documentation

pub mod schema_inference;
pub mod traffic_analyzer;

pub use schema_inference::{JsonSchema, PropertySchema, SchemaInferrer};
pub use traffic_analyzer::{EndpointAnalysis, EndpointDocumentation, TrafficAnalyzer};
