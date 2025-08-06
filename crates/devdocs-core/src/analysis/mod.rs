//! Traffic analysis modules for AI-powered documentation

pub mod schema_inference;
pub mod traffic_analyzer;

pub use schema_inference::{SchemaInferrer, JsonSchema, PropertySchema};
pub use traffic_analyzer::{TrafficAnalyzer, EndpointAnalysis, EndpointDocumentation};
