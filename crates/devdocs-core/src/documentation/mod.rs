//! Documentation generation engine
//!
//! This module provides comprehensive documentation generation capabilities,
//! including OpenAPI specification generation, interactive HTML documentation,
//! and real-time updates.

pub mod html_generator;
pub mod markdown_generator;
pub mod openapi_generator;
pub mod realtime_updater;

use crate::analysis::AnalysisResult;
use crate::errors::DevDocsError;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use uuid::Uuid;

/// Configuration for documentation generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentationConfig {
    /// API title
    pub title: String,
    /// API version
    pub version: String,
    /// API description
    pub description: Option<String>,
    /// Base URL for the API
    pub base_url: Option<String>,
    /// Contact information
    pub contact: Option<ContactInfo>,
    /// License information
    pub license: Option<LicenseInfo>,
    /// Enable interactive documentation
    pub enable_interactive: bool,
    /// Enable real-time updates
    pub enable_realtime_updates: bool,
    /// Custom CSS for branding
    pub custom_css: Option<String>,
    /// Logo URL
    pub logo_url: Option<String>,
}

impl Default for DocumentationConfig {
    fn default() -> Self {
        Self {
            title: "API Documentation".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Auto-generated API documentation from traffic analysis".to_string()),
            base_url: None,
            contact: None,
            license: None,
            enable_interactive: true,
            enable_realtime_updates: true,
            custom_css: None,
            logo_url: None,
        }
    }
}

/// Contact information for API documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
}

/// License information for API documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub name: String,
    pub url: Option<String>,
}

/// Generated documentation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedDocumentation {
    /// Unique identifier
    pub id: Uuid,
    /// OpenAPI specification
    pub openapi_spec: Value,
    /// HTML documentation
    pub html_content: String,
    /// Markdown documentation
    pub markdown_content: String,
    /// Generation timestamp
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Configuration used
    pub config: DocumentationConfig,
}

/// Main documentation generator
pub struct DocumentationGenerator {
    config: DocumentationConfig,
    openapi_generator: openapi_generator::OpenApiGenerator,
    html_generator: html_generator::HtmlGenerator,
    markdown_generator: markdown_generator::MarkdownGenerator,
}

impl DocumentationGenerator {
    /// Create a new documentation generator
    pub fn new(config: DocumentationConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            openapi_generator: openapi_generator::OpenApiGenerator::new(&config)?,
            html_generator: html_generator::HtmlGenerator::new(&config)?,
            markdown_generator: markdown_generator::MarkdownGenerator::new(&config)?,
            config,
        })
    }

    /// Generate comprehensive documentation from analysis results
    pub async fn generate_documentation(
        &self,
        analysis: &AnalysisResult,
    ) -> Result<GeneratedDocumentation, DevDocsError> {
        tracing::info!(
            "Generating documentation for {} endpoints",
            analysis.endpoints.len()
        );

        // Generate OpenAPI specification
        let openapi_spec = self
            .openapi_generator
            .generate_spec(&analysis.endpoints, &analysis.schemas)
            .await?;

        // Generate HTML documentation
        let html_content = self
            .html_generator
            .generate_html(&openapi_spec, analysis.documentation.as_deref())
            .await?;

        // Generate Markdown documentation
        let markdown_content = self
            .markdown_generator
            .generate_markdown(
                &analysis.endpoints,
                &analysis.schemas,
                analysis.documentation.as_deref(),
            )
            .await?;

        Ok(GeneratedDocumentation {
            id: Uuid::new_v4(),
            openapi_spec,
            html_content,
            markdown_content,
            generated_at: chrono::Utc::now(),
            config: self.config.clone(),
        })
    }

    /// Update configuration
    pub fn update_config(&mut self, config: DocumentationConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        self.openapi_generator.update_config(&config)?;
        self.html_generator.update_config(&config)?;
        self.markdown_generator.update_config(&config)?;
        Ok(())
    }

    /// Get current configuration
    pub fn config(&self) -> &DocumentationConfig {
        &self.config
    }
}

pub use html_generator::HtmlGenerator;
pub use markdown_generator::MarkdownGenerator;
pub use openapi_generator::OpenApiGenerator;
pub use realtime_updater::RealtimeUpdater;
