//! Traffic processor for analyzing samples and generating documentation

use devdocs_core::{
    analysis::{AnalysisConfig, TrafficAnalyzer},
    documentation::{DocumentationConfig, DocumentationGenerator, GeneratedDocumentation},
    DevDocsError, TrafficSample,
};
use std::collections::VecDeque;
use tokio::sync::RwLock;

/// Traffic processor that collects samples and generates documentation
pub struct TrafficProcessor {
    samples: RwLock<VecDeque<TrafficSample>>,
    analyzer: RwLock<TrafficAnalyzer>,
    doc_generator: DocumentationGenerator,
    analysis_config: AnalysisConfig,
    last_analysis: RwLock<Option<chrono::DateTime<chrono::Utc>>>,
    max_samples: usize,
    analysis_interval: std::time::Duration,
}

impl TrafficProcessor {
    /// Create a new traffic processor
    pub fn new(
        analysis_config: AnalysisConfig,
        doc_config: DocumentationConfig,
    ) -> Result<Self, DevDocsError> {
        let analyzer = TrafficAnalyzer::new(analysis_config.clone())?;
        let doc_generator = DocumentationGenerator::new(doc_config)?;

        Ok(Self {
            samples: RwLock::new(VecDeque::new()),
            analyzer: RwLock::new(analyzer),
            doc_generator,
            analysis_config,
            last_analysis: RwLock::new(None),
            max_samples: 1000, // Keep last 1000 samples
            analysis_interval: std::time::Duration::from_secs(60), // Analyze every minute
        })
    }

    /// Add a new traffic sample
    pub async fn add_sample(&self, sample: TrafficSample) -> Result<(), DevDocsError> {
        let mut samples = self.samples.write().await;

        // Add new sample
        samples.push_back(sample);

        // Keep only the most recent samples
        while samples.len() > self.max_samples {
            samples.pop_front();
        }

        Ok(())
    }

    /// Check if we should trigger analysis
    pub fn should_analyze(&self) -> bool {
        // Simple heuristic: analyze every minute or when we have enough samples
        if let Ok(last_analysis) = self.last_analysis.try_read() {
            if let Some(last) = *last_analysis {
                let elapsed = chrono::Utc::now().signed_duration_since(last);
                elapsed.num_seconds() >= self.analysis_interval.as_secs() as i64
            } else {
                // Never analyzed before, check if we have minimum samples
                if let Ok(samples) = self.samples.try_read() {
                    samples.len() >= self.analysis_config.min_samples_for_inference
                } else {
                    false
                }
            }
        } else {
            false
        }
    }

    /// Analyze traffic and generate documentation
    pub async fn analyze_and_generate_docs(&self) -> Result<GeneratedDocumentation, DevDocsError> {
        tracing::info!("Starting traffic analysis and documentation generation");

        // Get current samples
        let samples = {
            let samples_guard = self.samples.read().await;
            samples_guard.iter().cloned().collect::<Vec<_>>()
        };

        if samples.len() < self.analysis_config.min_samples_for_inference {
            return Err(DevDocsError::InvalidRequest(format!(
                "Insufficient samples for analysis. Need at least {}, got {}",
                self.analysis_config.min_samples_for_inference,
                samples.len()
            )));
        }

        // Perform analysis
        let analysis_result = {
            let mut analyzer = self.analyzer.write().await;
            analyzer.analyze_traffic(samples).await?
        };

        tracing::info!(
            "Analysis completed: {} endpoints, {} schemas, confidence: {:.2}",
            analysis_result.endpoints.len(),
            analysis_result.schemas.len(),
            analysis_result.confidence
        );

        // Generate documentation
        let documentation = self
            .doc_generator
            .generate_documentation(&analysis_result)
            .await?;

        // Update last analysis time
        {
            let mut last_analysis = self.last_analysis.write().await;
            *last_analysis = Some(chrono::Utc::now());
        }

        tracing::info!("Documentation generation completed");

        Ok(documentation)
    }

    /// Get current sample count
    pub fn sample_count(&self) -> usize {
        if let Ok(samples) = self.samples.try_read() {
            samples.len()
        } else {
            0
        }
    }

    /// Get number of unique endpoints discovered
    pub fn endpoint_count(&self) -> usize {
        if let Ok(samples) = self.samples.try_read() {
            let mut endpoints = std::collections::HashSet::new();
            for sample in samples.iter() {
                endpoints.insert(format!(
                    "{}:{}",
                    sample.request.method, sample.endpoint_pattern
                ));
            }
            endpoints.len()
        } else {
            0
        }
    }

    /// Get number of schemas inferred (placeholder)
    pub fn schema_count(&self) -> usize {
        // This would need to be tracked from the last analysis result
        // For now, return 0 as a placeholder
        0
    }

    /// Get last analysis time
    pub fn last_analysis_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        if let Ok(last_analysis) = self.last_analysis.try_read() {
            *last_analysis
        } else {
            None
        }
    }

    /// Force analysis regardless of timing
    pub async fn force_analysis(&self) -> Result<GeneratedDocumentation, DevDocsError> {
        self.analyze_and_generate_docs().await
    }

    /// Update analysis configuration
    pub async fn update_analysis_config(&self, config: AnalysisConfig) -> Result<(), DevDocsError> {
        let mut analyzer = self.analyzer.write().await;
        analyzer.update_config(config.clone())?;
        Ok(())
    }

    /// Update documentation configuration
    pub fn update_doc_config(&mut self, config: DocumentationConfig) -> Result<(), DevDocsError> {
        self.doc_generator.update_config(config)
    }

    /// Get current analysis configuration
    pub fn analysis_config(&self) -> &AnalysisConfig {
        &self.analysis_config
    }

    /// Get current documentation configuration
    pub fn doc_config(&self) -> &DocumentationConfig {
        self.doc_generator.config()
    }

    /// Clear all samples
    pub async fn clear_samples(&self) {
        let mut samples = self.samples.write().await;
        samples.clear();
    }

    /// Get sample statistics
    pub async fn get_sample_stats(&self) -> SampleStats {
        let samples = self.samples.read().await;

        let mut method_counts = std::collections::HashMap::new();
        let mut status_counts = std::collections::HashMap::new();
        let mut endpoint_counts = std::collections::HashMap::new();
        let mut total_response_time = 0.0;
        let mut response_count = 0;

        for sample in samples.iter() {
            // Count methods
            *method_counts
                .entry(sample.request.method.clone())
                .or_insert(0) += 1;

            // Count endpoints
            *endpoint_counts
                .entry(sample.endpoint_pattern.clone())
                .or_insert(0) += 1;

            // Count status codes and response times
            if let Some(response) = &sample.response {
                *status_counts.entry(response.status_code).or_insert(0) += 1;
                total_response_time += response.processing_time_ms as f64;
                response_count += 1;
            }
        }

        let avg_response_time = if response_count > 0 {
            total_response_time / response_count as f64
        } else {
            0.0
        };

        SampleStats {
            total_samples: samples.len(),
            method_counts,
            status_counts,
            endpoint_counts,
            avg_response_time,
        }
    }
}

/// Statistics about collected samples
#[derive(Debug, Clone)]
pub struct SampleStats {
    pub total_samples: usize,
    pub method_counts: std::collections::HashMap<String, usize>,
    pub status_counts: std::collections::HashMap<u16, usize>,
    pub endpoint_counts: std::collections::HashMap<String, usize>,
    pub avg_response_time: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use devdocs_core::{
        documentation::DocumentationConfig,
        models::{HttpRequest, HttpResponse},
    };

    #[tokio::test]
    async fn test_traffic_processor_creation() {
        let analysis_config = AnalysisConfig::default();
        let doc_config = DocumentationConfig::default();

        let processor = TrafficProcessor::new(analysis_config, doc_config);
        assert!(processor.is_ok());
    }

    #[tokio::test]
    async fn test_sample_addition() {
        let analysis_config = AnalysisConfig::default();
        let doc_config = DocumentationConfig::default();
        let processor = TrafficProcessor::new(analysis_config, doc_config).unwrap();

        let request = HttpRequest::new(
            "GET".to_string(),
            "/test".to_string(),
            "corr-123".to_string(),
        );
        let sample = TrafficSample::new(request, "/test".to_string());

        let result = processor.add_sample(sample).await;
        assert!(result.is_ok());
        assert_eq!(processor.sample_count(), 1);
    }

    #[tokio::test]
    async fn test_sample_stats() {
        let analysis_config = AnalysisConfig::default();
        let doc_config = DocumentationConfig::default();
        let processor = TrafficProcessor::new(analysis_config, doc_config).unwrap();

        // Add some test samples
        for i in 0..5 {
            let request =
                HttpRequest::new("GET".to_string(), format!("/test/{i}"), format!("corr-{i}"));
            let response = HttpResponse::new(request.id, 200).with_processing_time(100 + i * 10);
            let sample =
                TrafficSample::new(request, "/test/{id}".to_string()).with_response(response);

            processor.add_sample(sample).await.unwrap();
        }

        let stats = processor.get_sample_stats().await;
        assert_eq!(stats.total_samples, 5);
        assert_eq!(stats.method_counts.get("GET"), Some(&5));
        assert_eq!(stats.status_counts.get(&200), Some(&5));
        assert!(stats.avg_response_time > 0.0);
    }

    #[tokio::test]
    async fn test_should_analyze() {
        let analysis_config = AnalysisConfig {
            min_samples_for_inference: 3,
            ..Default::default()
        };

        let doc_config = DocumentationConfig::default();
        let processor = TrafficProcessor::new(analysis_config, doc_config).unwrap();

        // Should not analyze with insufficient samples
        assert!(!processor.should_analyze());

        // Add samples
        for i in 0..3 {
            let request =
                HttpRequest::new("GET".to_string(), format!("/test/{i}"), format!("corr-{i}"));
            let sample = TrafficSample::new(request, "/test/{id}".to_string());
            processor.add_sample(sample).await.unwrap();
        }

        // Should analyze now (first time with enough samples)
        assert!(processor.should_analyze());
    }
}
