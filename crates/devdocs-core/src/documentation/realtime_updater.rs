//! Real-time documentation updater
//!
//! This module provides WebSocket-based real-time updates for documentation
//! as API traffic patterns change.

use crate::documentation::DocumentationConfig;
use crate::errors::DevDocsError;
use crate::models::ApiEndpoint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Real-time update event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UpdateEvent {
    /// New endpoint discovered
    EndpointAdded {
        endpoint: ApiEndpoint,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Endpoint statistics updated
    EndpointUpdated {
        endpoint: ApiEndpoint,
        changes: EndpointChanges,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// New schema inferred
    SchemaAdded {
        name: String,
        schema: serde_json::Value,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Schema updated
    SchemaUpdated {
        name: String,
        schema: serde_json::Value,
        changes: SchemaChanges,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Documentation regenerated
    DocumentationUpdated {
        documentation_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Breaking change detected
    BreakingChange {
        change_type: BreakingChangeType,
        description: String,
        affected_endpoints: Vec<String>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

/// Changes to an endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointChanges {
    pub request_count_delta: i64,
    pub avg_response_time_change: f64,
    pub success_rate_change: f64,
    pub new_status_codes: Vec<u16>,
}

/// Changes to a schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaChanges {
    pub fields_added: Vec<String>,
    pub fields_removed: Vec<String>,
    pub fields_modified: Vec<String>,
    pub breaking_changes: Vec<String>,
}

/// Types of breaking changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BreakingChangeType {
    EndpointRemoved,
    RequiredFieldAdded,
    FieldTypeChanged,
    FieldRemoved,
    StatusCodeChanged,
}

/// WebSocket client connection
#[derive(Debug, Clone)]
pub struct ClientConnection {
    pub id: Uuid,
    pub subscriptions: Vec<String>,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

/// Real-time updater for documentation
pub struct RealtimeUpdater {
    config: DocumentationConfig,
    event_sender: broadcast::Sender<UpdateEvent>,
    clients: HashMap<Uuid, ClientConnection>,
    endpoint_history: HashMap<String, ApiEndpoint>,
    schema_history: HashMap<String, serde_json::Value>,
}

impl RealtimeUpdater {
    /// Create a new real-time updater
    pub fn new(config: DocumentationConfig) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        
        Self {
            config,
            event_sender,
            clients: HashMap::new(),
            endpoint_history: HashMap::new(),
            schema_history: HashMap::new(),
        }
    }

    /// Add a new client connection
    pub fn add_client(&mut self, subscriptions: Vec<String>) -> (Uuid, broadcast::Receiver<UpdateEvent>) {
        let client_id = Uuid::new_v4();
        let receiver = self.event_sender.subscribe();
        
        let client = ClientConnection {
            id: client_id,
            subscriptions,
            connected_at: chrono::Utc::now(),
        };
        
        self.clients.insert(client_id, client);
        
        tracing::info!("New client connected: {}", client_id);
        (client_id, receiver)
    }

    /// Remove a client connection
    pub fn remove_client(&mut self, client_id: Uuid) {
        if self.clients.remove(&client_id).is_some() {
            tracing::info!("Client disconnected: {}", client_id);
        }
    }

    /// Process endpoint updates and detect changes
    pub async fn process_endpoint_update(&mut self, endpoint: ApiEndpoint) -> Result<(), DevDocsError> {
        let endpoint_key = format!("{}:{}", endpoint.method, endpoint.path_pattern);
        
        if let Some(previous) = self.endpoint_history.get(&endpoint_key) {
            // Calculate changes
            let changes = EndpointChanges {
                request_count_delta: endpoint.request_count as i64 - previous.request_count as i64,
                avg_response_time_change: endpoint.avg_response_time_ms - previous.avg_response_time_ms,
                success_rate_change: endpoint.success_rate() - previous.success_rate(),
                new_status_codes: endpoint.status_codes.keys()
                    .filter(|&code| !previous.status_codes.contains_key(code))
                    .copied()
                    .collect(),
            };

            // Check for breaking changes
            self.detect_endpoint_breaking_changes(previous, &endpoint).await?;

            // Send update event
            let event = UpdateEvent::EndpointUpdated {
                endpoint: endpoint.clone(),
                changes,
                timestamp: chrono::Utc::now(),
            };
            
            self.send_event(event).await?;
        } else {
            // New endpoint discovered
            let event = UpdateEvent::EndpointAdded {
                endpoint: endpoint.clone(),
                timestamp: chrono::Utc::now(),
            };
            
            self.send_event(event).await?;
        }

        // Update history
        self.endpoint_history.insert(endpoint_key, endpoint);
        Ok(())
    }

    /// Process schema updates and detect changes
    pub async fn process_schema_update(
        &mut self,
        name: String,
        schema: serde_json::Value,
    ) -> Result<(), DevDocsError> {
        if let Some(previous_schema) = self.schema_history.get(&name) {
            // Analyze schema changes
            let changes = self.analyze_schema_changes(previous_schema, &schema);
            
            // Check for breaking changes
            if !changes.breaking_changes.is_empty() {
                let event = UpdateEvent::BreakingChange {
                    change_type: BreakingChangeType::FieldTypeChanged,
                    description: format!("Schema '{}' has breaking changes", name),
                    affected_endpoints: self.find_endpoints_using_schema(&name),
                    timestamp: chrono::Utc::now(),
                };
                
                self.send_event(event).await?;
            }

            // Send schema update event
            let event = UpdateEvent::SchemaUpdated {
                name: name.clone(),
                schema: schema.clone(),
                changes,
                timestamp: chrono::Utc::now(),
            };
            
            self.send_event(event).await?;
        } else {
            // New schema discovered
            let event = UpdateEvent::SchemaAdded {
                name: name.clone(),
                schema: schema.clone(),
                timestamp: chrono::Utc::now(),
            };
            
            self.send_event(event).await?;
        }

        // Update history
        self.schema_history.insert(name, schema);
        Ok(())
    }

    /// Send documentation updated event
    pub async fn notify_documentation_updated(&self, documentation_id: Uuid) -> Result<(), DevDocsError> {
        let event = UpdateEvent::DocumentationUpdated {
            documentation_id,
            timestamp: chrono::Utc::now(),
        };
        
        self.send_event(event).await
    }

    /// Send event to all subscribed clients
    async fn send_event(&self, event: UpdateEvent) -> Result<(), DevDocsError> {
        if self.event_sender.send(event.clone()).is_err() {
            tracing::warn!("No clients listening for real-time updates");
        } else {
            tracing::debug!("Sent real-time update: {:?}", event);
        }
        
        Ok(())
    }

    /// Detect breaking changes in endpoint updates
    async fn detect_endpoint_breaking_changes(
        &self,
        previous: &ApiEndpoint,
        current: &ApiEndpoint,
    ) -> Result<(), DevDocsError> {
        // Check for significant success rate drops
        let success_rate_drop = previous.success_rate() - current.success_rate();
        if success_rate_drop > 10.0 {
            let event = UpdateEvent::BreakingChange {
                change_type: BreakingChangeType::StatusCodeChanged,
                description: format!(
                    "Success rate dropped by {:.1}% for {} {}",
                    success_rate_drop, current.method, current.path_pattern
                ),
                affected_endpoints: vec![format!("{}:{}", current.method, current.path_pattern)],
                timestamp: chrono::Utc::now(),
            };
            
            self.send_event(event).await?;
        }

        // Check for new error status codes
        for &status_code in current.status_codes.keys() {
            if status_code >= 400 && !previous.status_codes.contains_key(&status_code) {
                let event = UpdateEvent::BreakingChange {
                    change_type: BreakingChangeType::StatusCodeChanged,
                    description: format!(
                        "New error status code {} detected for {} {}",
                        status_code, current.method, current.path_pattern
                    ),
                    affected_endpoints: vec![format!("{}:{}", current.method, current.path_pattern)],
                    timestamp: chrono::Utc::now(),
                };
                
                self.send_event(event).await?;
            }
        }

        Ok(())
    }

    /// Analyze changes between two schemas
    fn analyze_schema_changes(
        &self,
        previous: &serde_json::Value,
        current: &serde_json::Value,
    ) -> SchemaChanges {
        let mut changes = SchemaChanges {
            fields_added: Vec::new(),
            fields_removed: Vec::new(),
            fields_modified: Vec::new(),
            breaking_changes: Vec::new(),
        };

        // Compare properties if both are objects
        if let (Some(prev_props), Some(curr_props)) = (
            previous.get("properties").and_then(|p| p.as_object()),
            current.get("properties").and_then(|p| p.as_object()),
        ) {
            // Find added fields
            for field_name in curr_props.keys() {
                if !prev_props.contains_key(field_name) {
                    changes.fields_added.push(field_name.clone());
                }
            }

            // Find removed fields
            for field_name in prev_props.keys() {
                if !curr_props.contains_key(field_name) {
                    changes.fields_removed.push(field_name.clone());
                    changes.breaking_changes.push(format!("Field '{}' was removed", field_name));
                }
            }

            // Find modified fields
            for (field_name, curr_field) in curr_props {
                if let Some(prev_field) = prev_props.get(field_name) {
                    if prev_field != curr_field {
                        changes.fields_modified.push(field_name.clone());
                        
                        // Check for breaking type changes
                        if let (Some(prev_type), Some(curr_type)) = (
                            prev_field.get("type").and_then(|t| t.as_str()),
                            curr_field.get("type").and_then(|t| t.as_str()),
                        ) {
                            if prev_type != curr_type {
                                changes.breaking_changes.push(format!(
                                    "Field '{}' type changed from {} to {}",
                                    field_name, prev_type, curr_type
                                ));
                            }
                        }
                    }
                }
            }

            // Check for new required fields
            if let (Some(prev_required), Some(curr_required)) = (
                previous.get("required").and_then(|r| r.as_array()),
                current.get("required").and_then(|r| r.as_array()),
            ) {
                for required_field in curr_required {
                    if let Some(field_name) = required_field.as_str() {
                        if !prev_required.contains(required_field) {
                            changes.breaking_changes.push(format!(
                                "Field '{}' is now required",
                                field_name
                            ));
                        }
                    }
                }
            }
        }

        changes
    }

    /// Find endpoints that use a specific schema
    fn find_endpoints_using_schema(&self, schema_name: &str) -> Vec<String> {
        // This is a simplified implementation
        // In practice, we'd need to analyze the OpenAPI spec or maintain
        // a mapping of schemas to endpoints
        self.endpoint_history.keys()
            .filter(|endpoint_key| {
                // Simple heuristic: if schema name contains part of endpoint path
                let path_part = endpoint_key.split(':').nth(1).unwrap_or("");
                schema_name.to_lowercase().contains(&path_part.replace('/', "").to_lowercase())
            })
            .cloned()
            .collect()
    }

    /// Get current client count
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Get client statistics
    pub fn get_client_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        for client in self.clients.values() {
            for subscription in &client.subscriptions {
                *stats.entry(subscription.clone()).or_insert(0) += 1;
            }
        }
        
        stats
    }

    /// Update configuration
    pub fn update_config(&mut self, config: DocumentationConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_realtime_updater_creation() {
        let config = DocumentationConfig::default();
        let updater = RealtimeUpdater::new(config);
        assert_eq!(updater.client_count(), 0);
    }

    #[test]
    fn test_client_management() {
        let config = DocumentationConfig::default();
        let mut updater = RealtimeUpdater::new(config);

        let (client_id, _receiver) = updater.add_client(vec!["endpoints".to_string()]);
        assert_eq!(updater.client_count(), 1);

        updater.remove_client(client_id);
        assert_eq!(updater.client_count(), 0);
    }

    #[test]
    fn test_schema_change_analysis() {
        let config = DocumentationConfig::default();
        let updater = RealtimeUpdater::new(config);

        let previous_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            },
            "required": ["id"]
        });

        let current_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "email": {"type": "string"}
            },
            "required": ["id", "name"]
        });

        let changes = updater.analyze_schema_changes(&previous_schema, &current_schema);
        
        assert_eq!(changes.fields_added, vec!["email"]);
        assert!(changes.fields_modified.contains(&"id".to_string()));
        assert!(!changes.breaking_changes.is_empty());
    }

    #[tokio::test]
    async fn test_endpoint_update_processing() {
        let config = DocumentationConfig::default();
        let mut updater = RealtimeUpdater::new(config);

        let endpoint = ApiEndpoint::new("/users".to_string(), "GET".to_string());
        let result = updater.process_endpoint_update(endpoint).await;
        assert!(result.is_ok());
    }
}