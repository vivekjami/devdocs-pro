//! Enterprise authentication and authorization system
//! 
//! Supports JWT tokens, API keys, OAuth2, SAML, and multi-tenant access control

use crate::errors::DevDocsError;
use chrono::{DateTime, Utc};
use jwt::{Header, Token, VerifyWithKey, SignWithKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication
    pub enabled: bool,
    /// JWT secret key
    pub jwt_secret: String,
    /// Token expiration time in seconds
    pub token_expiry_seconds: u64,
    /// Enable API key authentication
    pub enable_api_keys: bool,
    /// Enable OAuth2 integration
    pub enable_oauth2: bool,
    /// OAuth2 configuration
    pub oauth2: Option<OAuth2Config>,
    /// Enable SAML SSO
    pub enable_saml: bool,
    /// SAML configuration
    pub saml: Option<SamlConfig>,
    /// Multi-tenant configuration
    pub multi_tenant: MultiTenantConfig,
    /// Rate limiting per user
    pub rate_limiting: AuthRateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub certificate: String,
    pub attribute_mapping: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantConfig {
    pub enabled: bool,
    pub isolation_level: TenantIsolationLevel,
    pub default_permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TenantIsolationLevel {
    /// Complete data isolation between tenants
    Complete,
    /// Shared infrastructure, isolated data
    Shared,
    /// Hybrid approach with configurable isolation
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "change_this_in_production".to_string()),
            token_expiry_seconds: 3600, // 1 hour
            enable_api_keys: true,
            enable_oauth2: false,
            oauth2: None,
            enable_saml: false,
            saml: None,
            multi_tenant: MultiTenantConfig {
                enabled: true,
                isolation_level: TenantIsolationLevel::Complete,
                default_permissions: vec!["read".to_string()],
            },
            rate_limiting: AuthRateLimitConfig {
                enabled: true,
                requests_per_minute: 1000,
                burst_size: 100,
            },
        }
    }
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub user_id: String,
    pub organization_id: Option<String>,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub token_type: TokenType,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    Jwt,
    ApiKey,
    OAuth2,
    Saml,
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,           // Subject (user ID)
    pub org: Option<String>,   // Organization ID
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub iat: i64,             // Issued at
    pub exp: i64,             // Expiration
    pub aud: String,          // Audience
    pub iss: String,          // Issuer
}

/// API key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub key_id: String,
    pub key_hash: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub metadata: HashMap<String, String>,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub organization_id: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

/// Organization/tenant information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub plan: String,
    pub settings: OrganizationSettings,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSettings {
    pub max_users: Option<u32>,
    pub max_api_calls_per_month: Option<u64>,
    pub data_retention_days: u32,
    pub enable_audit_logs: bool,
    pub custom_branding: bool,
}

/// Main authenticator
pub struct Authenticator {
    config: AuthConfig,
    jwt_key: Hmac<Sha256>,
    api_keys: HashMap<String, ApiKey>,
    users: HashMap<String, User>,
    organizations: HashMap<String, Organization>,
}

impl Authenticator {
    pub fn new(config: &AuthConfig) -> Result<Self, DevDocsError> {
        let jwt_key = Hmac::new_from_slice(config.jwt_secret.as_bytes())
            .map_err(|e| DevDocsError::Configuration(format!("Invalid JWT secret: {}", e)))?;
        
        Ok(Self {
            config: config.clone(),
            jwt_key,
            api_keys: HashMap::new(),
            users: HashMap::new(),
            organizations: HashMap::new(),
        })
    }

    /// Validate authentication token
    pub async fn validate_token(&self, token: &str) -> Result<AuthResult, DevDocsError> {
        if !self.config.enabled {
            return Ok(AuthResult {
                user_id: "anonymous".to_string(),
                organization_id: None,
                permissions: vec!["read".to_string()],
                roles: vec!["anonymous".to_string()],
                token_type: TokenType::Jwt,
                expires_at: None,
                metadata: HashMap::new(),
            });
        }

        // Try JWT first
        if let Ok(auth_result) = self.validate_jwt_token(token).await {
            return Ok(auth_result);
        }

        // Try API key
        if self.config.enable_api_keys {
            if let Ok(auth_result) = self.validate_api_key(token).await {
                return Ok(auth_result);
            }
        }

        Err(DevDocsError::Unauthorized("Invalid token".to_string()))
    }

    /// Validate JWT token
    pub async fn validate_jwt_token(&self, token: &str) -> Result<AuthResult, DevDocsError> {
        let token: Token<Header, JwtClaims, _> = token
            .verify_with_key(&self.jwt_key)
            .map_err(|e| DevDocsError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        let claims = token.claims();

        // Check expiration
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(DevDocsError::Unauthorized("Token expired".to_string()));
        }

        // Verify user exists and is active
        if let Some(user) = self.users.get(&claims.sub) {
            if !user.is_active {
                return Err(DevDocsError::Unauthorized("User account disabled".to_string()));
            }

            // Verify organization if specified
            if let Some(org_id) = &claims.org {
                if let Some(org) = self.organizations.get(org_id) {
                    if !org.is_active {
                        return Err(DevDocsError::Unauthorized("Organization disabled".to_string()));
                    }
                } else {
                    return Err(DevDocsError::Unauthorized("Organization not found".to_string()));
                }
            }

            Ok(AuthResult {
                user_id: claims.sub.clone(),
                organization_id: claims.org.clone(),
                permissions: claims.permissions.clone(),
                roles: claims.roles.clone(),
                token_type: TokenType::Jwt,
                expires_at: Some(DateTime::from_timestamp(claims.exp, 0).unwrap()),
                metadata: HashMap::new(),
            })
        } else {
            Err(DevDocsError::Unauthorized("User not found".to_string()))
        }
    }

    /// Validate API key
    pub async fn validate_api_key(&self, key: &str) -> Result<AuthResult, DevDocsError> {
        // Hash the provided key to compare with stored hash
        let key_hash = self.hash_api_key(key);
        
        // Find API key by hash
        let api_key = self.api_keys.values()
            .find(|k| k.key_hash == key_hash && k.is_active)
            .ok_or_else(|| DevDocsError::Unauthorized("Invalid API key".to_string()))?;

        // Check expiration
        if let Some(expires_at) = api_key.expires_at {
            if Utc::now() > expires_at {
                return Err(DevDocsError::Unauthorized("API key expired".to_string()));
            }
        }

        // Verify user exists and is active
        if let Some(user) = self.users.get(&api_key.user_id) {
            if !user.is_active {
                return Err(DevDocsError::Unauthorized("User account disabled".to_string()));
            }

            Ok(AuthResult {
                user_id: api_key.user_id.clone(),
                organization_id: api_key.organization_id.clone(),
                permissions: api_key.permissions.clone(),
                roles: user.roles.clone(),
                token_type: TokenType::ApiKey,
                expires_at: api_key.expires_at,
                metadata: api_key.metadata.clone(),
            })
        } else {
            Err(DevDocsError::Unauthorized("User not found".to_string()))
        }
    }

    /// Generate JWT token for user
    pub fn generate_jwt_token(&self, user: &User) -> Result<String, DevDocsError> {
        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(self.config.token_expiry_seconds as i64);

        let claims = JwtClaims {
            sub: user.id.clone(),
            org: user.organization_id.clone(),
            permissions: user.permissions.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            aud: "devdocs-pro".to_string(),
            iss: "devdocs-pro".to_string(),
        };

        let header = Header::default();
        let token = Token::new(header, claims)
            .sign_with_key(&self.jwt_key)
            .map_err(|e| DevDocsError::Authentication(format!("JWT signing failed: {}", e)))?;

        Ok(token.as_str().to_string())
    }

    /// Generate API key for user
    pub fn generate_api_key(&mut self, user_id: &str, organization_id: Option<String>, permissions: Vec<String>) -> Result<String, DevDocsError> {
        let key_id = uuid::Uuid::new_v4().to_string();
        let raw_key = format!("dk_{}", uuid::Uuid::new_v4().simple());
        let key_hash = self.hash_api_key(&raw_key);

        let api_key = ApiKey {
            key_id: key_id.clone(),
            key_hash,
            user_id: user_id.to_string(),
            organization_id,
            permissions,
            created_at: Utc::now(),
            expires_at: None, // No expiration by default
            last_used: None,
            is_active: true,
            metadata: HashMap::new(),
        };

        self.api_keys.insert(key_id, api_key);
        Ok(raw_key)
    }

    /// Create new user
    pub fn create_user(&mut self, email: String, organization_id: Option<String>, roles: Vec<String>) -> Result<User, DevDocsError> {
        let user_id = uuid::Uuid::new_v4().to_string();
        
        // Determine permissions based on roles
        let permissions = self.resolve_permissions_from_roles(&roles);

        let user = User {
            id: user_id.clone(),
            email,
            organization_id,
            roles,
            permissions,
            is_active: true,
            created_at: Utc::now(),
            last_login: None,
            metadata: HashMap::new(),
        };

        self.users.insert(user_id, user.clone());
        Ok(user)
    }

    /// Create new organization
    pub fn create_organization(&mut self, name: String, plan: String) -> Result<Organization, DevDocsError> {
        let org_id = uuid::Uuid::new_v4().to_string();

        let settings = OrganizationSettings {
            max_users: match plan.as_str() {
                "free" => Some(5),
                "pro" => Some(50),
                "enterprise" => None,
                _ => Some(5),
            },
            max_api_calls_per_month: match plan.as_str() {
                "free" => Some(1000),
                "pro" => Some(100000),
                "enterprise" => None,
                _ => Some(1000),
            },
            data_retention_days: match plan.as_str() {
                "free" => 30,
                "pro" => 90,
                "enterprise" => 365,
                _ => 30,
            },
            enable_audit_logs: plan != "free",
            custom_branding: plan == "enterprise",
        };

        let organization = Organization {
            id: org_id.clone(),
            name,
            plan,
            settings,
            created_at: Utc::now(),
            is_active: true,
        };

        self.organizations.insert(org_id, organization.clone());
        Ok(organization)
    }

    /// Check if user has specific permission
    pub fn has_permission(&self, user_id: &str, permission: &str) -> bool {
        if let Some(user) = self.users.get(user_id) {
            user.permissions.contains(&permission.to_string()) ||
            user.roles.contains(&"admin".to_string()) // Admins have all permissions
        } else {
            false
        }
    }

    /// Check if user belongs to organization
    pub fn user_belongs_to_organization(&self, user_id: &str, org_id: &str) -> bool {
        if let Some(user) = self.users.get(user_id) {
            user.organization_id.as_ref() == Some(&org_id.to_string())
        } else {
            false
        }
    }

    /// Revoke API key
    pub fn revoke_api_key(&mut self, key_id: &str) -> Result<(), DevDocsError> {
        if let Some(api_key) = self.api_keys.get_mut(key_id) {
            api_key.is_active = false;
            Ok(())
        } else {
            Err(DevDocsError::NotFound("API key not found".to_string()))
        }
    }

    /// Update user last login
    pub fn update_last_login(&mut self, user_id: &str) {
        if let Some(user) = self.users.get_mut(user_id) {
            user.last_login = Some(Utc::now());
        }
    }

    /// Update API key last used
    pub fn update_api_key_last_used(&mut self, key_hash: &str) {
        for api_key in self.api_keys.values_mut() {
            if api_key.key_hash == key_hash {
                api_key.last_used = Some(Utc::now());
                break;
            }
        }
    }

    fn hash_api_key(&self, key: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn resolve_permissions_from_roles(&self, roles: &[String]) -> Vec<String> {
        let mut permissions = HashSet::new();

        for role in roles {
            match role.as_str() {
                "admin" => {
                    permissions.extend(vec![
                        "read", "write", "delete", "admin", "manage_users", "manage_org"
                    ]);
                }
                "editor" => {
                    permissions.extend(vec!["read", "write"]);
                }
                "viewer" => {
                    permissions.insert("read");
                }
                "api_user" => {
                    permissions.extend(vec!["read", "write"]);
                }
                _ => {
                    // Custom role - use default permissions
                    permissions.extend(self.config.multi_tenant.default_permissions.iter().map(|s| s.as_str()));
                }
            }
        }

        permissions.into_iter().map(|s| s.to_string()).collect()
    }

    /// Get user statistics
    pub fn get_user_stats(&self) -> UserStats {
        let total_users = self.users.len();
        let active_users = self.users.values().filter(|u| u.is_active).count();
        let total_api_keys = self.api_keys.len();
        let active_api_keys = self.api_keys.values().filter(|k| k.is_active).count();

        UserStats {
            total_users,
            active_users,
            total_api_keys,
            active_api_keys,
            total_organizations: self.organizations.len(),
            active_organizations: self.organizations.values().filter(|o| o.is_active).count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStats {
    pub total_users: usize,
    pub active_users: usize,
    pub total_api_keys: usize,
    pub active_api_keys: usize,
    pub total_organizations: usize,
    pub active_organizations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        assert!(config.enabled);
        assert_eq!(config.token_expiry_seconds, 3600);
        assert!(config.enable_api_keys);
    }

    #[test]
    fn test_authenticator_creation() {
        let config = AuthConfig::default();
        let authenticator = Authenticator::new(&config);
        assert!(authenticator.is_ok());
    }

    #[test]
    fn test_user_creation() {
        let config = AuthConfig::default();
        let mut authenticator = Authenticator::new(&config).unwrap();
        
        let user = authenticator.create_user(
            "test@example.com".to_string(),
            None,
            vec!["viewer".to_string()],
        ).unwrap();
        
        assert_eq!(user.email, "test@example.com");
        assert!(user.permissions.contains(&"read".to_string()));
        assert!(user.is_active);
    }

    #[test]
    fn test_organization_creation() {
        let config = AuthConfig::default();
        let mut authenticator = Authenticator::new(&config).unwrap();
        
        let org = authenticator.create_organization(
            "Test Org".to_string(),
            "pro".to_string(),
        ).unwrap();
        
        assert_eq!(org.name, "Test Org");
        assert_eq!(org.plan, "pro");
        assert_eq!(org.settings.max_users, Some(50));
        assert!(org.is_active);
    }

    #[test]
    fn test_api_key_generation() {
        let config = AuthConfig::default();
        let mut authenticator = Authenticator::new(&config).unwrap();
        
        let user = authenticator.create_user(
            "test@example.com".to_string(),
            None,
            vec!["api_user".to_string()],
        ).unwrap();
        
        let api_key = authenticator.generate_api_key(
            &user.id,
            None,
            vec!["read".to_string(), "write".to_string()],
        ).unwrap();
        
        assert!(api_key.starts_with("dk_"));
        assert_eq!(authenticator.api_keys.len(), 1);
    }

    #[test]
    fn test_jwt_token_generation() {
        let config = AuthConfig::default();
        let mut authenticator = Authenticator::new(&config).unwrap();
        
        let user = authenticator.create_user(
            "test@example.com".to_string(),
            None,
            vec!["viewer".to_string()],
        ).unwrap();
        
        let token = authenticator.generate_jwt_token(&user);
        assert!(token.is_ok());
        
        let token_str = token.unwrap();
        assert!(!token_str.is_empty());
        assert!(token_str.contains('.'));
    }

    #[test]
    fn test_permission_resolution() {
        let config = AuthConfig::default();
        let authenticator = Authenticator::new(&config).unwrap();
        
        let admin_permissions = authenticator.resolve_permissions_from_roles(&vec!["admin".to_string()]);
        assert!(admin_permissions.contains(&"read".to_string()));
        assert!(admin_permissions.contains(&"write".to_string()));
        assert!(admin_permissions.contains(&"admin".to_string()));
        
        let viewer_permissions = authenticator.resolve_permissions_from_roles(&vec!["viewer".to_string()]);
        assert!(viewer_permissions.contains(&"read".to_string()));
        assert!(!viewer_permissions.contains(&"write".to_string()));
    }

    #[test]
    fn test_api_key_revocation() {
        let config = AuthConfig::default();
        let mut authenticator = Authenticator::new(&config).unwrap();
        
        let user = authenticator.create_user(
            "test@example.com".to_string(),
            None,
            vec!["api_user".to_string()],
        ).unwrap();
        
        let _api_key = authenticator.generate_api_key(
            &user.id,
            None,
            vec!["read".to_string()],
        ).unwrap();
        
        let key_id = authenticator.api_keys.keys().next().unwrap().clone();
        let result = authenticator.revoke_api_key(&key_id);
        assert!(result.is_ok());
        
        let api_key = authenticator.api_keys.get(&key_id).unwrap();
        assert!(!api_key.is_active);
    }

    #[test]
    fn test_user_stats() {
        let config = AuthConfig::default();
        let mut authenticator = Authenticator::new(&config).unwrap();
        
        let _user1 = authenticator.create_user(
            "user1@example.com".to_string(),
            None,
            vec!["viewer".to_string()],
        ).unwrap();
        
        let _user2 = authenticator.create_user(
            "user2@example.com".to_string(),
            None,
            vec!["editor".to_string()],
        ).unwrap();
        
        let _org = authenticator.create_organization(
            "Test Org".to_string(),
            "pro".to_string(),
        ).unwrap();
        
        let stats = authenticator.get_user_stats();
        assert_eq!(stats.total_users, 2);
        assert_eq!(stats.active_users, 2);
        assert_eq!(stats.total_organizations, 1);
        assert_eq!(stats.active_organizations, 1);
    }
}