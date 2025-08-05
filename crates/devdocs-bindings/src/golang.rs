//! Go language bindings for DevDocs Pro

use crate::common::{BindingResult, CommonMiddleware, FrameworkIntegration};
use crate::BindingConfig;
use tracing::{debug, info};

/// Go integration for DevDocs Pro
pub struct GoIntegration {
    /// Common middleware
    middleware: Option<CommonMiddleware>,
    
    /// Framework type
    framework: GoFramework,
    
    /// Active status
    active: bool,
}

/// Supported Go frameworks
#[derive(Debug, Clone, Copy)]
pub enum GoFramework {
    /// Gin framework
    Gin,
    
    /// Echo framework
    Echo,
    
    /// Chi framework
    Chi,
    
    /// Standard net/http
    NetHttp,
    
    /// Generic Go
    Generic,
}

impl GoIntegration {
    /// Create a new Go integration
    #[must_use]
    pub fn new(framework: GoFramework) -> Self {
        Self {
            middleware: None,
            framework,
            active: false,
        }
    }
    
    /// Initialize with configuration
    pub fn with_config(&mut self, config: BindingConfig) -> BindingResult<()> {
        let middleware = CommonMiddleware::new(config)?;
        self.middleware = Some(middleware);
        Ok(())
    }
    
    /// Get Gin middleware
    pub fn gin_middleware(&self) -> BindingResult<GinMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(GinMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
    
    /// Get Echo middleware
    pub fn echo_middleware(&self) -> BindingResult<EchoMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(EchoMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
    
    /// Get Chi middleware
    pub fn chi_middleware(&self) -> BindingResult<ChiMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(ChiMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
}

impl FrameworkIntegration for GoIntegration {
    fn framework_name(&self) -> &'static str {
        match self.framework {
            GoFramework::Gin => "Gin",
            GoFramework::Echo => "Echo",
            GoFramework::Chi => "Chi",
            GoFramework::NetHttp => "net/http",
            GoFramework::Generic => "Generic Go",
        }
    }
    
    fn initialize(&mut self) -> devdocs_core::Result<()> {
        info!("Initializing Go integration for {}", self.framework_name());
        self.active = true;
        Ok(())
    }
    
    fn is_active(&self) -> bool {
        self.active
    }
}

/// Gin-specific middleware
pub struct GinMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> GinMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Gin request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Gin request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

/// Echo-specific middleware
pub struct EchoMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> EchoMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Echo request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Echo request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

/// Chi-specific middleware
pub struct ChiMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> ChiMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Chi request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Chi request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_integration_creation() {
        let integration = GoIntegration::new(GoFramework::Gin);
        assert_eq!(integration.framework_name(), "Gin");
        assert!(!integration.is_active());
    }

    #[test]
    fn test_framework_names() {
        assert_eq!(
            GoIntegration::new(GoFramework::Gin).framework_name(),
            "Gin"
        );
        assert_eq!(
            GoIntegration::new(GoFramework::Echo).framework_name(),
            "Echo"
        );
        assert_eq!(
            GoIntegration::new(GoFramework::Chi).framework_name(),
            "Chi"
        );
        assert_eq!(
            GoIntegration::new(GoFramework::NetHttp).framework_name(),
            "net/http"
        );
    }
}
