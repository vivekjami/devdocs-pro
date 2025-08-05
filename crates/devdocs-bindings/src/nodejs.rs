//! Node.js language bindings for DevDocs Pro

use crate::common::{BindingResult, CommonMiddleware, FrameworkIntegration};
use crate::BindingConfig;
use tracing::{debug, info};

/// Node.js integration for DevDocs Pro
pub struct NodeJsIntegration {
    /// Common middleware
    middleware: Option<CommonMiddleware>,
    
    /// Framework type
    framework: NodeJsFramework,
    
    /// Active status
    active: bool,
}

/// Supported Node.js frameworks
#[derive(Debug, Clone, Copy)]
pub enum NodeJsFramework {
    /// Express.js framework
    Express,
    
    /// Koa.js framework
    Koa,
    
    /// NestJS framework
    NestJS,
    
    /// Generic Node.js
    Generic,
}

impl NodeJsIntegration {
    /// Create a new Node.js integration
    #[must_use]
    pub fn new(framework: NodeJsFramework) -> Self {
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
    
    /// Get Express middleware
    pub fn express_middleware(&self) -> BindingResult<ExpressMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(ExpressMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
    
    /// Get Koa middleware
    pub fn koa_middleware(&self) -> BindingResult<KoaMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(KoaMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
    
    /// Get NestJS middleware
    pub fn nestjs_middleware(&self) -> BindingResult<NestJsMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(NestJsMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
}

impl FrameworkIntegration for NodeJsIntegration {
    fn framework_name(&self) -> &'static str {
        match self.framework {
            NodeJsFramework::Express => "Express.js",
            NodeJsFramework::Koa => "Koa.js",
            NodeJsFramework::NestJS => "NestJS",
            NodeJsFramework::Generic => "Generic Node.js",
        }
    }
    
    fn initialize(&mut self) -> devdocs_core::Result<()> {
        info!("Initializing Node.js integration for {}", self.framework_name());
        self.active = true;
        Ok(())
    }
    
    fn is_active(&self) -> bool {
        self.active
    }
}

/// Express.js-specific middleware
pub struct ExpressMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> ExpressMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Express request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Express request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

/// Koa.js-specific middleware
pub struct KoaMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> KoaMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Koa request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Koa request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

/// NestJS-specific middleware
pub struct NestJsMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> NestJsMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process NestJS request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing NestJS request: {} {}", method, path);
        
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
    fn test_nodejs_integration_creation() {
        let integration = NodeJsIntegration::new(NodeJsFramework::Express);
        assert_eq!(integration.framework_name(), "Express.js");
        assert!(!integration.is_active());
    }

    #[test]
    fn test_framework_names() {
        assert_eq!(
            NodeJsIntegration::new(NodeJsFramework::Express).framework_name(),
            "Express.js"
        );
        assert_eq!(
            NodeJsIntegration::new(NodeJsFramework::Koa).framework_name(),
            "Koa.js"
        );
        assert_eq!(
            NodeJsIntegration::new(NodeJsFramework::NestJS).framework_name(),
            "NestJS"
        );
    }
}
