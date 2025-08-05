//! Python language bindings for DevDocs Pro

use crate::common::{BindingResult, CommonMiddleware, FrameworkIntegration};
use crate::BindingConfig;
use tracing::{debug, info};

/// Python integration for DevDocs Pro
pub struct PythonIntegration {
    /// Common middleware
    middleware: Option<CommonMiddleware>,
    
    /// Framework type
    framework: PythonFramework,
    
    /// Active status
    active: bool,
}

/// Supported Python frameworks
#[derive(Debug, Clone, Copy)]
pub enum PythonFramework {
    /// FastAPI framework
    FastAPI,
    
    /// Django framework
    Django,
    
    /// Flask framework
    Flask,
    
    /// Generic WSGI/ASGI
    Generic,
}

impl PythonIntegration {
    /// Create a new Python integration
    #[must_use]
    pub fn new(framework: PythonFramework) -> Self {
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
    
    /// Get FastAPI middleware
    pub fn fastapi_middleware(&self) -> BindingResult<FastAPIMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(FastAPIMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
    
    /// Get Django middleware
    pub fn django_middleware(&self) -> BindingResult<DjangoMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(DjangoMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
    
    /// Get Flask middleware
    pub fn flask_middleware(&self) -> BindingResult<FlaskMiddleware> {
        match &self.middleware {
            Some(middleware) => Ok(FlaskMiddleware::new(middleware)),
            None => Err(crate::common::BindingError::Configuration(
                "Middleware not initialized".into(),
            )),
        }
    }
}

impl FrameworkIntegration for PythonIntegration {
    fn framework_name(&self) -> &'static str {
        match self.framework {
            PythonFramework::FastAPI => "FastAPI",
            PythonFramework::Django => "Django",
            PythonFramework::Flask => "Flask",
            PythonFramework::Generic => "Generic Python",
        }
    }
    
    fn initialize(&mut self) -> devdocs_core::Result<()> {
        info!("Initializing Python integration for {}", self.framework_name());
        self.active = true;
        Ok(())
    }
    
    fn is_active(&self) -> bool {
        self.active
    }
}

/// FastAPI-specific middleware
pub struct FastAPIMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> FastAPIMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process FastAPI request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing FastAPI request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

/// Django-specific middleware
pub struct DjangoMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> DjangoMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Django request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Django request: {} {}", method, path);
        
        if self.common.should_exclude_path(path) {
            debug!("Excluding path: {}", path);
            return Ok(false);
        }
        
        // TODO: Implement actual request processing
        Ok(true)
    }
}

/// Flask-specific middleware
pub struct FlaskMiddleware<'a> {
    common: &'a CommonMiddleware,
}

impl<'a> FlaskMiddleware<'a> {
    fn new(common: &'a CommonMiddleware) -> Self {
        Self { common }
    }
    
    /// Process Flask request
    pub fn process_request(&self, path: &str, method: &str, body: &str) -> BindingResult<bool> {
        debug!("Processing Flask request: {} {}", method, path);
        
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
    fn test_python_integration_creation() {
        let integration = PythonIntegration::new(PythonFramework::FastAPI);
        assert_eq!(integration.framework_name(), "FastAPI");
        assert!(!integration.is_active());
    }

    #[test]
    fn test_framework_names() {
        assert_eq!(
            PythonIntegration::new(PythonFramework::FastAPI).framework_name(),
            "FastAPI"
        );
        assert_eq!(
            PythonIntegration::new(PythonFramework::Django).framework_name(),
            "Django"
        );
        assert_eq!(
            PythonIntegration::new(PythonFramework::Flask).framework_name(),
            "Flask"
        );
    }
}
