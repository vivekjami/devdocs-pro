//! HTML documentation generator
//!
//! This module generates interactive HTML documentation with live API testing
//! capabilities and responsive design.

use crate::documentation::DocumentationConfig;
use crate::errors::DevDocsError;
use serde_json::Value;

/// HTML documentation generator
pub struct HtmlGenerator {
    config: DocumentationConfig,
}

impl HtmlGenerator {
    /// Create a new HTML generator
    pub fn new(config: &DocumentationConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Generate interactive HTML documentation
    pub async fn generate_html(
        &self,
        openapi_spec: &Value,
        ai_documentation: Option<&str>,
    ) -> Result<String, DevDocsError> {
        let mut html = String::new();

        // Extract title from OpenAPI spec if available
        let title = openapi_spec
            .get("info")
            .and_then(|info| info.get("title"))
            .and_then(|title| title.as_str())
            .unwrap_or(&self.config.title);

        // HTML document structure
        html.push_str(&self.generate_html_head_with_title(title));
        html.push_str("<body>");
        html.push_str(&self.generate_header_with_title(title));
        html.push_str(&self.generate_navigation(openapi_spec));
        html.push_str("<main class=\"main-content\">");

        if let Some(ai_docs) = ai_documentation {
            html.push_str(&self.generate_ai_documentation_section(ai_docs));
        }

        html.push_str(&self.generate_api_overview(openapi_spec));
        html.push_str(&self.generate_endpoints_section(openapi_spec));
        html.push_str(&self.generate_schemas_section(openapi_spec));
        html.push_str("</main>");
        html.push_str(&self.generate_footer());
        html.push_str(&self.generate_javascript());
        html.push_str("</body></html>");

        Ok(html)
    }

    /// Generate HTML head section with custom title
    fn generate_html_head_with_title(&self, title: &str) -> String {
        let mut head = String::new();

        head.push_str("<!DOCTYPE html>");
        head.push_str("<html lang=\"en\">");
        head.push_str("<head>");
        head.push_str("<meta charset=\"UTF-8\">");
        head.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        head.push_str(&format!("<title>{title}</title>"));
        head.push_str(&self.generate_css());
        head.push_str("</head>");

        head
    }

    /// Generate HTML head section (legacy method)
    #[allow(dead_code)]
    fn generate_html_head(&self) -> String {
        self.generate_html_head_with_title(&self.config.title)
    }

    /// Generate CSS styles
    fn generate_css(&self) -> String {
        let mut css = String::new();

        css.push_str("<style>");
        css.push_str(include_str!("../../assets/documentation.css"));

        // Add custom CSS if provided
        if let Some(custom_css) = &self.config.custom_css {
            css.push_str(custom_css);
        }

        css.push_str("</style>");
        css
    }

    /// Generate header section with custom title
    fn generate_header_with_title(&self, title: &str) -> String {
        let mut header = String::new();

        header.push_str("<header class=\"header\">");
        header.push_str("<div class=\"container\">");

        if let Some(logo_url) = &self.config.logo_url {
            header.push_str(&format!(
                "<img src=\"{logo_url}\" alt=\"Logo\" class=\"logo\">"
            ));
        }

        header.push_str(&format!("<h1>{title}</h1>"));

        if let Some(description) = &self.config.description {
            header.push_str(&format!("<p class=\"description\">{description}</p>"));
        }

        header.push_str(&format!(
            "<span class=\"version\">v{}</span>",
            self.config.version
        ));
        header.push_str("</div>");
        header.push_str("</header>");

        header
    }

    /// Generate header section (legacy method)
    #[allow(dead_code)]
    fn generate_header(&self) -> String {
        self.generate_header_with_title(&self.config.title)
    }

    /// Generate navigation menu
    fn generate_navigation(&self, _openapi_spec: &Value) -> String {
        let mut nav = String::new();

        nav.push_str("<nav class=\"navigation\">");
        nav.push_str("<div class=\"container\">");
        nav.push_str("<ul class=\"nav-menu\">");
        nav.push_str("<li><a href=\"#overview\">Overview</a></li>");
        nav.push_str("<li><a href=\"#endpoints\">Endpoints</a></li>");
        nav.push_str("<li><a href=\"#schemas\">Schemas</a></li>");

        if self.config.enable_interactive {
            nav.push_str("<li><a href=\"#try-it\">Try It</a></li>");
        }

        nav.push_str("</ul>");
        nav.push_str("</div>");
        nav.push_str("</nav>");

        nav
    }

    /// Generate AI documentation section
    fn generate_ai_documentation_section(&self, ai_docs: &str) -> String {
        let mut section = String::new();

        section.push_str("<section id=\"ai-docs\" class=\"ai-documentation\">");
        section.push_str("<div class=\"container\">");
        section.push_str("<h2>AI-Generated Documentation</h2>");
        section.push_str("<div class=\"ai-content\">");

        // Convert markdown to HTML (basic conversion)
        let html_content = self.markdown_to_html(ai_docs);
        section.push_str(&html_content);

        section.push_str("</div>");
        section.push_str("</div>");
        section.push_str("</section>");

        section
    }

    /// Generate API overview section
    fn generate_api_overview(&self, openapi_spec: &Value) -> String {
        let mut overview = String::new();

        overview.push_str("<section id=\"overview\" class=\"api-overview\">");
        overview.push_str("<div class=\"container\">");
        overview.push_str("<h2>API Overview</h2>");

        if let Some(info) = openapi_spec.get("info") {
            if let Some(description) = info.get("description") {
                overview.push_str(&format!(
                    "<p class=\"api-description\">{}</p>",
                    description.as_str().unwrap_or("")
                ));
            }
        }

        // Add server information
        if let Some(servers) = openapi_spec.get("servers") {
            if let Some(servers_array) = servers.as_array() {
                overview.push_str("<h3>Base URLs</h3>");
                overview.push_str("<ul class=\"server-list\">");

                for server in servers_array {
                    if let Some(url) = server.get("url") {
                        let description = server
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("API Server");

                        overview.push_str(&format!(
                            "<li><code>{}</code> - {}</li>",
                            url.as_str().unwrap_or(""),
                            description
                        ));
                    }
                }

                overview.push_str("</ul>");
            }
        }

        overview.push_str("</div>");
        overview.push_str("</section>");

        overview
    }

    /// Generate endpoints section
    fn generate_endpoints_section(&self, openapi_spec: &Value) -> String {
        let mut endpoints = String::new();

        endpoints.push_str("<section id=\"endpoints\" class=\"endpoints\">");
        endpoints.push_str("<div class=\"container\">");
        endpoints.push_str("<h2>API Endpoints</h2>");

        if let Some(paths) = openapi_spec.get("paths") {
            if let Some(paths_obj) = paths.as_object() {
                for (path, path_item) in paths_obj {
                    endpoints.push_str(&self.generate_path_documentation(path, path_item));
                }
            }
        }

        endpoints.push_str("</div>");
        endpoints.push_str("</section>");

        endpoints
    }

    /// Generate documentation for a single path
    fn generate_path_documentation(&self, path: &str, path_item: &Value) -> String {
        let mut path_doc = String::new();

        path_doc.push_str(&format!("<div class=\"path-item\" data-path=\"{path}\">"));
        path_doc.push_str(&format!("<h3 class=\"path-title\">{path}</h3>"));

        if let Some(path_obj) = path_item.as_object() {
            for (method, operation) in path_obj {
                path_doc.push_str(&self.generate_operation_documentation(method, operation, path));
            }
        }

        path_doc.push_str("</div>");
        path_doc
    }

    /// Generate documentation for a single operation
    fn generate_operation_documentation(
        &self,
        method: &str,
        operation: &Value,
        path: &str,
    ) -> String {
        let mut op_doc = String::new();

        let method_upper = method.to_uppercase();
        op_doc.push_str(&format!(
            "<div class=\"operation\" data-method=\"{method}\" data-path=\"{path}\">"
        ));

        // Method and summary
        op_doc.push_str(&format!(
            "<div class=\"operation-header\"><span class=\"method method-{method}\">{method_upper}</span>"
        ));

        if let Some(summary) = operation.get("summary") {
            op_doc.push_str(&format!(
                "<span class=\"summary\">{}</span>",
                summary.as_str().unwrap_or("")
            ));
        }

        op_doc.push_str("</div>");

        // Description
        if let Some(description) = operation.get("description") {
            op_doc.push_str(&format!(
                "<p class=\"description\">{}</p>",
                description.as_str().unwrap_or("")
            ));
        }

        // Parameters
        if let Some(parameters) = operation.get("parameters") {
            op_doc.push_str(&self.generate_parameters_documentation(parameters));
        }

        // Request body
        if let Some(request_body) = operation.get("requestBody") {
            op_doc.push_str(&self.generate_request_body_documentation(request_body));
        }

        // Responses
        if let Some(responses) = operation.get("responses") {
            op_doc.push_str(&self.generate_responses_documentation(responses));
        }

        // Interactive testing section
        if self.config.enable_interactive {
            op_doc.push_str(&self.generate_try_it_section(method, path, operation));
        }

        op_doc.push_str("</div>");
        op_doc
    }

    /// Generate parameters documentation
    fn generate_parameters_documentation(&self, parameters: &Value) -> String {
        let mut params_doc = String::new();

        if let Some(params_array) = parameters.as_array() {
            if !params_array.is_empty() {
                params_doc.push_str("<h4>Parameters</h4>");
                params_doc.push_str("<table class=\"parameters-table\">");
                params_doc.push_str("<thead><tr><th>Name</th><th>Type</th><th>In</th><th>Required</th><th>Description</th></tr></thead>");
                params_doc.push_str("<tbody>");

                for param in params_array {
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let param_in = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                    let required = param
                        .get("required")
                        .and_then(|r| r.as_bool())
                        .unwrap_or(false);
                    let description = param
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");

                    let param_type = param
                        .get("schema")
                        .and_then(|s| s.get("type"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("string");

                    params_doc.push_str(&format!(
                        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        name, param_type, param_in, if required { "Yes" } else { "No" }, description
                    ));
                }

                params_doc.push_str("</tbody></table>");
            }
        }

        params_doc
    }

    /// Generate request body documentation
    fn generate_request_body_documentation(&self, request_body: &Value) -> String {
        let mut body_doc = String::new();

        body_doc.push_str("<h4>Request Body</h4>");

        let required = request_body
            .get("required")
            .and_then(|r| r.as_bool())
            .unwrap_or(false);
        if required {
            body_doc.push_str("<p><strong>Required</strong></p>");
        }

        if let Some(content) = request_body.get("content") {
            if let Some(content_obj) = content.as_object() {
                for (media_type, media_obj) in content_obj {
                    body_doc.push_str(&format!("<h5>{media_type}</h5>"));

                    if let Some(schema) = media_obj.get("schema") {
                        body_doc.push_str("<pre class=\"schema\"><code>");
                        body_doc
                            .push_str(&serde_json::to_string_pretty(schema).unwrap_or_default());
                        body_doc.push_str("</code></pre>");
                    }
                }
            }
        }

        body_doc
    }

    /// Generate responses documentation
    fn generate_responses_documentation(&self, responses: &Value) -> String {
        let mut responses_doc = String::new();

        responses_doc.push_str("<h4>Responses</h4>");

        if let Some(responses_obj) = responses.as_object() {
            for (status_code, response) in responses_obj {
                responses_doc.push_str(&format!(
                    "<div class=\"response-item\"><h5>HTTP {status_code}</h5>"
                ));

                if let Some(description) = response.get("description") {
                    responses_doc
                        .push_str(&format!("<p>{}</p>", description.as_str().unwrap_or("")));
                }

                if let Some(content) = response.get("content") {
                    if let Some(content_obj) = content.as_object() {
                        for (media_type, media_obj) in content_obj {
                            responses_doc.push_str(&format!("<h6>{media_type}</h6>"));

                            if let Some(schema) = media_obj.get("schema") {
                                responses_doc.push_str("<pre class=\"schema\"><code>");
                                responses_doc.push_str(
                                    &serde_json::to_string_pretty(schema).unwrap_or_default(),
                                );
                                responses_doc.push_str("</code></pre>");
                            }
                        }
                    }
                }

                responses_doc.push_str("</div>");
            }
        }

        responses_doc
    }

    /// Generate interactive "Try It" section
    fn generate_try_it_section(&self, method: &str, path: &str, operation: &Value) -> String {
        let mut try_it = String::new();

        try_it.push_str("<div class=\"try-it-section\">");
        try_it.push_str("<h4>Try It Out</h4>");
        try_it.push_str(&format!(
            "<form class=\"try-it-form\" data-method=\"{method}\" data-path=\"{path}\">"
        ));

        // Parameter inputs
        if let Some(parameters) = operation.get("parameters") {
            if let Some(params_array) = parameters.as_array() {
                for param in params_array {
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let param_in = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                    let required = param
                        .get("required")
                        .and_then(|r| r.as_bool())
                        .unwrap_or(false);

                    try_it.push_str(&format!(
                        "<div class=\"form-group\"><label for=\"{}\">{} ({}){}</label>",
                        name,
                        name,
                        param_in,
                        if required { " *" } else { "" }
                    ));

                    try_it.push_str(&format!(
                        "<input type=\"text\" id=\"{}\" name=\"{}\" data-in=\"{}\" {}>",
                        name,
                        name,
                        param_in,
                        if required { "required" } else { "" }
                    ));

                    try_it.push_str("</div>");
                }
            }
        }

        // Request body input
        if operation.get("requestBody").is_some() {
            try_it.push_str("<div class=\"form-group\">");
            try_it.push_str("<label for=\"request-body\">Request Body</label>");
            try_it.push_str("<textarea id=\"request-body\" name=\"body\" rows=\"10\" placeholder=\"Enter JSON request body\"></textarea>");
            try_it.push_str("</div>");
        }

        try_it.push_str("<button type=\"submit\" class=\"try-it-button\">Send Request</button>");
        try_it.push_str("</form>");

        // Response display
        try_it.push_str("<div class=\"response-display\" style=\"display: none;\">");
        try_it.push_str("<h5>Response</h5>");
        try_it.push_str("<pre class=\"response-content\"></pre>");
        try_it.push_str("</div>");

        try_it.push_str("</div>");
        try_it
    }

    /// Generate schemas section
    fn generate_schemas_section(&self, openapi_spec: &Value) -> String {
        let mut schemas = String::new();

        schemas.push_str("<section id=\"schemas\" class=\"schemas\">");
        schemas.push_str("<div class=\"container\">");
        schemas.push_str("<h2>Data Models</h2>");

        if let Some(components) = openapi_spec.get("components") {
            if let Some(schemas_obj) = components.get("schemas") {
                if let Some(schemas_map) = schemas_obj.as_object() {
                    for (schema_name, schema) in schemas_map {
                        schemas.push_str(&format!(
                            "<div class=\"schema-item\"><h3>{schema_name}</h3>"
                        ));

                        schemas.push_str("<pre class=\"schema\"><code>");
                        schemas.push_str(&serde_json::to_string_pretty(schema).unwrap_or_default());
                        schemas.push_str("</code></pre>");

                        schemas.push_str("</div>");
                    }
                }
            }
        }

        schemas.push_str("</div>");
        schemas.push_str("</section>");

        schemas
    }

    /// Generate footer
    fn generate_footer(&self) -> String {
        let mut footer = String::new();

        footer.push_str("<footer class=\"footer\">");
        footer.push_str("<div class=\"container\">");
        footer.push_str(
            "<p>Generated by DevDocs Pro - Real-time API documentation from traffic analysis</p>",
        );

        if let Some(contact) = &self.config.contact {
            if let Some(email) = &contact.email {
                footer.push_str(&format!(
                    "<p>Contact: <a href=\"mailto:{email}\">{email}</a></p>"
                ));
            }
        }

        footer.push_str("</div>");
        footer.push_str("</footer>");

        footer
    }

    /// Generate JavaScript for interactivity
    fn generate_javascript(&self) -> String {
        let mut js = String::new();

        js.push_str("<script>");
        js.push_str(include_str!("../../assets/documentation.js"));
        js.push_str("</script>");

        js
    }

    /// Basic markdown to HTML conversion
    fn markdown_to_html(&self, markdown: &str) -> String {
        let mut html = String::new();
        let lines: Vec<&str> = markdown.lines().collect();
        let mut in_code_block = false;

        for line in lines {
            if line.starts_with("```") {
                if in_code_block {
                    html.push_str("</code></pre>");
                    in_code_block = false;
                } else {
                    html.push_str("<pre><code>");
                    in_code_block = true;
                }
            } else if in_code_block {
                html.push_str(line);
                html.push('\n');
            } else if let Some(title) = line.strip_prefix("# ") {
                html.push_str(&format!("<h1>{title}</h1>"));
            } else if let Some(title) = line.strip_prefix("## ") {
                html.push_str(&format!("<h2>{title}</h2>"));
            } else if let Some(title) = line.strip_prefix("### ") {
                html.push_str(&format!("<h3>{title}</h3>"));
            } else if let Some(item) = line.strip_prefix("- ") {
                html.push_str(&format!("<li>{item}</li>"));
            } else if !line.trim().is_empty() {
                html.push_str(&format!("<p>{line}</p>"));
            }
        }

        if in_code_block {
            html.push_str("</code></pre>");
        }

        html
    }

    /// Update configuration
    pub fn update_config(&mut self, config: &DocumentationConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_html_generator_creation() {
        let config = DocumentationConfig::default();
        let generator = HtmlGenerator::new(&config);
        assert!(generator.is_ok());
    }

    #[tokio::test]
    async fn test_html_generation() {
        let config = DocumentationConfig::default();
        let generator = HtmlGenerator::new(&config).unwrap();

        let openapi_spec = json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    }
                }
            }
        });

        let html = generator.generate_html(&openapi_spec, None).await.unwrap();

        // Debug: print the HTML to see what's actually generated
        println!("Generated HTML: {html}");

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test API"));
        assert!(html.contains("/users"));
        assert!(html.contains("List users"));
    }

    #[test]
    fn test_markdown_to_html() {
        let config = DocumentationConfig::default();
        let generator = HtmlGenerator::new(&config).unwrap();

        let markdown =
            "# Title\n\nThis is a paragraph.\n\n## Subtitle\n\n- List item 1\n- List item 2";
        let html = generator.markdown_to_html(markdown);

        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<h2>Subtitle</h2>"));
        assert!(html.contains("<p>This is a paragraph.</p>"));
        assert!(html.contains("<li>List item 1</li>"));
    }
}
