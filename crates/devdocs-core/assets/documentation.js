// DevDocs Pro Interactive Documentation JavaScript

(function() {
    'use strict';

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    function init() {
        setupNavigation();
        setupTryItForms();
        setupCodeCopying();
        setupSearchFunctionality();
        setupRealtimeUpdates();
        setupResponsiveNavigation();
    }

    // Navigation functionality
    function setupNavigation() {
        const navLinks = document.querySelectorAll('.nav-menu a');
        const sections = document.querySelectorAll('section[id]');

        // Smooth scrolling for navigation links
        navLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                const href = this.getAttribute('href');
                if (href.startsWith('#')) {
                    e.preventDefault();
                    const target = document.querySelector(href);
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                }
            });
        });

        // Update active navigation on scroll
        function updateActiveNav() {
            let current = '';
            sections.forEach(section => {
                const sectionTop = section.offsetTop - 100;
                if (window.pageYOffset >= sectionTop) {
                    current = section.getAttribute('id');
                }
            });

            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current) {
                    link.classList.add('active');
                }
            });
        }

        window.addEventListener('scroll', updateActiveNav);
        updateActiveNav(); // Initial call
    }

    // Try It functionality
    function setupTryItForms() {
        const forms = document.querySelectorAll('.try-it-form');
        
        forms.forEach(form => {
            form.addEventListener('submit', async function(e) {
                e.preventDefault();
                await handleApiRequest(this);
            });
        });
    }

    async function handleApiRequest(form) {
        const method = form.dataset.method.toUpperCase();
        const pathTemplate = form.dataset.path;
        const button = form.querySelector('.try-it-button');
        const responseDisplay = form.parentElement.querySelector('.response-display');
        const responseContent = responseDisplay.querySelector('.response-content');

        // Show loading state
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span> Sending...';
        responseDisplay.style.display = 'block';
        responseContent.textContent = 'Sending request...';

        try {
            // Build URL
            let url = pathTemplate;
            const formData = new FormData(form);
            const queryParams = new URLSearchParams();
            let requestBody = null;

            // Process form inputs
            for (const [name, value] of formData.entries()) {
                const input = form.querySelector(`[name="${name}"]`);
                const paramIn = input.dataset.in;

                if (paramIn === 'path') {
                    url = url.replace(`{${name}}`, encodeURIComponent(value));
                } else if (paramIn === 'query') {
                    if (value.trim()) {
                        queryParams.append(name, value);
                    }
                } else if (name === 'body') {
                    if (value.trim()) {
                        try {
                            requestBody = JSON.parse(value);
                        } catch (e) {
                            throw new Error('Invalid JSON in request body');
                        }
                    }
                }
            }

            // Add query parameters
            if (queryParams.toString()) {
                url += '?' + queryParams.toString();
            }

            // Get base URL (if available)
            const baseUrl = getBaseUrl();
            const fullUrl = baseUrl + url;

            // Prepare request options
            const requestOptions = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };

            if (requestBody && ['POST', 'PUT', 'PATCH'].includes(method)) {
                requestOptions.body = JSON.stringify(requestBody, null, 2);
            }

            // Add authentication if available
            const authToken = getAuthToken();
            if (authToken) {
                requestOptions.headers['Authorization'] = `Bearer ${authToken}`;
            }

            // Make the request
            const response = await fetch(fullUrl, requestOptions);
            const responseText = await response.text();
            
            let responseData;
            try {
                responseData = JSON.parse(responseText);
            } catch (e) {
                responseData = responseText;
            }

            // Display response
            const responseInfo = {
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers.entries()),
                data: responseData
            };

            responseContent.innerHTML = formatResponse(responseInfo);
            responseContent.className = `response-content ${response.ok ? 'status-success' : 'status-error'}`;

        } catch (error) {
            responseContent.innerHTML = `<span class="status-error">Error: ${error.message}</span>`;
            responseContent.className = 'response-content status-error';
        } finally {
            // Reset button
            button.disabled = false;
            button.textContent = 'Send Request';
        }
    }

    function getBaseUrl() {
        // Try to get base URL from the page or use current origin
        const serverList = document.querySelector('.server-list');
        if (serverList) {
            const firstServer = serverList.querySelector('code');
            if (firstServer) {
                return firstServer.textContent.trim();
            }
        }
        return window.location.origin;
    }

    function getAuthToken() {
        // Check for stored auth token
        return localStorage.getItem('devdocs-auth-token') || '';
    }

    function formatResponse(responseInfo) {
        const { status, statusText, headers, data } = responseInfo;
        
        let html = `<div class="response-status">
            <strong>Status:</strong> ${status} ${statusText}
        </div>`;
        
        html += `<div class="response-headers">
            <strong>Headers:</strong>
            <pre>${JSON.stringify(headers, null, 2)}</pre>
        </div>`;
        
        html += `<div class="response-body">
            <strong>Body:</strong>
            <pre>${typeof data === 'string' ? data : JSON.stringify(data, null, 2)}</pre>
        </div>`;
        
        return html;
    }

    // Code copying functionality
    function setupCodeCopying() {
        const codeBlocks = document.querySelectorAll('pre code');
        
        codeBlocks.forEach(block => {
            const pre = block.parentElement;
            const button = document.createElement('button');
            button.className = 'copy-button';
            button.textContent = 'Copy';
            button.style.cssText = `
                position: absolute;
                top: 0.5rem;
                right: 0.5rem;
                background: var(--primary-color);
                color: white;
                border: none;
                padding: 0.25rem 0.5rem;
                border-radius: var(--radius-sm);
                font-size: 0.75rem;
                cursor: pointer;
                opacity: 0;
                transition: opacity 0.2s ease;
            `;
            
            pre.style.position = 'relative';
            pre.appendChild(button);
            
            pre.addEventListener('mouseenter', () => {
                button.style.opacity = '1';
            });
            
            pre.addEventListener('mouseleave', () => {
                button.style.opacity = '0';
            });
            
            button.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(block.textContent);
                    button.textContent = 'Copied!';
                    setTimeout(() => {
                        button.textContent = 'Copy';
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy code:', err);
                }
            });
        });
    }

    // Search functionality
    function setupSearchFunctionality() {
        // Create search input
        const nav = document.querySelector('.navigation .container');
        if (nav) {
            const searchContainer = document.createElement('div');
            searchContainer.className = 'search-container';
            searchContainer.style.cssText = `
                position: relative;
                margin-left: auto;
            `;
            
            const searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'Search endpoints...';
            searchInput.className = 'search-input';
            searchInput.style.cssText = `
                padding: 0.5rem 1rem;
                border: 1px solid var(--border-color);
                border-radius: var(--radius-md);
                font-size: 0.875rem;
                width: 250px;
            `;
            
            const searchResults = document.createElement('div');
            searchResults.className = 'search-results';
            searchResults.style.cssText = `
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: white;
                border: 1px solid var(--border-color);
                border-radius: var(--radius-md);
                box-shadow: var(--shadow-lg);
                max-height: 300px;
                overflow-y: auto;
                z-index: 1000;
                display: none;
            `;
            
            searchContainer.appendChild(searchInput);
            searchContainer.appendChild(searchResults);
            nav.appendChild(searchContainer);
            
            // Search functionality
            let searchTimeout;
            searchInput.addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    performSearch(this.value, searchResults);
                }, 300);
            });
            
            // Hide results when clicking outside
            document.addEventListener('click', function(e) {
                if (!searchContainer.contains(e.target)) {
                    searchResults.style.display = 'none';
                }
            });
        }
    }

    function performSearch(query, resultsContainer) {
        if (!query.trim()) {
            resultsContainer.style.display = 'none';
            return;
        }
        
        const operations = document.querySelectorAll('.operation');
        const results = [];
        
        operations.forEach(operation => {
            const method = operation.dataset.method;
            const path = operation.dataset.path;
            const summary = operation.querySelector('.summary')?.textContent || '';
            const description = operation.querySelector('.description')?.textContent || '';
            
            const searchText = `${method} ${path} ${summary} ${description}`.toLowerCase();
            if (searchText.includes(query.toLowerCase())) {
                results.push({
                    method,
                    path,
                    summary,
                    element: operation
                });
            }
        });
        
        displaySearchResults(results, resultsContainer);
    }

    function displaySearchResults(results, container) {
        if (results.length === 0) {
            container.innerHTML = '<div style="padding: 1rem; color: var(--text-muted);">No results found</div>';
        } else {
            container.innerHTML = results.map(result => `
                <div class="search-result" style="padding: 0.75rem; border-bottom: 1px solid var(--border-color); cursor: pointer;">
                    <div style="font-weight: 500;">
                        <span class="method method-${result.method.toLowerCase()}" style="margin-right: 0.5rem;">${result.method.toUpperCase()}</span>
                        ${result.path}
                    </div>
                    <div style="font-size: 0.875rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        ${result.summary}
                    </div>
                </div>
            `).join('');
            
            // Add click handlers
            container.querySelectorAll('.search-result').forEach((resultEl, index) => {
                resultEl.addEventListener('click', () => {
                    results[index].element.scrollIntoView({
                        behavior: 'smooth',
                        block: 'center'
                    });
                    container.style.display = 'none';
                });
            });
        }
        
        container.style.display = 'block';
    }

    // Real-time updates via WebSocket
    function setupRealtimeUpdates() {
        if (!window.WebSocket) {
            return; // WebSocket not supported
        }
        
        // Try to connect to WebSocket for real-time updates
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/documentation`;
        
        try {
            const ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('Connected to real-time updates');
                showNotification('Connected to real-time updates', 'success');
            };
            
            ws.onmessage = function(event) {
                try {
                    const update = JSON.parse(event.data);
                    handleRealtimeUpdate(update);
                } catch (e) {
                    console.error('Failed to parse WebSocket message:', e);
                }
            };
            
            ws.onclose = function() {
                console.log('Disconnected from real-time updates');
                // Try to reconnect after 5 seconds
                setTimeout(() => setupRealtimeUpdates(), 5000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
            
        } catch (e) {
            console.log('Real-time updates not available');
        }
    }

    function handleRealtimeUpdate(update) {
        switch (update.type) {
            case 'EndpointAdded':
                showNotification(`New endpoint discovered: ${update.endpoint.method} ${update.endpoint.path_pattern}`, 'info');
                break;
            case 'EndpointUpdated':
                showNotification(`Endpoint updated: ${update.endpoint.method} ${update.endpoint.path_pattern}`, 'info');
                break;
            case 'SchemaAdded':
                showNotification(`New schema discovered: ${update.name}`, 'info');
                break;
            case 'SchemaUpdated':
                showNotification(`Schema updated: ${update.name}`, 'info');
                break;
            case 'DocumentationUpdated':
                showNotification('Documentation has been updated', 'success');
                // Optionally reload the page or update content
                break;
            case 'BreakingChange':
                showNotification(`Breaking change detected: ${update.description}`, 'warning');
                break;
        }
    }

    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 1rem;
            right: 1rem;
            background: ${type === 'success' ? 'var(--success-color)' : 
                        type === 'warning' ? 'var(--warning-color)' : 
                        type === 'error' ? 'var(--error-color)' : 'var(--primary-color)'};
            color: white;
            padding: 1rem 1.5rem;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            z-index: 10000;
            max-width: 400px;
            animation: slideIn 0.3s ease;
        `;
        
        notification.textContent = message;
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
        
        // Add click to dismiss
        notification.addEventListener('click', () => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        });
    }

    // Responsive navigation
    function setupResponsiveNavigation() {
        const nav = document.querySelector('.navigation');
        const navMenu = document.querySelector('.nav-menu');
        
        if (window.innerWidth <= 768) {
            // Add mobile menu toggle
            const toggleButton = document.createElement('button');
            toggleButton.className = 'nav-toggle';
            toggleButton.innerHTML = '☰';
            toggleButton.style.cssText = `
                display: block;
                background: none;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                padding: 0.5rem;
                margin-left: auto;
            `;
            
            nav.querySelector('.container').appendChild(toggleButton);
            
            toggleButton.addEventListener('click', () => {
                navMenu.classList.toggle('mobile-open');
            });
        }
    }

    // Add CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
        
        .nav-menu.mobile-open {
            display: flex !important;
            flex-direction: column;
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-lg);
        }
        
        @media (max-width: 768px) {
            .nav-menu {
                display: none;
            }
        }
    `;
    document.head.appendChild(style);

})();