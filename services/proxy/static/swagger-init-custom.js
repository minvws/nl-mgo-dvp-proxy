document.addEventListener("DOMContentLoaded", function() {
    SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: "#swagger-ui",
        deepLinking: false,
        showExtensions: true,
        showCommonExtensions: true,
        presets: [
            SwaggerUIBundle.presets.apis,
            SwaggerUIBundle.SwaggerUIStandalonePreset
        ]
    });
});
