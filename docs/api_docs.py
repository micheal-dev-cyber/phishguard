"""REST API docs page — Swagger/OpenAPI UI with full endpoint listing."""

SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard AI — API Reference</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>
  body { margin:0; background:#0d1117; }
  .swagger-ui .topbar { display:none; }
  .swagger-ui .info .title { color:#e2e8f0; }
  .swagger-ui .info { margin:20px 0; }
  .swagger-ui .scheme-container { background:#111827; box-shadow:none; }
  .swagger-ui .opblock-tag { color:#60a5fa; }
  .swagger-ui .opblock .opblock-summary-path { font-weight:700; }
  .swagger-ui .opblock .opblock-summary-description { color:#94a3b8; }
  .swagger-ui .opblock-body { background:#0d1117; }
  .swagger-ui .model-box { background:#111827; }
  .swagger-ui section.models { background:#111827; }
  .swagger-ui .models-control { color:#60a5fa; }
  .swagger-ui .model-container { background:#1e293b; }
  .swagger-ui .model-title { color:#e2e8f0; }
  .swagger-ui label { color:#94a3b8; }
  .swagger-ui .responses-inner h4, .swagger-ui .responses-inner h5 { color:#e2e8f0; }
  .swagger-ui .parameter__name { color:#e2e8f0; }
  .swagger-ui .parameter__type { color:#60a5fa; }
  .swagger-ui .prop-type { color:#60a5fa; }
  .swagger-ui .response-col_status { color:#e2e8f0; }
  .swagger-ui .response-col_description { color:#94a3b8; }
  .swagger-ui table thead tr td { color:#e2e8f0; }
</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: '/api/v1/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
    layout: 'BaseLayout',
    docExpansion: 'list',
    defaultModelsExpandDepth: -1,
  });
</script>
</body>
</html>"""


def render_api_docs_page():
    import streamlit as st
    st.set_page_config(page_title="API Reference — PhishGuard AI", layout="wide")
    st.markdown(SWAGGER_HTML, unsafe_allow_html=True)
