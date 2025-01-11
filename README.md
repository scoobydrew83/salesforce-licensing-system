## API Documentation

### OpenAPI/Swagger Documentation

The API is documented using OpenAPI (Swagger) specification. All endpoints, request/response schemas, and authentication requirements are detailed in the specification.

```yaml
openapi: 3.0.0
info:
  title: Licensing API
  version: 1.0.0
  description: API for managing Salesforce managed package licenses
servers:
  - url: http://localhost:3000
    description: Development server
  - url: https://api.licensing.example.com
    description: Production server
