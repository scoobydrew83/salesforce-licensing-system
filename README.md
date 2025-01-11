{
  `path`: `README.md`,
  `repo`: `salesforce-licensing-system`,
  `owner`: `scoobydrew83`,
  `branch`: `main`,
  `content`: `# Salesforce Managed Package Licensing System

Complete implementation guide and documentation for a scalable, secure licensing system for Salesforce managed packages.

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Database Schema](#database-schema)
5. [API Implementation](#api-implementation)
6. [Frontend Implementation](#frontend-implementation)
7. [Security](#security)
8. [Deployment](#deployment)
9. [Monitoring](#monitoring)
10. [Backup & Recovery](#backup--recovery)
11. [CI/CD](#cicd)
12. [Development Guide](#development-guide)

## System Overview

The Salesforce Managed Package Licensing System is a complete solution for managing and validating licenses for Salesforce managed packages. It provides:

- License generation and management
- Real-time license validation
- Organization management
- Usage tracking
- Admin portal
- Comprehensive API
- Automated deployment

### Key Features

- Secure license key generation and validation
- Multi-tenant support
- Rate limiting and abuse prevention
- Audit logging
- Analytics and reporting
- High availability setup
- Automated backups
- Monitoring and alerting

## Architecture

### High-Level Architecture Diagram

```
                                    +------------------------+
                                    |    Cloudflare DNS      |
                                    +------------------------+
                                              |
                                              v
+------------------+              +------------------------+
|  Salesforce Org  |  <------>   |      Load Balancer     |
+------------------+              +------------------------+
                                              |
                    +---------------------------+---------------------------+
                    |                          |                          |
            +---------------+           +---------------+          +---------------+
            |   API Node 1  |           |   API Node 2  |          |   API Node 3  |
            +---------------+           +---------------+          +---------------+
                    |                          |                          |
            +-------+------------------------+-+------------------------+--+-------+
            |                               |                          |          |
    +---------------+               +---------------+          +---------------+  |
    |  PostgreSQL   | <----------> |  PostgreSQL   |          |     Redis     |  |
    |  Primary      |             |   Replica     |          |    Cluster    |  |
    +---------------+               +---------------+          +---------------+  |
            |                                                                    |
            |                +--------------------------------+                  |
            +--------------> |         Admin Portal           | <---------------+
                            +--------------------------------+

```

### Component Details

#### Load Balancer
- AWS Application Load Balancer or DigitalOcean Load Balancer
- SSL/TLS termination
- Health checks every 30 seconds
- Connection draining enabled
- Cross-zone load balancing

#### API Nodes
- Multiple Node.js instances
- Auto-scaling group
- Health monitoring
- Graceful shutdown handling
- Load balanced requests

#### Database Layer
- PostgreSQL 14+ with replication
- PostGIS extension (optional)
- Automatic failover
- Connection pooling
- Regular backups

#### Caching Layer
- Redis 6.x cluster
- Multiple nodes for redundancy
- Persistence enabled
- Maxmemory-policy: volatile-lru

## Technology Stack

### Backend Technologies

```json
{
  \"runtime\": \"Node.js 18+\",
  \"framework\": \"Express 4.x\",
  \"language\": \"TypeScript 4.x\",
  \"database\": \"PostgreSQL 14+\",
  \"cache\": \"Redis 6.x\",
  \"authentication\": \"Auth0\",
  \"containerization\": \"Docker + Docker Compose\"
}
```

### Frontend Technologies

```json
{
  \"framework\": \"React 18+\",
  \"language\": \"TypeScript 4.x\",
  \"ui-framework\": \"Material-UI 5.x\",
  \"state-management\": \"Redux Toolkit\",
  \"routing\": \"React Router 6\",
  \"styling\": \"Emotion/Styled Components\"
}
```

### Infrastructure

```json
{
  \"cloud\": [\"AWS\", \"DigitalOcean\"],
  \"cdn\": \"Cloudflare\",
  \"monitoring\": [\"Prometheus\", \"Grafana\"],
  \"logging\": \"ELK Stack\",
  \"ci-cd\": \"GitHub Actions\"
}
```

## Database Schema

### Core Tables

```sql
-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";

-- Organization Management
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    salesforce_org_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    status VARCHAR(50) DEFAULT 'ACTIVE',
    max_licenses INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB,
    CONSTRAINT unique_sf_org_id UNIQUE (salesforce_org_id)
);

-- License Types
CREATE TABLE license_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    features JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_license_type_name UNIQUE (name)
);

-- Licenses
CREATE TABLE licenses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    license_key VARCHAR(255) NOT NULL,
    organization_id UUID REFERENCES organizations(id),
    license_type_id UUID REFERENCES license_types(id),
    status VARCHAR(50) DEFAULT 'ACTIVE',
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    warning_period_days INTEGER DEFAULT 30,
    max_users INTEGER,
    current_users INTEGER DEFAULT 0,
    is_trial BOOLEAN DEFAULT false,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_license_key UNIQUE (license_key),
    CONSTRAINT valid_status CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED'))
);

-- License Validations
CREATE TABLE license_validations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    license_id UUID REFERENCES licenses(id),
    organization_id UUID REFERENCES organizations(id),
    validation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_count INTEGER,
    status VARCHAR(50) NOT NULL,
    response_code INTEGER,
    validation_duration_ms INTEGER,
    request_payload JSONB,
    response_payload JSONB,
    CONSTRAINT valid_validation_status CHECK (status IN ('VALID', 'INVALID', 'EXPIRED', 'REVOKED'))
);

-- Audit Log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    changes JSONB,
    ip_address INET,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Indexes

```sql
-- Organizations
CREATE INDEX idx_org_sf_id ON organizations(salesforce_org_id);
CREATE INDEX idx_org_status ON organizations(status);
CREATE INDEX idx_org_domain ON organizations(domain);

-- Licenses
CREATE INDEX idx_license_org_id ON licenses(organization_id);
CREATE INDEX idx_license_type_id ON licenses(license_type_id);
CREATE INDEX idx_license_status ON licenses(status);
CREATE INDEX idx_license_dates ON licenses(start_date, end_date);

-- License Validations
CREATE INDEX idx_validation_license ON license_validations(license_id);
CREATE INDEX idx_validation_org ON license_validations(organization_id);
CREATE INDEX idx_validation_date ON license_validations(validation_date);

-- Audit Log
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_date ON audit_log(created_at);
```

## API Implementation

### Core API Structure

```typescript
// src/server.ts
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createPool } from './db/pool';
import { createRedisClient } from './cache/redis';
import { setupRoutes } from './routes';
import { errorHandler } from './middleware/error';
import { requestLogger } from './middleware/logging';

export async function createServer() {
    const app = express();
    
    // Security middleware
    app.use(helmet());
    app.use(express.json());
    
    // Rate limiting
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        standardHeaders: true,
        legacyHeaders: false
    });
    app.use(limiter);
    
    // Logging
    app.use(requestLogger());
    
    // Database connection
    const pool = await createPool();
    app.locals.db = pool;
    
    // Redis connection
    const redis = await createRedisClient();
    app.locals.redis = redis;
    
    // Setup routes
    setupRoutes(app);
    
    // Error handling
    app.use(errorHandler);
    
    return app;
}
```

### API Endpoints

#### License Management

```typescript
// src/routes/licenses.ts
import { Router } from 'express';
import { validateLicenseRequest } from '../middleware/validation';
import { authenticateRequest } from '../middleware/auth';
import * as LicenseController from '../controllers/licenses';

const router = Router();

router.post(
    '/licenses',
    authenticateRequest,
    validateLicenseRequest,
    LicenseController.createLicense
);

router.get(
    '/licenses/:licenseKey',
    authenticateRequest,
    LicenseController.getLicense
);

router.post(
    '/licenses/validate',
    LicenseController.validateLicense
);

export default router;
```

### License Controller Implementation

```typescript
// src/controllers/licenses.ts
import { Request, Response, NextFunction } from 'express';
import { LicenseService } from '../services/license';
import { AuditService } from '../services/audit';
import { createError } from '../utils/errors';

export async function createLicense(
    req: Request,
    res: Response,
    next: NextFunction
) {
    try {
        const licenseData = req.body;
        const license = await LicenseService.createLicense(licenseData);
        
        await AuditService.log({
            entityType: 'LICENSE',
            entityId: license.id,
            action: 'CREATE',
            actorId: req.user.id,
            changes: licenseData,
            ipAddress: req.ip
        });
        
        res.status(201).json(license);
    } catch (error) {
        next(error);
    }
}

export async function validateLicense(
    req: Request,
    res: Response,
    next: NextFunction
) {
    try {
        const { licenseKey, orgId } = req.body;
        
        const validation = await LicenseService.validateLicense(
            licenseKey,
            orgId
        );
        
        res.json(validation);
    } catch (error) {
        next(error);
    }
}
```

## Frontend Implementation

### Admin Portal Structure

```typescript
// src/App.tsx
import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { ThemeProvider } from '@mui/material/styles';
import { Provider } from 'react-redux';
import { Auth0Provider } from '@auth0/auth0-react';
import { theme } from './theme';
import { store } from './store';
import { AppRouter } from './router';
import { Layout } from './components/Layout';

export const App: React.FC = () => {
    return (
        <Auth0Provider
            domain={process.env.REACT_APP_AUTH0_DOMAIN!}
            clientId={process.env.REACT_APP_AUTH0_CLIENT_ID!}
            redirectUri={window.location.origin}
        >
            <Provider store={store}>
                <ThemeProvider theme={theme}>
                    <BrowserRouter>
                        <Layout>
                            <AppRouter />
                        </Layout>
                    </BrowserRouter>
                </ThemeProvider>
            </Provider>
        </Auth0Provider>
    );
};
```

### License Management Component

```typescript
// src/components/LicenseManagement/LicenseList.tsx
import React from 'react';
import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    IconButton,
    Tooltip
} from '@mui/material';
import { Edit, Delete, Refresh } from '@mui/icons-material';
import { useGetLicensesQuery } from '../../services/api';
import { License } from '../../types';

export const LicenseList: React.FC = () => {
    const { data: licenses, isLoading, error } = useGetLicensesQuery();

    if (isLoading) return <div>Loading...</div>;
    if (error) return <div>Error loading licenses</div>;

    return (
        <TableContainer component={Paper}>
            <Table>
                <TableHead>
                    <TableRow>
                        <TableCell>License Key</TableCell>
                        <TableCell>Organization</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Expiration</TableCell>
                        <TableCell>Actions</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {licenses.map((license: License) => (
                        <TableRow key={license.id}>
                            <TableCell>{license.licenseKey}</TableCell>
                            <TableCell>{license.organization.name}</TableCell>
                            <TableCell>{license.status}</TableCell>
                            <TableCell>
                                {new Date(license.endDate).toLocaleDateString()}
                            </TableCell>
                            <TableCell>
                                <Tooltip title=\"Edit\">
                                    <IconButton>
                                        <Edit />
                                    </IconButton>
                                </Tooltip>
                                <Tooltip title=\"Delete\">
                                    <IconButton>
                                        <Delete />
                                    </IconButton>
                                </Tooltip>
                                <Tooltip title=\"Refresh\">
                                    <IconButton>
                                        <Refresh />
                                    </IconButton>
                                </Tooltip>
                            </TableCell>`,
  {
  `path`: `README.md`,
  `repo`: `salesforce-licensing-system`,
  `owner`: `scoobydrew83`,
  `branch`: `main`,
  `content`: `                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    );
};

## Security

### Authentication Implementation

```typescript
// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'express-jwt';
import jwks from 'jwks-rsa';

export const authenticateRequest = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
    }),
    audience: process.env.AUTH0_AUDIENCE,
    issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    algorithms: ['RS256']
});

export const requireScopes = (requiredScopes: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const tokenScopes = req.user?.scope?.split(' ') || [];
        const hasRequiredScopes = requiredScopes.every(scope => 
            tokenScopes.includes(scope)
        );
        
        if (!hasRequiredScopes) {
            return res.status(403).json({
                error: 'Insufficient permissions'
            });
        }
        
        next();
    };
};
```

### Rate Limiting

```typescript
// src/middleware/rateLimit.ts
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redis } from '../services/redis';

export const createRateLimiter = (options: {
    windowMs?: number;
    max?: number;
    keyPrefix?: string;
}) => {
    return rateLimit({
        store: new RedisStore({
            client: redis,
            prefix: options.keyPrefix || 'rl:'
        }),
        windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
        max: options.max || 100,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            res.status(429).json({
                error: 'Too many requests, please try again later.'
            });
        }
    });
};

// API-specific rate limiters
export const licensingRateLimiter = createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 30,
    keyPrefix: 'rl:licensing:'
});

export const validationRateLimiter = createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    keyPrefix: 'rl:validation:'
});
```

## Deployment

### Docker Configuration

```dockerfile
# Dockerfile for API
FROM node:18-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:18-alpine

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

EXPOSE 3000
CMD [\"npm\", \"start\"]
```

### Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: 
      context: ./api
      dockerfile: Dockerfile
    restart: always
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:pass@db:5432/licensing
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    ports:
      - \"3000:3000\"

  admin:
    build:
      context: ./admin-portal
      dockerfile: Dockerfile
    restart: always
    ports:
      - \"80:80\"
    depends_on:
      - api

  db:
    image: postgres:14-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=licensing
      - POSTGRES_PASSWORD=secure_password
      - POSTGRES_DB=licensing
    ports:
      - \"5432:5432\"

  redis:
    image: redis:6-alpine
    command: redis-server --appendonly yes
    volumes:
      - redisdata:/data
    ports:
      - \"6379:6379\"

volumes:
  pgdata:
  redisdata:
```

### Deployment Scripts

```bash
#!/bin/bash
# deploy.sh

set -e

# Load environment variables
source .env

# Pull latest changes
git pull origin main

# Build and start containers
docker-compose build
docker-compose up -d

# Run database migrations
npm run migrate:latest

# Clear Redis cache
docker-compose exec redis redis-cli FLUSHALL

# Health check
curl -f http://localhost:3000/health || exit 1

echo \"Deployment completed successfully\"
```

## Monitoring

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'licensing-api'
    static_configs:
      - targets: ['api:3000']

  - job_name: 'nodejs'
    static_configs:
      - targets: ['api:9090']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
```

### Grafana Dashboard Configuration

```json
{
  \"dashboard\": {
    \"id\": null,
    \"title\": \"Licensing System Dashboard\",
    \"tags\": [\"licensing\"],
    \"timezone\": \"browser\",
    \"panels\": [
      {
        \"title\": \"License Validations per Minute\",
        \"type\": \"graph\",
        \"datasource\": \"Prometheus\",
        \"targets\": [
          {
            \"expr\": \"rate(license_validations_total[1m])\",
            \"legendFormat\": \"Validations\"
          }
        ]
      },
      {
        \"title\": \"API Response Times\",
        \"type\": \"graph\",
        \"datasource\": \"Prometheus\",
        \"targets\": [
          {
            \"expr\": \"histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))\",
            \"legendFormat\": \"95th Percentile\"
          }
        ]
      }
    ]
  }
}
```

## CI/CD

### GitHub Actions Workflow

```yaml
# .github/workflows/main.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis
        ports:
          - 6379:6379
        options: >-
          --health-cmd \"redis-cli ping\"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run tests
      run: npm test
      env:
        DATABASE_URL: postgresql://test:test@localhost:5432/test
        REDIS_URL: redis://localhost:6379
    
    - name: Run linting
      run: npm run lint

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v1
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1
    
    - name: Login to Amazon ECR
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v1
    
    - name: Build and push API image
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        docker build -t $ECR_REGISTRY/licensing-api:$IMAGE_TAG .
        docker push $ECR_REGISTRY/licensing-api:$IMAGE_TAG
    
    - name: Deploy to production
      uses: appleboy/ssh-action@master
      with:
        host: ${{ secrets.PROD_HOST }}
        username: ${{ secrets.PROD_USERNAME }}
        key: ${{ secrets.PROD_SSH_KEY }}
        script: |
          cd /opt/licensing-system
          echo \"IMAGE_TAG=${{ github.sha }}\" > .env
          docker-compose pull
          docker-compose up -d
```

## Development Guide

### Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/licensing-system.git
cd licensing-system
```

2. Install dependencies:
```bash
# Install API dependencies
cd api
npm install

# Install Admin Portal dependencies
cd ../admin-portal
npm install
```

3. Set up environment variables:
```bash
# API environment
cp api/.env.example api/.env

# Admin Portal environment
cp admin-portal/.env.example admin-portal/.env
```

4. Start development services:
```bash
# Start database and Redis
docker-compose -f docker-compose.dev.yml up -d

# Run database migrations
cd api
npm run migrate:latest

# Start API in development mode
npm run dev

# Start Admin Portal in development mode
cd ../admin-portal
npm start
```

### Development Commands

```json
{
  \"scripts\": {
    \"dev\": \"ts-node-dev --respawn src/server.ts\",
    \"build\": \"tsc\",
    \"start\": \"node dist/server.js\",
    \"test\": \"jest\",
    \"test:watch\": \"jest --watch\",
    \"lint\": \"eslint . --ext .ts\",
    \"lint:fix\": \"eslint . --ext .ts --fix\",
    \"migrate:make\": \"knex migrate:make\",
    \"migrate:latest\": \"knex migrate:latest\",
    \"migrate:rollback\": \"knex migrate:rollback\"
  }
}
```

### Testing Guidelines

1. Unit Tests Location:
```
src/
└── __tests__/
    ├── unit/
    │   ├── services/
    │   ├── controllers/
    │   └── utils/
    └── integration/
        ├── api/
        └── db/
```

2. Example Test:
```typescript
// src/__tests__/unit/services/license.test.ts
import { LicenseService } from '../../../services/license';
import { db } from '../../../db';

describe('LicenseService', () => {
    beforeEach(async () => {
        await db.migrate.rollback();
        await db.migrate.latest();
    });

    afterAll(async () => {
        await db.destroy();
    });

    describe('createLicense', () => {
        it('should create a new license', async () => {
            const licenseData = {
                organizationId: 'test-org',
                type: 'STANDARD',
                startDate: new Date(),
                endDate: new Date(Date.now() + 86400000)
            };

            const license = await LicenseService.createLicense(licenseData);

            expect(license).toHaveProperty('id');
            expect(license).toHaveProperty('licenseKey');
            expect(license.organizationId).toBe(licenseData.organizationId);
        });
    });
});
```

### API Documentation

Documentation is automatically generated using OpenAPI/Swagger:

```typescript
// src/swagger.ts
export const swaggerDocument = {
    openapi: '3.0.0',
    info: {
        title: 'Licensing API',
        version: '1.0.0',
        description: 'API for managing Salesforce managed package licenses'
    },
    servers: [
        {
            url: 'http://localhost:3000',
            description: 'Development server'
        }
    ],
    paths: {
        '/licenses': {
            post: {
                summary: 'Create a new license',
                tags: ['Licenses'],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                $ref: '#/components/schemas/CreateLicenseRequest'
                            }
                        }
                    }
                },
                responses: {
                    '201': {
                        description: 'License created successfully',
                        content: {
                            'application/json': {
                                schema: {
                                    $ref: '#/components/schemas/License'
                                }
                            }
                        }
                    }
                }
            }
        }
    }
};
```

This comprehensive documentation provides all the necessary details for setting up, developing, and maintaining the Salesforce Managed Package Licensing System. For additional support or questions, please consult the project maintainers.`,
  `message`: `Added comprehensive implementation details`
}
## API Documentation

### OpenAPI/Swagger Documentation

The API is documented using OpenAPI (Swagger) specification:

```yaml
openapi: 3.0.0
info:
  title: Licensing API
  version: 1.0.0
  description: API for managing Salesforce managed package licenses
paths:
  /licenses:
    post:
      summary: Create new license
      tags: [Licenses]
      security

paths:
  /licenses:
    post:
      summary: Create new license
      tags: [Licenses]
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateLicenseRequest'
      responses:
        '201':
          description: License created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/License'
        '400':
          description: Invalid request
        '401':
          description: Unauthorized
        '403':
          description: Forbidden

    get:
      summary: List all licenses
      tags: [Licenses]
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: page
          schema:
            type: integer
            default: 1
        - in: query
          name: limit
          schema:
            type: integer
            default: 20
      responses:
        '200':
          description: List of licenses
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/License'
                  pagination:
                    $ref: '#/components/schemas/Pagination'

  /licenses/{licenseKey}:
    get:
      summary: Get license details
      tags: [Licenses]
      parameters:
        - in: path
          name: licenseKey
          required: true
          schema:
            type: string
      responses:
        '200':
          description: License details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/License'
        '404':
          description: License not found

  /licenses/validate:
    post:
      summary: Validate license
      tags: [Licenses]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - licenseKey
                - orgId
              properties:
                licenseKey:
                  type: string
                orgId:
                  type: string
                userCount:
                  type: integer
      responses:
        '200':
          description: License validation result
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ValidationResult'

components:
  schemas:
    CreateLicenseRequest:
      type: object
      required:
        - organizationId
        - licenseTypeId
        - startDate
        - endDate
      properties:
        organizationId:
          type: string
          format: uuid
        licenseTypeId:
          type: string
          format: uuid
        startDate:
          type: string
          format: date-time
        endDate:
          type: string
          format: date-time
        maxUsers:
          type: integer
          minimum: 1
        isTrial:
          type: boolean
          default: false

    License:
      type: object
      properties:
        id:
          type: string
          format: uuid
        licenseKey:
          type: string
        organizationId:
          type: string
          format: uuid
        status:
          type: string
          enum: [ACTIVE, EXPIRED, REVOKED, SUSPENDED]
        startDate:
          type: string
          format: date-time
        endDate:
          type: string
          format: date-time
        maxUsers:
          type: integer
        currentUsers:
          type: integer
        isTrial:
          type: boolean
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time

    ValidationResult:
      type: object
      properties:
        valid:
          type: boolean
        status:
          type: string
          enum: [VALID, INVALID, EXPIRED, REVOKED]
        message:
          type: string
        expirationDate:
          type: string
          format: date-time
        maxUsers:
          type: integer
        features:
          type: array
          items:
            type: string

    Pagination:
      type: object
      properties:
        currentPage:
          type: integer
        totalPages:
          type: integer
        totalItems:
          type: integer
        itemsPerPage:
          type: integer

  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT


Salesforce Integration
Apex Integration Class

public class LicenseValidator {
    private static final String API_ENDPOINT = 'https://api.licensing.example.com';
    private static final String LICENSE_KEY = 'YOUR_LICENSE_KEY';
    
    public class ValidationResult {
        @AuraEnabled public Boolean isValid { get; set; }
        @AuraEnabled public String status { get; set; }
        @AuraEnabled public String message { get; set; }
        @AuraEnabled public DateTime expirationDate { get; set; }
    }
    
    @AuraEnabled
    public static ValidationResult validateLicense() {
        try {
            String orgId = UserInfo.getOrganizationId();
            Integer userCount = [SELECT COUNT() FROM User WHERE IsActive = true];
            
            Http http = new Http();
            HttpRequest request = new HttpRequest();
            request.setEndpoint(API_ENDPOINT + '/licenses/validate');
            request.setMethod('POST');
            request.setHeader('Content-Type', 'application/json');
            
            Map<String, Object> requestBody = new Map<String, Object>{
                'licenseKey' => LICENSE_KEY,
                'orgId' => orgId,
                'userCount' => userCount
            };
            
            request.setBody(JSON.serialize(requestBody));
            
            HttpResponse response = http.send(request);
            
            if (response.getStatusCode() == 200) {
                Map<String, Object> result = (Map<String, Object>)JSON.deserializeUntyped(response.getBody());
                
                ValidationResult validationResult = new ValidationResult();
                validationResult.isValid = (Boolean)result.get('valid');
                validationResult.status = (String)result.get('status');
                validationResult.message = (String)result.get('message');
                validationResult.expirationDate = DateTime.valueOf((String)result.get('expirationDate'));
                
                return validationResult;
            } else {
                throw new LicenseException('License validation failed: ' + response.getStatus());
            }
        } catch (Exception e) {
            throw new LicenseException('License validation error: ' + e.getMessage());
        }
    }
    
    public class LicenseException extends Exception {}
}
}
