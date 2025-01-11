                        </TableRow>
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
CMD ["npm", "start"]
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
      - "3000:3000"

  admin:
    build:
      context: ./admin-portal
      dockerfile: Dockerfile
    restart: always
    ports:
      - "80:80"
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
      - "5432:5432"

  redis:
    image: redis:6-alpine
    command: redis-server --appendonly yes
    volumes:
      - redisdata:/data
    ports:
      - "6379:6379"

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

echo "Deployment completed successfully"
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
  "dashboard": {
    "id": null,
    "title": "Licensing System Dashboard",
    "tags": ["licensing"],
    "timezone": "browser",
    "panels": [
      {
        "title": "License Validations per Minute",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "rate(license_validations_total[1m])",
            "legendFormat": "Validations"
          }
        ]
      },
      {
        "title": "API Response Times",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th Percentile"
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
          --health-cmd "redis-cli ping"
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
          echo "IMAGE_TAG=${{ github.sha }}" > .env
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
  "scripts": {
    "dev": "ts-node-dev --respawn src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "lint": "eslint . --ext .ts",
    "lint:fix": "eslint . --ext .ts --fix",
    "migrate:make": "knex migrate:make",
    "migrate:latest": "knex migrate:latest",
    "migrate:rollback": "knex migrate:rollback"
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

This comprehensive documentation provides all the necessary details for setting up, developing, and maintaining the Salesforce Managed Package Licensing System. For additional support or questions, please consult the project maintainers.