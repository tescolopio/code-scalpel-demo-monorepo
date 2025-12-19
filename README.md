# code-scalpel-demo-monorepo
Verify and demonstrate the revolutionary claims of Code Scalpel v2.5+ and v3.0. Audience: Engineering (QA), Security (Red Team), Marketing (Demos). Principle: "If a demo needs explanation, it’s not ready."

## Project Structure

This monorepo contains:

- **`/backend`**: Java 21 Spring Boot 3.2 application
  - Spring Boot Web
  - Spring Data JPA
  - Spring Security
  - Spring Boot Actuator
  - PostgreSQL driver
  
- **`/frontend`**: React 18+ with Vite and TypeScript
  - Axios for HTTP requests
  - React Router DOM for routing
  
- **`/docker-compose.yml`**: PostgreSQL 15 database service

- **`/torture-tests/stage3-boundary-crossing`**: Fixtures for the Boundary Crossing level of the Code Scalpel Ninja Warrior torture suite (cross-language contract, schema drift, protocol hopping, ORM leaks, and message queue taint)
- **`/torture-tests/stage-4-confidence-crisis`**: Code Scalpel Ninja Warrior Stage 4 torture cases focused on uncertainty quantification
  
- **`/.scalpel`**: Empty config directories
  - `policy/`: Policy configurations
  - `budget/`: Budget configurations
  
- **`pom.xml`**: Root multimodule Maven build

## Prerequisites

- Java 21
- Maven 3.9+
- Node.js 18+ and npm
- Docker and Docker Compose

## Quick Start

### Backend (Spring Boot)

```bash
cd backend
mvn clean install
mvn spring-boot:run
```

The backend will start on http://localhost:8080

### Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

The frontend will start on http://localhost:5173

### Database (PostgreSQL)

```bash
docker-compose up -d
```

PostgreSQL will be available on port 5432 with:
- Database: `demodb`
- User: `demouser`
- Password: `demopass`

## Build Commands

### Backend

```bash
# Build from root
mvn clean install

# Build backend only
cd backend && mvn clean package
```

### Frontend

```bash
cd frontend
npm run build
```

## API Endpoints

- **Health Check**: http://localhost:8080/api/health
- **Actuator**: http://localhost:8080/actuator/health

## License

See repository license.
