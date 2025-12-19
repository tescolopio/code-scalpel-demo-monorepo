# Code Scalpel Ninja Warrior
Verify and demonstrate the revolutionary claims of Code Scalpel v2.5+ and v3.0. Audience: Engineering (QA), Security (Red Team), Marketing (Demos). Principle: "If a demo needs explanation, it’s not ready."

## Project Structure

This monorepo contains:

- **`/backend`**: Java 21 Spring Boot 3.2 application
  - Spring Boot Web
  - Spring Data JPA
  - Spring Security
  - Spring Boot Actuator
  - PostgreSQL driver

- **`/torture-tests/dynamic-labyrinth`**: Stage 2 (*Dynamic Labyrinth*) Python snippets aligned to the Code Scalpel Ninja Warrior torture tests
  
- **`/frontend`**: React 18+ with Vite and TypeScript
  - Axios for HTTP requests
  - React Router DOM for routing
  
- **`/docker-compose.yml`**: PostgreSQL 15 database service

- **`/torture-tests/stage3-boundary-crossing`**: Fixtures for the Boundary Crossing level of the Code Scalpel Ninja Warrior torture suite (cross-language contract, schema drift, protocol hopping, ORM leaks, and message queue taint)
- **`/torture-tests/stage-4-confidence-crisis`**: Code Scalpel Ninja Warrior Stage 4 torture cases focused on uncertainty quantification
  
- **`/.scalpel`**: Empty config directories
  - `policy/`: Policy configurations
  - `budget/`: Budget configurations
  
- **`/torture-tests/mount-midoriyama`**: Stage 6 sandbox & symbolic execution torture tests derived from the Code Scalpel Ninja Warrior spec
  
- **`pom.xml`**: Root multimodule Maven build

## Code Scalpel Ninja Warrior Torture Tests

The full 40-obstacle gauntlet is specified in [`Code_Scalpel_Ninja_Warrior_Torture_Tests.md`](./Code_Scalpel_Ninja_Warrior_Torture_Tests.md). All fixtures are present under `/torture-tests` and include per-obstacle expected outcomes (pass/fail behavior) so Code Scalpel can begin validation immediately.

| Stage | Focus | Obstacles | Location | Expected Outcome (high level) |
| --- | --- | --- | --- | --- |
| 1. Qualifying Round | Parser & AST fundamentals | 8 | `torture-tests/qualifying-round` | Build correct ASTs or precise errors for unicode, syntax extremes, polyglots, incomplete code, comments, encodings, macros, and version variances |
| 2. Dynamic Labyrinth | Dynamic language pathology | 7 | `torture-tests/dynamic-labyrinth` | Flag eval/exec, dynamic attrs/imports/metaclasses/patching/descriptors/factories with explicit uncertainty and taint propagation |
| 3. Boundary Crossing | Cross-language contract enforcement | 6 | `torture-tests/stage3-boundary-crossing` | Reset trust at network/serialization hops; detect schema drift, type evaporation, ORM escape hatches, and MQ taint chains |
| 4. Confidence Crisis | Uncertainty quantification | 6 | `torture-tests/stage-4-confidence-crisis` | Calibrated confidence, ambiguity acknowledgment, contradiction surfacing, and monotonic confidence decay along inference chains |
| 5. Policy Fortress | Guardrail & policy bypass resistance | 7 | `torture-tests/policy-fortress` | Block incremental erosion, encoding evasion, transitive/semantic bypasses, config tampering, social engineering, and budget gaming |
| 6. Mount Midoriyama | Sandbox & symbolic limits | 6 | `torture-tests/mount-midoriyama` | Contain sandbox escapes/resource abuse/side channels and enforce timeouts on path explosion and solver torture; resist adversarial agents |

Evidence expectations (results, confidence, performance metrics, hashes) follow the master spec’s Evaluation Framework and are mirrored in each stage README for quick reference.

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
