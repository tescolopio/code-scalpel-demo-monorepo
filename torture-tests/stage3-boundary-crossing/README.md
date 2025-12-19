# Stage 3: The Boundary Crossing

This folder contains executable-style fixtures for the **Boundary Crossing** level of the Code Scalpel Ninja Warrior torture tests. Each obstacle is represented by minimal, self-contained code that forces Code Scalpel to reason across language, protocol, and trust boundaries. The files are intentionally small to keep analysis focused on the boundary failures described in the master specification.

## Obstacles and fixtures

- **3.1 Type System Evaporation**  
  - `obstacle-3.1-type-system-evaporation/frontend-role-form.ts` (strictly typed TypeScript request that is trivial to subvert)  
  - `obstacle-3.1-type-system-evaporation/backend_receiver.py` (Python backend that trusts the evaporated runtime types)
- **3.2 Schema Drift Detector**  
  - `obstacle-3.2-schema-drift/producer_v2_payload.json` (producer emits v2 payload)  
  - `obstacle-3.2-schema-drift/consumer_v1_parser.ts` (consumer locked to v1 schema with silent drops)
- **3.3 Trust Boundary Blindness**  
  - `obstacle-3.3-trust-boundary-blindness/TrustBoundaryBlindnessExample.java` (internal headers, env vars, and DB content implicitly trusted)
- **3.4 REST/GraphQL/gRPC Maze**  
  - `obstacle-3.4-rest-graphql-grpc-maze/schema.graphql` (entry GraphQL contract)  
  - `obstacle-3.4-rest-graphql-grpc-maze/gateway.ts` (GraphQL → REST → gRPC taint chain)  
  - `obstacle-3.4-rest-graphql-grpc-maze/inventory.proto` (downstream gRPC contract)
- **3.5 ORM Abstraction Leak**  
  - `obstacle-3.5-orm-abstraction-leak/OrderRepository.java` (Spring Data escape hatch using a concatenated native query)  
  - `obstacle-3.5-orm-abstraction-leak/sqlalchemy_repo.py` (SQLAlchemy text() with unchecked column)
- **3.6 Message Queue Mystery**  
  - `obstacle-3.6-message-queue-mystery/publisher.ts` (publishes tainted user input to Kafka topic)  
  - `obstacle-3.6-message-queue-mystery/worker.py` (delayed consumer that formats SQL directly from the message)

## How to use

1. Point Code Scalpel at the files in each obstacle folder.  
2. Verify it:
   - Resets confidence at every network/serialization boundary.  
   - Detects schema/version mismatches and silent data loss.  
   - Treats all cross-service inputs as untrusted until validated.  
   - Keeps taint flowing across REST → gRPC → DB → MQ hops.  
   - Flags ORM escape hatches and message queue sinks as critical.
3. A pass requires Code Scalpel to call out the boundary loss, not just the local code smell.

These fixtures mirror the expectations in **Code_Scalpel_Ninja_Warrior_Torture_Tests.md** and are intended for static analysis—not for runtime execution in this demo monorepo.
