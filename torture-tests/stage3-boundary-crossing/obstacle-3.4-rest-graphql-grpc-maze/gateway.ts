// Obstacle 3.4: Data flows GraphQL -> REST -> gRPC with no taint preservation.
// Intentional XSS/taint exposure to ensure Code Scalpel tracks data across protocol hops.
import express from 'express'
import { buildSchema } from 'graphql'
import { graphqlHTTP } from 'express-graphql'
import fetch from 'node-fetch'
import { InventoryClient } from './inventory_grpc_stub' // placeholder for generated client

const app = express()
const schema = buildSchema(`
  type Query { product(id: ID!, note: String): Product }
  type Product { id: ID!, name: String!, price: Int!, note: String }
`)

const root = {
  product: async ({ id, note }: { id: string; note?: string }) => {
    // 1) Send untrusted note into REST microservice.
    await fetch(`http://rest-microservice.local/products/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userNote: note })
    })

    // 2) Forward the same note into gRPC without sanitization.
    const client = new InventoryClient('inventory:50051', null)
    const grpcResponse = await client.getProduct({ id, user_note: note })

    return {
      id: grpcResponse.id,
      name: grpcResponse.name,
      price: grpcResponse.price_cents,
      note // returned directly to caller, enabling stored/reflected XSS vectors
    }
  }
}

app.use(
  '/graphql',
  graphqlHTTP({
    schema,
    rootValue: root,
    graphiql: true
  })
)

app.listen(4000, () => {
  console.log('GraphQL torture-test gateway running on port 4000 (INTENTIONALLY INSECURE - DO NOT USE IN PRODUCTION)')
})
