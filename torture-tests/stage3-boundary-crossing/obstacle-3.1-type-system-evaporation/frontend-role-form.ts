// Obstacle 3.1: Type system evaporates once data leaves the TypeScript runtime.
type Role = 'admin' | 'user'

interface RoleChangeRequest {
  userId: string
  role: Role
  note?: string
}

// Type narrowing looks airtight, but userRole comes from the DOM and is attacker-controlled.
const userRole = (document.getElementById('role-input') as HTMLInputElement).value as Role

const payload: RoleChangeRequest = {
  userId: 'abc-123',
  // Trusting the compile-time Role union even though it is erased at JSON.stringify time.
  role: userRole,
  note: 'frontend already validated role'
}

// Nothing in this fetch enforces the enum. Code Scalpel should reset confidence at this boundary.
fetch('http://localhost:8080/api/boundary/role', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload)
})
