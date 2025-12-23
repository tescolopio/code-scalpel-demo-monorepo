// Safe control: TypeScript types + runtime enforcement on the backend.
// The TS type is *not* trusted at runtime; the backend validates.

type Role = 'admin' | 'user'

export async function submitRoleSafe(role: Role): Promise<void> {
  // Still a plain string at runtime when serialized.
  await fetch('/api/role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  })
}
