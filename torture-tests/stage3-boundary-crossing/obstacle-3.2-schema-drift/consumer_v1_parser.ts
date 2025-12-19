// Obstacle 3.2: Consumer stuck on schema v1 silently drops or mis-parses v2 payloads.
// Expected: Code Scalpel flags the lost currency, shipping, and string->number drift.
type OrderV1 = {
  orderId: string
  totalCents: number
}

export function parseV1(body: unknown): OrderV1 {
  const data = body as Record<string, unknown>

  // v2 sends totalCents as a string, but the v1 consumer coerces without validation.
  const coercedTotal = Number(data.totalCents)

  return {
    orderId: String(data.orderId),
    totalCents: coercedTotal // silently becomes NaN on unexpected formats
  }
}

// Fields added in v2 (currency, lineItems, shipping) are ignored completely.
// Schema drift should be detected as potential silent data loss and type confusion.
