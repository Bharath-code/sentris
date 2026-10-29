import { createFileRoute } from '@tanstack/react-router'
import { handleMe } from '@/server/me'

export const Route = createFileRoute('/api/v1/me')({
  server: { handlers: { GET: ({ request }) => handleMe(request) } },
})
