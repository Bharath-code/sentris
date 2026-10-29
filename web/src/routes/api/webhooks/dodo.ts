import { createFileRoute } from '@tanstack/react-router'
import { handleDodoWebhook } from '@/server/billing'

export const Route = createFileRoute('/api/webhooks/dodo')({
  server: { handlers: { POST: ({ request }) => handleDodoWebhook(request) } },
})
