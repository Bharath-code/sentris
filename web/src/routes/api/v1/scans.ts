import { createFileRoute } from '@tanstack/react-router'
import { handleScanUpload } from '@/server/ingest'

export const Route = createFileRoute('/api/v1/scans')({
  server: { handlers: { POST: ({ request }) => handleScanUpload(request) } },
})
