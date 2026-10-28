import { createFileRoute, Link } from '@tanstack/react-router'
import { Severity } from '@/components/ui'
import { getScan } from '@/lib/api'
import { Panel, Table } from '@/components/panel'

export const Route = createFileRoute('/app/scans/$id')({
  loader: ({ params }) => getScan({ data: { id: params.id } }),
  component: ScanDetail,
  errorComponent: () => (
    <main className="container-page py-16 text-center text-muted">
      Scan not found. <Link to="/app" className="underline underline-offset-4">Back to dashboard</Link>
    </main>
  ),
})

function ScanDetail() {
  const { scan, findings } = Route.useLoaderData()
  return (
    <main className="container-page space-y-8 py-10">
      <div>
        <Link to="/app" className="text-sm text-muted hover:text-fg">← Dashboard</Link>
        <h1 className="mt-4 text-2xl font-semibold tracking-tight">{scan.repo}</h1>
        <p className="mt-1 font-mono text-xs text-muted">
          {scan.branch}{scan.commitHash && ` @ ${scan.commitHash.slice(0, 8)}`} · {scan.filesScanned.toLocaleString()} files · {scan.durationMs} ms ·{' '}
          {new Date(scan.createdAt).toLocaleString()}
        </p>
      </div>
      <Panel title={`${findings.length} finding${findings.length === 1 ? '' : 's'}`} hint="Previews are redacted on the developer's machine before upload.">
        {findings.length === 0 ? (
          <p className="text-sm text-ok">Clean scan. Nothing leaked.</p>
        ) : (
          <Table head={['Severity', 'Rule', 'Location', 'Preview']}>
            {findings.map((f) => (
              <tr key={f.id}>
                <td><Severity level={f.severity} /></td>
                <td>{f.ruleId}</td>
                <td className="font-mono text-xs text-muted">{f.filePath}:{f.line}</td>
                <td className="font-mono text-xs text-faint">{f.preview}</td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
      <p className="text-sm text-muted">
        Fix locally with <code className="font-mono text-fg">sentris fix --all</code>, then run <code className="font-mono text-fg">sentris sync .</code> again.
      </p>
    </main>
  )
}
