import { createFileRoute, Link } from '@tanstack/react-router'
import { z } from 'zod'
import { Severity } from '@/components/ui'
import { getScan } from '@/lib/api'
import { Panel, Table } from '@/components/panel'

export const Route = createFileRoute('/app/scans/$id')({
  validateSearch: z.object({ offset: z.number().int().min(0).max(1_000_000).optional() }),
  loaderDeps: ({ search }) => ({ offset: search.offset ?? 0 }),
  loader: ({ params, deps }) => getScan({ data: { id: params.id, offset: deps.offset } }),
  component: ScanDetail,
  errorComponent: () => (
    <main className="container-page py-16 text-center text-muted">
      Scan not found. <Link to="/app" className="underline underline-offset-4">Back to dashboard</Link>
    </main>
  ),
})

function ScanDetail() {
  const { scan, findings, offset, total, pageSize } = Route.useLoaderData()
  const { id } = Route.useParams()
  const end = offset + findings.length
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
      <Panel title={`${total.toLocaleString()} finding${total === 1 ? '' : 's'}`} hint="No key characters are ever uploaded. Run sentris scan locally to see the match.">
        {findings.length === 0 ? (
          <p className="text-sm text-ok">Clean scan. Nothing leaked.</p>
        ) : (
          <Table head={['Severity', 'Rule', 'Location']}>
            {findings.map((f) => (
              <tr key={f.id}>
                <td><Severity level={f.severity} /></td>
                <td>{f.ruleId}</td>
                <td className="font-mono text-xs text-muted">{f.filePath}:{f.line}</td>
              </tr>
            ))}
          </Table>
        )}
        {total > pageSize && (
          <nav className="mt-4 flex items-center justify-between text-sm text-muted" aria-label="Findings pages">
            <span className="tabular-nums">
              {(offset + 1).toLocaleString()}–{end.toLocaleString()} of {total.toLocaleString()}
              {end < total && ` · ${(total - end).toLocaleString()} more`}
            </span>
            <span className="flex gap-4">
              {offset > 0 && <Link to="/app/scans/$id" params={{ id }} search={{ offset: Math.max(0, offset - pageSize) || undefined }} className="hover:text-fg">← Previous</Link>}
              {end < total && <Link to="/app/scans/$id" params={{ id }} search={{ offset: offset + pageSize }} className="hover:text-fg">Next →</Link>}
            </span>
          </nav>
        )}
      </Panel>
      <p className="text-sm text-muted">
        Fix locally with <code className="font-mono text-fg">sentris fix --all</code>, then run <code className="font-mono text-fg">sentris sync .</code> again.
      </p>
    </main>
  )
}
