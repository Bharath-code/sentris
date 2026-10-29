import type { ReactNode } from 'react'

export function Panel({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <section>
      <div className="mb-4">
        <h2 className="font-semibold tracking-tight">{title}</h2>
        {hint && <p className="mt-0.5 text-sm text-muted">{hint}</p>}
      </div>
      <div className="rounded-2xl p-5 ring-1 ring-line sm:p-6">{children}</div>
    </section>
  )
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="-mx-5 overflow-x-auto sm:-mx-6">
      <table className="w-full text-left text-sm [&_td]:px-5 [&_td]:py-3 sm:[&_td]:px-6 [&_tbody_tr]:relative [&_tbody_tr]:border-t [&_tbody_tr]:border-line [&_tbody_tr:hover]:bg-sunken/60">
        <thead>
          <tr className="text-xs text-faint">
            {head.map((h, i) => <th key={i} className="px-5 pb-3 font-normal sm:px-6">{h}</th>)}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}
