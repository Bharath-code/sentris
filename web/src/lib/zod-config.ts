import { z } from 'zod'

// Zod probes `Function('')` to decide on JIT; under our CSP the probe is reported as a violation even though it is caught.
// Imported first in router.tsx so it runs before any schema is built.
z.config({ jitless: true })
