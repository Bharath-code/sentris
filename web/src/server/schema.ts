import { sqliteTable, text, integer, real, index, uniqueIndex } from 'drizzle-orm/sqlite-core'

const ts = (name: string) => integer(name, { mode: 'timestamp_ms' })
const now = () => new Date()

// Better Auth core tables (field names must match its defaults)
export const user = sqliteTable('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
  image: text('image'),
  createdAt: ts('created_at').notNull().$defaultFn(now),
  updatedAt: ts('updated_at').notNull().$defaultFn(now),
})

export const session = sqliteTable('session', {
  id: text('id').primaryKey(),
  expiresAt: ts('expires_at').notNull(),
  token: text('token').notNull().unique(),
  createdAt: ts('created_at').notNull().$defaultFn(now),
  updatedAt: ts('updated_at').notNull().$defaultFn(now),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId: text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
})

export const account = sqliteTable('account', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: ts('access_token_expires_at'),
  refreshTokenExpiresAt: ts('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
  createdAt: ts('created_at').notNull().$defaultFn(now),
  updatedAt: ts('updated_at').notNull().$defaultFn(now),
})

// Better Auth's database-backed rate limiter (in-memory counters are per-isolate, so useless on Workers)
export const rateLimit = sqliteTable('rate_limit', {
  id: text('id').primaryKey(),
  key: text('key').notNull().unique(),
  count: integer('count').notNull(),
  lastRequest: integer('last_request').notNull(),
})

// Webhook ids already applied; replays are acknowledged without touching the org
export const webhookEvent = sqliteTable('webhook_event', {
  id: text('id').primaryKey(),
  appliedAt: ts('applied_at').notNull().$defaultFn(now),
})

export const verification = sqliteTable('verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: ts('expires_at').notNull(),
  createdAt: ts('created_at').$defaultFn(now),
  updatedAt: ts('updated_at').$defaultFn(now),
})

// ponytail: one org per owner; member/invite tables when teams need more than the owner's keys
export const org = sqliteTable('org', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  ownerId: text('owner_id').notNull().unique().references(() => user.id, { onDelete: 'cascade' }),
  // 8 hex chars shared by every key in the org; the CLI displays it as the org id
  zkTag: text('zk_tag').notNull().unique(),
  plan: text('plan', { enum: ['free', 'pro'] }).notNull().default('free'),
  seats: integer('seats').notNull().default(1),
  subscriptionStatus: text('subscription_status'),
  dodoCustomerId: text('dodo_customer_id'),
  dodoSubscriptionId: text('dodo_subscription_id').unique(),
  currentPeriodEnd: ts('current_period_end'),
  // Timestamp of the last applied billing webhook; older events are dropped
  billingEventAt: ts('billing_event_at'),
  createdAt: ts('created_at').notNull().$defaultFn(now),
})

export const apiKey = sqliteTable('api_key', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  preview: text('preview').notNull(),
  hash: text('hash').notNull().unique(),
  createdAt: ts('created_at').notNull().$defaultFn(now),
  lastUsedAt: ts('last_used_at'),
  revokedAt: ts('revoked_at'),
})

export const scan = sqliteTable(
  'scan',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
    cliScanId: text('cli_scan_id').notNull(),
    repo: text('repo').notNull(),
    branch: text('branch').notNull(),
    commitHash: text('commit_hash'),
    filesScanned: integer('files_scanned').notNull(),
    durationMs: integer('duration_ms').notNull(),
    findingsCount: integer('findings_count').notNull(),
    createdAt: ts('created_at').notNull().$defaultFn(now),
  },
  (t) => [index('scan_org_created').on(t.orgId, t.createdAt), uniqueIndex('scan_org_cli').on(t.orgId, t.cliScanId)],
)

export const finding = sqliteTable(
  'finding',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
    scanId: text('scan_id').notNull().references(() => scan.id, { onDelete: 'cascade' }),
    repo: text('repo').notNull(),
    fingerprint: text('fingerprint').notNull(),
    ruleId: text('rule_id').notNull(),
    severity: text('severity').notNull(),
    filePath: text('file_path').notNull(),
    line: integer('line').notNull(),
    entropy: real('entropy').notNull(),
    preview: text('preview').notNull(),
    createdAt: ts('created_at').notNull().$defaultFn(now),
  },
  (t) => [index('finding_org_fp').on(t.orgId, t.fingerprint), index('finding_scan').on(t.scanId)],
)
