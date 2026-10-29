# Rotation capability matrix (task R0)

Researched 2026-10-29 from official docs. "Confirmed" = read on the cited page. "Not documented" = the page I read does not describe it; that is **not** proof the capability is absent. "Unverified" = only seen through a search summary or a secondary source.

## Decision

**First rotator: AWS IAM access keys.** It is the only provider where all four needed operations are documented and callable: create, reversible deactivate, delete, and a hard cap of 2 keys that makes old+new overlap native. Anthropic is the strongest second candidate (reversible `inactive` status exists, create is the open question). GitHub, Stripe and Slack are dashboard-only for creation as far as the docs show, so they get "guided revoke + poll `verify_live`" rather than rotation.

## Matrix

| Provider | Create via API | Reversible deactivate | Delete / revoke | Max concurrent keys | Verdict |
|---|---|---|---|---|---|
| **AWS IAM access key** | Confirmed: `create-access-key`; secret "can be retrieved only at the time you create it" ([1]) | Confirmed: `update-access-key --status Inactive`, "can be reactivated" ([2]) | Confirmed: `delete-access-key` (R2 relies on the standard IAM API; delete page not separately fetched) | Confirmed: "a maximum of two access keys per user" ([1]) | **Rotatable. First provider.** |
| **GitHub PAT (classic / fine-grained)** | Not documented. PAT docs describe only the UI ("Generate new token") ([3]); no create endpoint on the orgs PAT API either ([5]) | Not documented | UI delete for own tokens ([3]). `POST /credentials/revoke` revokes credentials "the caller does not own", unauthenticated, permanent, owners notified, 1000/request, 60 unauth requests/hour ([4]). Org-level revoke endpoints exist but "Only GitHub Apps can use this endpoint" ([5]) | Not applicable | **Not rotatable.** Guided revoke only. Using `/credentials/revoke` on your own token is a product/policy call (it is permanent and has no grace window) |
| **Stripe secret / restricted key** | Dashboard only on the keys page ([6]); no key-management API is described there | Dashboard "Expire key" (permanent for that key) ([6]) | Dashboard expire/rotate ([6]) | Not stated | **Not rotatable via API as documented.** Useful fact: Dashboard rotation has a grace period "up to 7 days" where old and new both work ([6]), so a guided flow can tell the user to use it |
| **Anthropic API key (Admin API)** | Not found: only `GET /v1/organizations/api_keys` (list) and `POST /v1/organizations/api_keys/{id}` (update) were visible ([7], [8]) | **Confirmed: update `status` to `inactive`/`active`/`archived`** ([7]) | Not found as a separate delete; `archived` may serve ([7]) | Not stated | **Partial: deactivate/reactivate works with an Admin key; creating the replacement is the gap.** Re-check Admin API index before R-phase 2 |
| **OpenAI project API key** | Unverified: a search summary of the official reference lists only list/retrieve/delete for project keys and create for *admin* keys (`POST /organization/admin_api_keys`) ([9]); direct page fetches returned 403/404 | Not found | Delete (unverified, [9]) | Not stated | **Unverified. Do not plan around it until the reference is read directly.** |
| **Slack** | Tokens: rotation via `oauth.v2.exchange` then `oauth.v2.access` with `grant_type=refresh_token`, access token expires every 12 hours, refresh tokens single-use, "may not be turned off once it's turned on" ([10]). **Incoming webhook URLs: not documented** as rotatable; sources found describe delete-and-recreate in the Slack UI only (secondary, unverified against official docs) | Not applicable | Tokens: `auth.revoke` (secondary source); webhooks: UI delete | Token pair: oldest extra revoked if >2 ([10]) | Slack **webhook** leaks (what `slack-webhook-url` rule detects) are not API-rotatable as far as found. Guided revoke only |

## Facts R-phase tasks depend on

| Fact | Status | Used by |
|---|---|---|
| `aws iam get-access-key-last-used --access-key-id` returns `UserName` and `AccessKeyLastUsed{LastUsedDate, ServiceName, Region}`; `LastUsedDate` is null and service/region "N/A" if never used or tracking has no data ([11]) | Confirmed. The page documents no freshness guarantee, so `finish` must say "last-used data may lag" | R2 `resolve_principal`, R3 `finish` |
| `update-access-key` accepts `Active`, `Inactive`, `Expired`; Inactive is reversible ([2]) | Confirmed | R2, R3 `undo` |
| CloudTrail `LookupEvents`: lookup attribute `AccessKeyId` is valid ([12]); management events (and Insights) only; "within the last 90 days"; per Region ([13]) | Confirmed | F2 |
| `LookupAttributes` "can contain only one item" per call; max 50 results/page with `NextToken`; "two per second, per account, per Region" with throttling errors ([13]) | Confirmed | F2 must page, back off on throttling, and cannot combine key id with time filters beyond `StartTime`/`EndTime` |
| Response includes `Events[].Username`, `EventName`, `EventSource`, `EventTime`, `CloudTrailEvent` (JSON string holding source IP and user agent) ([13]) | Confirmed fields; source IP / user agent live inside the `CloudTrailEvent` string, not as top-level fields. The inner schema was not fetched | F2: parse the inner JSON; add a fixture-based test |
| AWS: IAM users with access keys are discouraged in favour of temporary credentials ([1]) | Confirmed | README wording: rotation helps users who still have keys, it is not a recommendation to keep them |

## Impact on the plan

- **R0 AC "GitHub PAT cell states definitively whether programmatic create exists":** answer is *no create endpoint is documented* in the PAT docs or the orgs PAT API. I cannot prove a negative from docs alone; treat GitHub as non-rotatable.
- **R2/R3 unchanged:** AWS-first design holds.
- **F2 gets one added requirement:** the source IP is inside `CloudTrailEvent` JSON; paging and 2 req/s throttling must be handled.
- **New scope question for you:** for GitHub, do you want a `sentris revoke` guided flow (open the token settings URL, poll `verify_live` until `Revoked`), or also allow the unauthenticated `POST /credentials/revoke` for tokens you own? It is instant and permanent (no grace), and the page says it is intended for credentials the caller does not own.
- **Add a follow-up task (R6, optional):** Anthropic deactivate/reactivate via Admin API as a "guided revoke with undo" before true rotation exists. Not scheduled.

## Sources

1. https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
2. https://docs.aws.amazon.com/cli/latest/reference/iam/update-access-key.html
3. https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
4. https://docs.github.com/en/rest/credentials/revoke
5. https://docs.github.com/en/rest/orgs/personal-access-tokens
6. https://docs.stripe.com/keys
7. https://platform.claude.com/docs/en/api/admin-api/apikeys/update-api-key (resolves to `.../api/beta/organization/api_keys/update`)
8. https://platform.claude.com/docs/en/api/beta/organization/api_keys/list
9. https://developers.openai.com/api/reference/resources/organization/subresources/admin_api_keys/index.md (found via search; direct fetch of the project-keys reference failed, so treat as unverified)
10. https://docs.slack.dev/authentication/using-token-rotation
11. https://docs.aws.amazon.com/cli/latest/reference/iam/get-access-key-last-used.html
12. https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html
13. https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
