-- Re-synced scans already in the table would block the unique index: keep the first of each
DELETE FROM `finding` WHERE `scan_id` IN (SELECT `id` FROM `scan` WHERE rowid NOT IN (SELECT min(rowid) FROM `scan` GROUP BY `org_id`, `cli_scan_id`));--> statement-breakpoint
DELETE FROM `scan` WHERE rowid NOT IN (SELECT min(rowid) FROM `scan` GROUP BY `org_id`, `cli_scan_id`);--> statement-breakpoint
CREATE TABLE `rate_limit` (
	`id` text PRIMARY KEY NOT NULL,
	`key` text NOT NULL,
	`count` integer NOT NULL,
	`last_request` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `rate_limit_key_unique` ON `rate_limit` (`key`);--> statement-breakpoint
CREATE TABLE `webhook_event` (
	`id` text PRIMARY KEY NOT NULL,
	`applied_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `scan_org_cli` ON `scan` (`org_id`,`cli_scan_id`);--> statement-breakpoint
-- Tokens saved before encryptOAuthTokens was enabled are plaintext; Sentris only needs GitHub for sign-in, so drop them
UPDATE `account` SET `access_token` = NULL, `refresh_token` = NULL, `id_token` = NULL;
