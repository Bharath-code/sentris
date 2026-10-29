CREATE TABLE `account` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`provider_id` text NOT NULL,
	`user_id` text NOT NULL,
	`access_token` text,
	`refresh_token` text,
	`id_token` text,
	`access_token_expires_at` integer,
	`refresh_token_expires_at` integer,
	`scope` text,
	`password` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `api_key` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`name` text NOT NULL,
	`preview` text NOT NULL,
	`hash` text NOT NULL,
	`created_at` integer NOT NULL,
	`last_used_at` integer,
	`revoked_at` integer,
	FOREIGN KEY (`org_id`) REFERENCES `org`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `api_key_hash_unique` ON `api_key` (`hash`);--> statement-breakpoint
CREATE TABLE `finding` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`scan_id` text NOT NULL,
	`repo` text NOT NULL,
	`fingerprint` text NOT NULL,
	`rule_id` text NOT NULL,
	`severity` text NOT NULL,
	`file_path` text NOT NULL,
	`line` integer NOT NULL,
	`entropy` real NOT NULL,
	`preview` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`org_id`) REFERENCES `org`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`scan_id`) REFERENCES `scan`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `finding_org_fp` ON `finding` (`org_id`,`fingerprint`);--> statement-breakpoint
CREATE INDEX `finding_scan` ON `finding` (`scan_id`);--> statement-breakpoint
CREATE TABLE `org` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`owner_id` text NOT NULL,
	`zk_tag` text NOT NULL,
	`plan` text DEFAULT 'free' NOT NULL,
	`seats` integer DEFAULT 1 NOT NULL,
	`subscription_status` text,
	`dodo_customer_id` text,
	`dodo_subscription_id` text,
	`current_period_end` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`owner_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `org_owner_id_unique` ON `org` (`owner_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `org_zk_tag_unique` ON `org` (`zk_tag`);--> statement-breakpoint
CREATE UNIQUE INDEX `org_dodo_subscription_id_unique` ON `org` (`dodo_subscription_id`);--> statement-breakpoint
CREATE TABLE `scan` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`cli_scan_id` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text NOT NULL,
	`commit_hash` text,
	`files_scanned` integer NOT NULL,
	`duration_ms` integer NOT NULL,
	`findings_count` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`org_id`) REFERENCES `org`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `scan_org_created` ON `scan` (`org_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `session` (
	`id` text PRIMARY KEY NOT NULL,
	`expires_at` integer NOT NULL,
	`token` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`ip_address` text,
	`user_agent` text,
	`user_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `session_token_unique` ON `session` (`token`);--> statement-breakpoint
CREATE TABLE `user` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`email` text NOT NULL,
	`email_verified` integer DEFAULT false NOT NULL,
	`image` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_email_unique` ON `user` (`email`);--> statement-breakpoint
CREATE TABLE `verification` (
	`id` text PRIMARY KEY NOT NULL,
	`identifier` text NOT NULL,
	`value` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer,
	`updated_at` integer
);
