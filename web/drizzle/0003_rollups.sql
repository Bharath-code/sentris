CREATE TABLE `scan_severity` (
	`scan_id` text NOT NULL,
	`org_id` text NOT NULL,
	`severity` text NOT NULL,
	`n` integer NOT NULL,
	`created_at` integer NOT NULL,
	PRIMARY KEY(`scan_id`, `severity`),
	FOREIGN KEY (`scan_id`) REFERENCES `scan`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`org_id`) REFERENCES `org`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `scan_severity_org_created` ON `scan_severity` (`org_id`,`created_at`);--> statement-breakpoint
DROP INDEX `finding_org_fp`;--> statement-breakpoint
CREATE INDEX `finding_org_fp_repo` ON `finding` (`org_id`,`fingerprint`,`repo`);--> statement-breakpoint
CREATE INDEX `api_key_org` ON `api_key` (`org_id`);--> statement-breakpoint
-- Backfill the rollup for scans stored before it existed
INSERT INTO `scan_severity` (`scan_id`, `org_id`, `severity`, `n`, `created_at`)
SELECT f.`scan_id`, f.`org_id`, lower(f.`severity`), count(*), s.`created_at`
FROM `finding` f JOIN `scan` s ON s.`id` = f.`scan_id`
GROUP BY f.`scan_id`, lower(f.`severity`);
