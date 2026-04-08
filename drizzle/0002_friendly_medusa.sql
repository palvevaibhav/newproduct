CREATE TABLE `dashboard_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`snapshotDate` timestamp NOT NULL,
	`totalMonitoredPackages` int,
	`packagesWithCritical` int,
	`packagesWithHigh` int,
	`packagesWithMedium` int,
	`packagesWithLow` int,
	`totalVulnerabilities` int,
	`averageHealthScore` int,
	`overallRiskLevel` varchar(50),
	`newVulnerabilitiesCount` int,
	`fixedVulnerabilitiesCount` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `dashboard_snapshots_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `package_metrics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`packageId` int NOT NULL,
	`packageName` varchar(255) NOT NULL,
	`packageVersion` varchar(100),
	`metricsDate` timestamp NOT NULL,
	`criticalCount` int DEFAULT 0,
	`highCount` int DEFAULT 0,
	`mediumCount` int DEFAULT 0,
	`lowCount` int DEFAULT 0,
	`totalVulnerabilities` int DEFAULT 0,
	`maxCvssScore` varchar(10),
	`healthScore` int,
	`riskLevel` varchar(50),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `package_metrics_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vulnerability_timeline` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`packageId` int,
	`cveId` varchar(50) NOT NULL,
	`packageName` varchar(255),
	`affectedVersion` varchar(100),
	`discoveredAt` timestamp NOT NULL,
	`fixedAt` timestamp,
	`fixedVersion` varchar(100),
	`cvssScore` varchar(10),
	`severity` varchar(50),
	`status` varchar(50),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vulnerability_timeline_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `dashboard_snapshots` ADD CONSTRAINT `dashboard_snapshots_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `package_metrics` ADD CONSTRAINT `package_metrics_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `package_metrics` ADD CONSTRAINT `package_metrics_packageId_monitored_packages_id_fk` FOREIGN KEY (`packageId`) REFERENCES `monitored_packages`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `vulnerability_timeline` ADD CONSTRAINT `vulnerability_timeline_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `vulnerability_timeline` ADD CONSTRAINT `vulnerability_timeline_packageId_monitored_packages_id_fk` FOREIGN KEY (`packageId`) REFERENCES `monitored_packages`(`id`) ON DELETE no action ON UPDATE no action;