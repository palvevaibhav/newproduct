CREATE TABLE `monitored_packages` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`packageName` varchar(255) NOT NULL,
	`packageVersion` varchar(100),
	`ecosystem` varchar(50),
	`lastChecked` timestamp,
	`knownVulnerabilities` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `monitored_packages_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `notification_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`queryId` int,
	`notificationType` varchar(50) NOT NULL,
	`title` varchar(255) NOT NULL,
	`content` text,
	`cvssScore` varchar(10),
	`relatedCveId` varchar(50),
	`sentAt` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `notification_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `security_queries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`queryText` text NOT NULL,
	`queryType` varchar(50) NOT NULL,
	`detectedIntents` text,
	`extractedEntities` text,
	`resultSummary` text,
	`fullResult` text,
	`isCritical` boolean DEFAULT false,
	`maxCvssScore` varchar(10),
	`queriedAt` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `security_queries_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vulnerability_cache` (
	`id` int AUTO_INCREMENT NOT NULL,
	`identifier` varchar(255) NOT NULL,
	`identifierType` varchar(50) NOT NULL,
	`sourceData` text,
	`nvdData` text,
	`osvData` text,
	`ghsaData` text,
	`npmData` text,
	`redhatData` text,
	`cvssScore` varchar(10),
	`severity` varchar(50),
	`affectedVersions` text,
	`fixedVersions` text,
	`references` text,
	`lastFetched` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `vulnerability_cache_id` PRIMARY KEY(`id`),
	CONSTRAINT `vulnerability_cache_identifier_unique` UNIQUE(`identifier`)
);
--> statement-breakpoint
ALTER TABLE `monitored_packages` ADD CONSTRAINT `monitored_packages_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `notification_history` ADD CONSTRAINT `notification_history_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `notification_history` ADD CONSTRAINT `notification_history_queryId_security_queries_id_fk` FOREIGN KEY (`queryId`) REFERENCES `security_queries`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `security_queries` ADD CONSTRAINT `security_queries_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;