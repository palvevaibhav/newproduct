# Decision RAG Security Intelligence - Project TODO

## Core Architecture
- [x] Query classifier and intent detector
- [x] Multi-source data fetcher integration (NVD, OSV, GHSA, Red Hat, NPM)
- [x] RAG pipeline with LLM synthesis
- [x] Result caching system in database
- [x] CVE detail parser and extractor
- [x] Package vulnerability scanner

## Database Schema
- [x] Queries table (history and caching)
- [x] Vulnerability cache table
- [x] Query results table with metadata
- [x] Monitored packages table (for notifications)
- [x] Notification history table

## Backend Implementation
- [x] Query router procedure (classify input type)
- [x] Data fetcher procedures for each source
- [x] RAG synthesis procedure with LLM integration
- [x] Cache lookup and storage procedures
- [x] Package scanner procedure
- [x] Critical CVE detection and notification trigger

## Frontend Implementation
- [x] Blueprint-themed layout with grid pattern and CAD aesthetic
- [x] Search input component with query examples
- [x] Loading states and progress indicators
- [x] Vulnerability report display component
- [x] CVSS score visualization
- [x] Affected versions and fix recommendations
- [x] Query history sidebar
- [x] Error handling and user feedback

## API Integration
- [x] NVD API integration
- [x] OSV API integration
- [x] GHSA (GitHub Advisory) integration
- [x] Red Hat security data integration
- [x] NPM advisory search integration
- [x] LLM synthesis integration

## Notifications & Monitoring
- [x] Critical CVE notification system (CVSS > 8.0)
- [x] Owner notification on new high-severity vulnerabilities
- [x] Query analytics and tracking

## Testing & Deployment
- [x] Unit tests for query classifier
- [x] Integration tests for data fetchers
- [x] End-to-end tests for RAG pipeline
- [x] Frontend component tests
- [x] Performance optimization and caching validation
- [x] Final checkpoint and deployment readiness


## Dashboard Implementation (New)
- [ ] Dashboard schema tables for metrics and trends
- [ ] Package security timeline aggregation
- [ ] Vulnerability trend analysis over time
- [ ] Risk heatmap data generation
- [ ] Dashboard UI with Recharts visualizations
- [ ] Real-time metrics and KPI cards
- [ ] Package health scoring algorithm
- [ ] Historical trend comparison
- [ ] Dashboard data aggregation procedures
- [ ] End-to-end dashboard testing
