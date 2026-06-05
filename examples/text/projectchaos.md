# DevOps Architecture: "Project Chaos"

## 🏗️ Architecture Overview
* **Version Control:** Single shared `master` branch for all devs. No pull requests required.
* **CI/CD:** Legacy Jenkins server deployed on a single physical machine in the office closet.
* **Infrastructure:** 48 manually configured AWS EC2 instances. No Infrastructure as Code (IaC) is used.
* **Database:** One giant, unindexed MySQL database handling both OLTP and OLAP workloads.
* **Monitoring:** Nagios setup that only checks if the main web server responds with a 200 OK.

---

## ⚠️ Known Issues

### 1. Version Control & Source Code
* **Shared `master` Branch:** Developers commit directly to the production branch, causing frequent conflicts.
* **Hardcoded Credentials:** API keys, database passwords, and JWT secrets are hardcoded directly into the repository.
* **Missing `.gitignore`:** `.env` files and compiled binaries are accidentally committed to Git.

### 2. CI/CD Pipeline
* **Single Point of Failure:** Jenkins runs on a bare-metal server; if the office loses power, the CI/CD pipeline is down.
* **Manual Scripts:** The pipeline relies heavily on unversioned `bash` scripts rather than declarative pipelines.
* **No Automated Testing:** The only pipeline step is `mvn package`, with absolutely zero unit or integration tests running.
* **"Works on My Machine":** Developers lack local container parity with the production environment, causing frequent deployment failures.

### 3. Infrastructure & Provisioning
* **No Infrastructure as Code (IaC):** All EC2 instances are configured manually via SSH.
* **Special Snowflake Environments:** Development, Staging, and Production servers all have different OS versions and installed packages.
* **Unmanaged State:** No auto-scaling is configured. The system runs on fixed oversized instances, resulting in huge bills during low-traffic periods.

### 4. Database & State
* **Single Shared Database:** The primary MySQL server is shared across five different microservices, tightly coupling the applications.
* **Missing Indexes:** Table scans cripple the database during routine reporting, degrading the entire user experience.
* **No Automated Backups:** Database backups rely on a manual `mysqldump` cron job running on the DB server, which hasn't been verified in months.

### 5. Security & Compliance
* **Overprivileged IAM Roles:** The application EC2 instances use an `AdministratorAccess` IAM policy, violating the principle of least privilege.
* **No Secrets Manager:** Credentials are passed via plain text environment files during deployment.

### 6. Observability
* **Alert Fatigue:** The Nagios server sends hundreds of alerts directly to the team's primary email inbox, resulting in ignored notifications.
* **No APM (Application Performance Monitoring):** We rely entirely on user complaints on social media to detect application errors.
* **Scattered Logs:** Logs are not centralized. Developers must SSH into individual servers and `grep` through gigabytes of text.
