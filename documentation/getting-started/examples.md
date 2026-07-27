# Examples

Practical use cases for Vigil.

## Pre-commit Security Check

Scan before committing changes:

```bash
#!/bin/bash
# .git/hooks/pre-commit

vigil scan .
if [ $? -ne 0 ]; then
  echo "❌ Vulnerabilities found. Run 'vigil report' to review."
  exit 1
fi
```

## GitHub Actions CI

```.yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Install Vigil
        run: go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest

      - name: Scan dependencies
        run: vigil scan .
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Check for high-severity vulns
        run: vigil ci --fail-on high

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: .vigil.cache
```

## GitLab CI Pipeline

```yaml
security_scan:
  stage: test
  image: golang:1.24
  script:
    - go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
    - vigil scan .
    - vigil ci --fail-on critical
  artifacts:
    when: always
    paths:
      - .vigil.cache
    reports:
      junit: vigil-report.xml
```

## Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        NVD_API_KEY = credentials('nvd-api-key')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh 'go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest'
                sh 'vigil scan .'
                sh 'vigil report --format json --export security.json'
            }
        }

        stage('Gate Check') {
            steps {
                sh 'vigil ci --fail-on high'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '.vigil.cache,security.json'
        }
    }
}
```

## Weekly Security Report

Generate and email weekly security summary:

```bash
#!/bin/bash
# weekly-security-scan.sh

cd /path/to/project

vigil scan .
vigil report --format security --export /tmp/security-report.txt

# Email to team
mail -s "Weekly Security Scan - $(date +%Y-%m-%d)" \
     security@company.com < /tmp/security-report.txt
```

Add to cron:

```bash
# Every Monday at 9am
0 9 * * 1 /path/to/weekly-security-scan.sh
```

## Multi-project Scan

Scan multiple projects and aggregate results:

```bash
#!/bin/bash
# scan-all-projects.sh

PROJECTS=(
  "/path/to/frontend"
  "/path/to/backend"
  "/path/to/mobile-app"
)

for project in "${PROJECTS[@]}"; do
  echo "Scanning $project..."
  cd "$project"
  vigil scan .
  vigil report --format csv --export "$project-vulns.csv"
done

# Merge CSV files
cat */vulns.csv > all-vulnerabilities.csv
```

## Slack Notification on Critical Vulns

Post to Slack when critical vulnerabilities found:

```bash
#!/bin/bash
# scan-and-notify.sh

vigil scan .
vigil report --filter critical --format json --export critical.json

if [ -s critical.json ]; then
  COUNT=$(jq '.dependencies[].vulnerabilities | length' critical.json | awk '{s+=$1} END {print s}')

  curl -X POST "$SLACK_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{
      \"text\": \"🚨 $COUNT critical vulnerabilities found in production\",
      \"attachments\": [{
        \"color\": \"danger\",
        \"text\": \"Run \`vigil report\` for details\"
      }]
    }"
fi
```

## Compare Before/After Dependency Update

Check if update introduces new vulnerabilities:

```bash
#!/bin/bash
# compare-vulns.sh

# Scan before update
vigil scan .
cp .vigil.cache .vigil.cache.before

# Update dependencies
npm update

# Scan after update
vigil scan .
cp .vigil.cache .vigil.cache.after

# Compare
diff <(jq -S '.dependencies[].vulnerabilities[].id' .vigil.cache.before) \
     <(jq -S '.dependencies[].vulnerabilities[].id' .vigil.cache.after)
```

## Filter Production Dependencies Only

Ignore dev dependencies for production deployment checks:

```bash
vigil scan . --skip-devdeps
vigil report --format security
```

## CVSS Threshold Gate

Fail on specific CVSS score:

```bash
# Fail if any vuln has CVSS ≥ 8.0
vigil ci --fail-on-cvss 8.0
```

## Export to Jira/Linear

Generate CSV for import into issue trackers:

```bash
vigil scan .
vigil report --format csv --export vulnerabilities.csv

# CSV has columns: package, version, type, cve_id, summary, severity, risk_score
# Import into Jira/Linear as tasks
```

## Docker Build Integration

Add security scan to Dockerfile:

```dockerfile
FROM node:20 AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM golang:1.24 AS security-scan
WORKDIR /app
COPY --from=deps /app/package-lock.json ./
RUN go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
RUN vigil scan . && vigil ci --fail-on critical

FROM node:20-slim
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
CMD ["node", "server.js"]
```

## Monorepo Scanning

Scan all packages in monorepo:

```bash
#!/bin/bash
# scan-monorepo.sh

find . -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" | while read lockfile; do
  dir=$(dirname "$lockfile")
  echo "Scanning $dir..."
  (cd "$dir" && vigil scan .)
done
```

## Vulnerability Dashboard Data

Generate JSON for custom dashboards:

```bash
vigil scan .
vigil report --format json --export dashboard-data.json

# Parse with jq for metrics
echo "Total vulnerabilities: $(jq '.total_vulns' dashboard-data.json)"
echo "Critical: $(jq '.critical_vulns' dashboard-data.json)"
echo "High: $(jq '.high_vulns' dashboard-data.json)"
```

## Automated Remediation Tracking

Track remediation over time:

```bash
#!/bin/bash
# track-remediation.sh

DATE=$(date +%Y-%m-%d)
vigil scan .
vigil report --format json --export "scans/scan-$DATE.json"

# Compare with last week
LAST_WEEK=$(date -d '7 days ago' +%Y-%m-%d)
if [ -f "scans/scan-$LAST_WEEK.json" ]; then
  echo "Progress since $LAST_WEEK:"
  echo "  Before: $(jq '.total_vulns' scans/scan-$LAST_WEEK.json) vulns"
  echo "  After:  $(jq '.total_vulns' scans/scan-$DATE.json) vulns"
fi
```

## SLA Compliance Check

Ensure vulnerabilities fixed within SLA:

```bash
#!/bin/bash
# sla-check.sh

# Critical: 7 days
# High: 30 days
# Medium: 90 days

vigil scan .
vigil report --format json --export current.json

jq -r '.dependencies[].vulnerabilities[] |
  select(.severity == "critical" and
         (.published_at | fromdateiso8601) < (now - (7*86400))) |
  "SLA BREACH: \(.id) published \(.published_at)"' current.json
```

## Next Steps

- [Commands Reference](../user-guide/commands.md) - All CLI options
- [Reports](../user-guide/reports.md) - Output format details
- [Troubleshooting](../user-guide/troubleshooting.md) - Common issues
