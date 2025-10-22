/**
 * ESLint Security Test Runner
 * This script runs comprehensive security tests on the backend codebase
 * and generates a detailed security report
 */

import { ESLint } from "eslint";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import custom security rules
import securityRules from "./eslint-custom-rules/security-rules.js";

// Security categories
const SECURITY_CATEGORIES = {
  "detect-missing-authentication": {
    category: "Missing Authentication on Critical Routes",
    severity: "CRITICAL",
    description:
      "Routes that perform sensitive operations without authentication middleware",
  },
  "detect-sensitive-data-exposure": {
    category: "Sensitive Data Exposure",
    severity: "HIGH",
    description:
      "Credentials, passwords, or sensitive data being logged or exposed",
  },
  "detect-nosql-injection": {
    category: "Injection Risks (NoSQL Injection)",
    severity: "CRITICAL",
    description:
      "User input used directly in database queries without validation",
  },
  "detect-insecure-otp": {
    category: "Insecure OTP Implementation",
    severity: "HIGH",
    description: "Weak OTP generation, storage, or validation mechanisms",
  },
  "detect-xss-vulnerabilities": {
    category: "Cross-Site Scripting (XSS)",
    severity: "HIGH",
    description: "User input reflected without sanitization",
  },
  "detect-insecure-file-upload": {
    category: "Insecure File Upload",
    severity: "CRITICAL",
    description: "File uploads without proper validation or security measures",
  },
  "detect-missing-security-headers": {
    category: "Missing Security Headers",
    severity: "MEDIUM",
    description: "Application missing critical security headers",
  },
  "detect-missing-csrf": {
    category: "Missing CSRF Protection",
    severity: "HIGH",
    description: "Cookie-based authentication without CSRF protection",
  },
};

async function runSecurityTests() {
  console.log("╔═══════════════════════════════════════════════════════════╗");
  console.log("║       FashioNexus Security Vulnerability Scanner         ║");
  console.log(
    "╚═══════════════════════════════════════════════════════════╝\n"
  );

  // Create ESLint instance with custom rules
  const eslint = new ESLint({
    useEslintrc: false,
    overrideConfig: {
      env: {
        node: true,
        es2021: true,
      },
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
      plugins: ["local-security"],
      rules: {
        "local-security/detect-missing-authentication": "error",
        "local-security/detect-sensitive-data-exposure": "error",
        "local-security/detect-nosql-injection": "error",
        "local-security/detect-insecure-otp": "error",
        "local-security/detect-xss-vulnerabilities": "error",
        "local-security/detect-insecure-file-upload": "error",
        "local-security/detect-missing-security-headers": "error",
        "local-security/detect-missing-csrf": "error",
      },
    },
    plugins: {
      "local-security": securityRules,
    },
  });

  // Files to scan
  const filesToScan = [
    "api/index.js",
    "api/routes/**/*.js",
    "api/controllers/**/*.js",
    "api/middleware/**/*.js",
    "api/utils/**/*.js",
  ];

  console.log("📂 Scanning files:");
  filesToScan.forEach((file) => console.log(`   - ${file}`));
  console.log("\n🔍 Running security analysis...\n");

  try {
    // Lint files
    const results = await eslint.lintFiles(filesToScan);

    // Process results
    const securityIssues = processResults(results);

    // Generate report
    generateConsoleReport(securityIssues);
    generateHtmlReport(securityIssues);
    generateJsonReport(securityIssues);

    console.log("\n✅ Security scan completed!");
    console.log("📄 Reports generated:");
    console.log("   - SECURITY_REPORT.md");
    console.log("   - security-report.html");
    console.log("   - security-report.json\n");

    // Return exit code based on critical issues
    const criticalCount = securityIssues.filter(
      (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "CRITICAL"
    ).length;

    if (criticalCount > 0) {
      console.log(`⚠️  Found ${criticalCount} CRITICAL security issues!`);
      process.exit(1);
    }
  } catch (error) {
    console.error("❌ Error during security scan:", error);
    process.exit(1);
  }
}

function processResults(results) {
  const issues = [];

  results.forEach((result) => {
    if (result.messages && result.messages.length > 0) {
      result.messages.forEach((message) => {
        if (message.ruleId && message.ruleId.startsWith("detect-")) {
          issues.push({
            file:
              result.filePath.replace(/\\/g, "/").split("/api/")[1] ||
              result.filePath,
            line: message.line,
            column: message.column,
            ruleId: message.ruleId,
            message: message.message,
            severity: message.severity === 2 ? "error" : "warning",
          });
        }
      });
    }
  });

  return issues;
}

function generateConsoleReport(issues) {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("                    SECURITY ISSUES FOUND                  ");
  console.log("═══════════════════════════════════════════════════════════\n");

  // Group by category
  const grouped = {};
  issues.forEach((issue) => {
    const category = SECURITY_CATEGORIES[issue.ruleId]?.category || "Other";
    if (!grouped[category]) {
      grouped[category] = [];
    }
    grouped[category].push(issue);
  });

  // Display by category
  Object.keys(grouped)
    .sort()
    .forEach((category) => {
      const categoryIssues = grouped[category];
      const ruleId = categoryIssues[0].ruleId;
      const info = SECURITY_CATEGORIES[ruleId];

      console.log(`\n${"=".repeat(60)}`);
      console.log(`📋 ${category}`);
      console.log(`   Severity: ${info?.severity || "UNKNOWN"}`);
      console.log(`   Description: ${info?.description || "N/A"}`);
      console.log(`   Count: ${categoryIssues.length} issue(s)`);
      console.log(`${"=".repeat(60)}\n`);

      categoryIssues.forEach((issue, index) => {
        console.log(
          `   ${index + 1}. ${issue.file}:${issue.line}:${issue.column}`
        );
        console.log(`      ⚠️  ${issue.message}\n`);
      });
    });

  // Summary
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("                         SUMMARY                           ");
  console.log("═══════════════════════════════════════════════════════════\n");

  const criticalCount = issues.filter(
    (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "CRITICAL"
  ).length;
  const highCount = issues.filter(
    (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "HIGH"
  ).length;
  const mediumCount = issues.filter(
    (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "MEDIUM"
  ).length;

  console.log(`   🔴 CRITICAL: ${criticalCount}`);
  console.log(`   🟠 HIGH:     ${highCount}`);
  console.log(`   🟡 MEDIUM:   ${mediumCount}`);
  console.log(`   ────────────────────`);
  console.log(`   📊 TOTAL:    ${issues.length}\n`);
}

function generateHtmlReport(issues) {
  const grouped = {};
  issues.forEach((issue) => {
    const category = SECURITY_CATEGORIES[issue.ruleId]?.category || "Other";
    if (!grouped[category]) {
      grouped[category] = [];
    }
    grouped[category].push(issue);
  });

  let html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FashioNexus Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .content {
            padding: 30px;
        }
        .category {
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        .category-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 2px solid #e0e0e0;
        }
        .category-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        .category-header .meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-critical {
            background: #dc3545;
            color: white;
        }
        .badge-high {
            background: #fd7e14;
            color: white;
        }
        .badge-medium {
            background: #ffc107;
            color: #333;
        }
        .issue {
            padding: 20px;
            border-bottom: 1px solid #f0f0f0;
        }
        .issue:last-child {
            border-bottom: none;
        }
        .issue-location {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 8px 12px;
            border-radius: 4px;
            display: inline-block;
            margin-bottom: 10px;
            font-size: 0.9em;
            color: #495057;
        }
        .issue-message {
            color: #666;
            margin-top: 8px;
            padding-left: 15px;
            border-left: 3px solid #667eea;
        }
        .timestamp {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Vulnerability Report</h1>
            <p>FashioNexus Backend Security Analysis</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3 class="critical">${
                  issues.filter(
                    (i) =>
                      SECURITY_CATEGORIES[i.ruleId]?.severity === "CRITICAL"
                  ).length
                }</h3>
                <p>Critical Issues</p>
            </div>
            <div class="summary-card">
                <h3 class="high">${
                  issues.filter(
                    (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "HIGH"
                  ).length
                }</h3>
                <p>High Issues</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">${
                  issues.filter(
                    (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "MEDIUM"
                  ).length
                }</h3>
                <p>Medium Issues</p>
            </div>
            <div class="summary-card">
                <h3>${issues.length}</h3>
                <p>Total Issues</p>
            </div>
        </div>
        
        <div class="content">
  `;

  Object.keys(grouped)
    .sort()
    .forEach((category) => {
      const categoryIssues = grouped[category];
      const ruleId = categoryIssues[0].ruleId;
      const info = SECURITY_CATEGORIES[ruleId];
      const severityClass = (info?.severity || "MEDIUM").toLowerCase();

      html += `
            <div class="category">
                <div class="category-header">
                    <h2>${category}</h2>
                    <div class="meta">
                        <span class="badge badge-${severityClass}">${
        info?.severity || "UNKNOWN"
      }</span>
                        <span style="color: #666;">${
                          categoryIssues.length
                        } issue(s) found</span>
                    </div>
                    <p style="margin-top: 10px; color: #666;">${
                      info?.description || "N/A"
                    }</p>
                </div>
    `;

      categoryIssues.forEach((issue, index) => {
        html += `
                <div class="issue">
                    <div><strong>Issue #${index + 1}</strong></div>
                    <div class="issue-location">📁 ${issue.file}:${
          issue.line
        }:${issue.column}</div>
                    <div class="issue-message">⚠️ ${issue.message}</div>
                </div>
      `;
      });

      html += `
            </div>
    `;
    });

  html += `
        </div>
        <div class="timestamp">
            Report generated on ${new Date().toLocaleString()}
        </div>
    </div>
</body>
</html>
  `;

  fs.writeFileSync("security-report-after.html", html);
}

function generateJsonReport(issues) {
  const grouped = {};
  issues.forEach((issue) => {
    const category = SECURITY_CATEGORIES[issue.ruleId]?.category || "Other";
    if (!grouped[category]) {
      grouped[category] = {
        severity: SECURITY_CATEGORIES[issue.ruleId]?.severity || "UNKNOWN",
        description: SECURITY_CATEGORIES[issue.ruleId]?.description || "N/A",
        issues: [],
      };
    }
    grouped[category].issues.push(issue);
  });

  const report = {
    scanDate: new Date().toISOString(),
    summary: {
      total: issues.length,
      critical: issues.filter(
        (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "CRITICAL"
      ).length,
      high: issues.filter(
        (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "HIGH"
      ).length,
      medium: issues.filter(
        (i) => SECURITY_CATEGORIES[i.ruleId]?.severity === "MEDIUM"
      ).length,
    },
    categories: grouped,
  };

  fs.writeFileSync(
    "security-report-after.json",
    JSON.stringify(report, null, 2)
  );
}

// Run the security tests
runSecurityTests();
