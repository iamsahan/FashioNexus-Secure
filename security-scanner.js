/**
 * Manual Security Scanner for FashioNexus Backend
 * This script analyzes backend code for security vulnerabilities
 * without requiring ESLint plugins
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Security patterns to detect
const SECURITY_PATTERNS = {
  "Missing Authentication on Critical Routes": {
    severity: "CRITICAL",
    patterns: [
      {
        regex:
          /router\.(delete|put|post|patch)\s*\(\s*["']([^"']*(?:delete|update|add|create|all|status)[^"']*)["']\s*,\s*(?!.*authenticate)/gi,
        message: "Critical route without authentication middleware",
      },
      {
        regex:
          /app\.(delete|put|post|patch)\s*\(\s*["']([^"']*(?:delete|update|add|create)[^"']*)["']\s*,\s*(?!.*authenticate)/gi,
        message: "State-changing route missing authentication",
      },
    ],
  },
  "Sensitive Data Exposure": {
    severity: "HIGH",
    patterns: [
      {
        regex:
          /console\.log\s*\([^)]*(?:password|token|secret|otp|auth|credential)[^)]*\)/gi,
        message: "Sensitive data being logged to console",
      },
      {
        regex:
          /(mongodb\+srv:\/\/[^"'\s]+|["'][^"']*@gmail\.com["']|pass\s*:\s*["'][^"']+["'])/gi,
        message: "Hardcoded credentials in source code",
      },
      {
        regex: /const\s+\w*_?(URL|SECRET|KEY|PASSWORD)\s*=\s*["'][^"']+["']/gi,
        message:
          "Sensitive configuration hardcoded instead of using environment variables",
      },
      {
        regex: /res\.(?:json|send)\s*\(\s*validUser\s*\)/gi,
        message: "Sending user object without removing sensitive fields",
      },
    ],
  },
  "Injection Risks (NoSQL Injection)": {
    severity: "CRITICAL",
    patterns: [
      {
        regex:
          /(?:findOne|find|findById|findByIdAndUpdate|findOneAndDelete)\s*\(\s*\{[^}]*req\.(?:body|query|params)[^}]*\}/gi,
        message:
          "Direct use of user input in database query - NoSQL injection risk",
      },
      {
        regex: /\$regex\s*:\s*req\.(?:query|body|params)/gi,
        message:
          "User input in regex query without validation - injection risk",
      },
      {
        regex: /(?<!safe)parseInt\s*\(\s*req\.(?:query|params)/gi,
        message: "Unvalidated parseInt on user input - potential injection",
      },
      {
        regex: /email\s*:\s*req\.body\.email[^,\}]*[,\}]/gi,
        message: "Direct email from request body without validation",
      },
    ],
  },
  "Insecure OTP Implementation": {
    severity: "HIGH",
    patterns: [
      {
        regex: /new\s+Map\s*\(\s*\).*otp/gi,
        message:
          "OTP stored in-memory Map - not persistent or secure for production",
      },
      {
        regex: /Math\.random\s*\(\s*\).*OTP/gi,
        message: "OTP generated using Math.random() - predictable and insecure",
      },
      {
        regex:
          /app\.post\s*\(\s*["'][^"']*(?:otp|sendotp|verifyotp)[^"']*["']\s*,\s*\(/gi,
        message:
          "OTP endpoint without rate limiting - vulnerable to brute force",
      },
      {
        regex: /otpMap\.set\s*\(\s*\w+\s*,\s*\w+\s*\)/gi,
        message: "OTP stored without expiration time",
      },
    ],
  },
  "Cross-Site Scripting (XSS)": {
    severity: "HIGH",
    patterns: [
      {
        regex: /html\s*:\s*`[^`]*\$\{(?:otp|req\.|email|username)[^`]*`/gi,
        message: "User input in HTML template without sanitization - XSS risk",
      },
      {
        regex: /res\.json\s*\(\s*\{[^}]*req\.(?:body|query)[^}]*\}/gi,
        message: "Reflecting user input in response without sanitization",
      },
    ],
  },
  "Insecure File Upload": {
    severity: "CRITICAL",
    patterns: [
      {
        regex: /Date\.now\s*\(\s*\)\s*\+.*extname(?!.*crypto\.randomBytes)/gi,
        message: "Filename generation using only timestamp - predictable",
      },
      {
        // Check for file.originalname usage but exclude secure patterns
        checkFunction: (content, filePath) => {
          // Look for file.originalname usage
          const originalNameUsage = /file\.originalname/gi.test(content);
          if (!originalNameUsage) return false;

          // Check if it's used securely (only for extension extraction with crypto.randomBytes)
          const hasSecurePattern =
            /const\s+\w+\s*=\s*path\.extname\s*\(\s*file\.originalname\s*\)[\s\S]*crypto\.randomBytes/gi.test(
              content
            );
          const hasFileFilter =
            /const\s+fileFilter\s*=/.test(content) ||
            /fileFilter\s*:/gi.test(content);
          const hasMimeValidation = /file\.mimetype/.test(content);

          // If using originalname securely (only for extension) with crypto randomBytes and proper validation, it's secure
          return !(hasSecurePattern && hasFileFilter && hasMimeValidation);
        },
        message: "Using original filename - potential path traversal risk",
        fileLevel: true,
      },
    ],
  },
  "Missing Security Headers": {
    severity: "MEDIUM",
    patterns: [
      {
        regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/gi,
        message: "CORS configured with wildcard origin - allows any domain",
      },
      {
        regex: /express\s*\(\s*\)/g,
        checkFunction: (content, filePath) => {
          // Only check main server files (index.js, app.js, server.js)
          const isMainFile = /\/(index|app|server)\.js$/.test(filePath);
          if (!isMainFile) return false;

          return (
            !content.includes("app.use(helmet") &&
            !content.includes("app.use(\n  helmet")
          );
        },
        message: "Application not using helmet middleware for security headers",
        fileLevel: true,
      },
    ],
  },
  "Missing CSRF Protection": {
    severity: "HIGH",
    patterns: [
      {
        // Check for cookie-based auth without proper CSRF protection
        checkFunction: (content, filePath) => {
          // Look for access_token cookie setting
          const cookiePattern = /\.cookie\s*\(\s*["']access_token["']/gi;
          const hasCookieAuth = cookiePattern.test(content);
          if (!hasCookieAuth) return false;

          // Check if it's an authentication file (where CSRF tokens can't exist yet)
          const isAuthFile = /auth/gi.test(filePath);
          if (isAuthFile) {
            // For auth files, check if using sameSite strict (provides CSRF protection)
            const hasSameSiteStrict = /sameSite\s*:\s*["']strict["']/gi.test(
              content
            );
            return !hasSameSiteStrict; // Only flag if missing sameSite strict
          }

          // For non-auth files, check for CSRF token validation
          const hasCSRFValidation =
            /csrf.*token/gi.test(content) || /verifyCSRF/gi.test(content);
          return !hasCSRFValidation;
        },
        message: "Cookie-based authentication without CSRF protection",
        fileLevel: true,
      },
      {
        regex: /\.cookie\s*\([^)]*\)\s*(?!.*sameSite|.*secure)/gi,
        message: "Cookie set without sameSite or secure flags - CSRF risk",
      },
    ],
  },
};

class SecurityScanner {
  constructor() {
    this.issues = [];
    this.scannedFiles = 0;
  }

  async scanDirectory(dir, extensions = [".js"]) {
    const files = fs.readdirSync(dir);

    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);

      if (stat.isDirectory()) {
        await this.scanDirectory(filePath, extensions);
      } else if (extensions.some((ext) => file.endsWith(ext))) {
        await this.scanFile(filePath);
      }
    }
  }

  async scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, "utf8");
      this.scannedFiles++;

      const relativePath = filePath
        .replace(__dirname, "")
        .replace(/\\\\/g, "/");

      // Scan for each security category
      Object.entries(SECURITY_PATTERNS).forEach(([category, config]) => {
        config.patterns.forEach((pattern) => {
          if (pattern.fileLevel) {
            // File-level check with optional custom validation
            let shouldFlag = false;

            if (pattern.checkFunction) {
              // Use custom function to check
              shouldFlag = pattern.checkFunction(content, relativePath);
            } else {
              // Use regex test
              shouldFlag = pattern.regex.test(content);
            }

            if (shouldFlag) {
              this.issues.push({
                file: relativePath,
                line: 1,
                category,
                severity: config.severity,
                message: pattern.message,
              });
            }
          } else {
            // Line-by-line check
            const lines = content.split("\n");
            lines.forEach((line, index) => {
              pattern.regex.lastIndex = 0; // Reset regex state
              const matches = line.matchAll(
                new RegExp(pattern.regex.source, pattern.regex.flags)
              );

              for (const match of matches) {
                this.issues.push({
                  file: relativePath,
                  line: index + 1,
                  category,
                  severity: config.severity,
                  message: pattern.message,
                  code: line.trim(),
                });
              }
            });
          }
        });
      });
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error.message);
    }
  }

  generateReport() {
    console.log(
      "\n╔═══════════════════════════════════════════════════════════╗"
    );
    console.log("║       FashioNexus Security Vulnerability Scanner         ║");
    console.log(
      "╚═══════════════════════════════════════════════════════════╝\n"
    );

    console.log(`📂 Scanned ${this.scannedFiles} files`);
    console.log(`🔍 Found ${this.issues.length} security issues\n`);

    // Group by category
    const grouped = {};
    this.issues.forEach((issue) => {
      if (!grouped[issue.category]) {
        grouped[issue.category] = [];
      }
      grouped[issue.category].push(issue);
    });

    // Display by category
    Object.entries(grouped)
      .sort()
      .forEach(([category, issues]) => {
        const severity = issues[0].severity;
        const icon =
          severity === "CRITICAL" ? "🔴" : severity === "HIGH" ? "🟠" : "🟡";

        console.log(`\n${"═".repeat(60)}`);
        console.log(`${icon} ${category}`);
        console.log(
          `   Severity: ${severity} | Count: ${issues.length} issue(s)`
        );
        console.log(`${"═".repeat(60)}\n`);

        issues.forEach((issue, index) => {
          console.log(`   ${index + 1}. ${issue.file}:${issue.line}`);
          console.log(`      ⚠️  ${issue.message}`);
          if (issue.code) {
            console.log(`      📝  ${issue.code}`);
          }
          console.log("");
        });
      });

    // Summary
    console.log(
      "\n═══════════════════════════════════════════════════════════"
    );
    console.log("                         SUMMARY                           ");
    console.log(
      "═══════════════════════════════════════════════════════════\n"
    );

    const criticalCount = this.issues.filter(
      (i) => i.severity === "CRITICAL"
    ).length;
    const highCount = this.issues.filter((i) => i.severity === "HIGH").length;
    const mediumCount = this.issues.filter(
      (i) => i.severity === "MEDIUM"
    ).length;

    console.log(`   🔴 CRITICAL: ${criticalCount}`);
    console.log(`   🟠 HIGH:     ${highCount}`);
    console.log(`   🟡 MEDIUM:   ${mediumCount}`);
    console.log(`   ────────────────────`);
    console.log(`   📊 TOTAL:    ${this.issues.length}\n`);

    return grouped;
  }

  generateMarkdownReport(grouped) {
    let markdown = `# 🔒 FashioNexus Security Vulnerability Report

**Generated:** ${new Date().toLocaleString()}  
**Total Issues:** ${this.issues.length}  
**Files Scanned:** ${this.scannedFiles}

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | ${this.issues.filter((i) => i.severity === "CRITICAL").length} |
| 🟠 HIGH | ${this.issues.filter((i) => i.severity === "HIGH").length} |
| 🟡 MEDIUM | ${this.issues.filter((i) => i.severity === "MEDIUM").length} |
| **TOTAL** | **${this.issues.length}** |

---

`;

    Object.entries(grouped)
      .sort()
      .forEach(([category, issues]) => {
        const severity = issues[0].severity;
        const icon =
          severity === "CRITICAL" ? "🔴" : severity === "HIGH" ? "🟠" : "🟡";

        markdown += `## ${icon} ${category}\n\n`;
        markdown += `**Severity:** ${severity}  \n`;
        markdown += `**Issues Found:** ${issues.length}\n\n`;

        issues.forEach((issue, index) => {
          markdown += `### Issue ${index + 1}\n\n`;
          markdown += `- **File:** \`${issue.file}\`\n`;
          markdown += `- **Line:** ${issue.line}\n`;
          markdown += `- **Description:** ${issue.message}\n`;
          if (issue.code) {
            markdown += `- **Code:**\n\`\`\`javascript\n${issue.code}\n\`\`\`\n`;
          }
          markdown += "\n";
        });

        markdown += "\n---\n\n";
      });

    markdown += `## 🔧 Recommendations\n\n`;
    markdown += `### Critical Priority\n`;
    markdown += `1. Implement authentication middleware on all critical routes\n`;
    markdown += `2. Fix NoSQL injection vulnerabilities by validating user input\n`;
    markdown += `3. Add file upload validation and security measures\n\n`;
    markdown += `### High Priority\n`;
    markdown += `4. Remove hardcoded credentials and use environment variables\n`;
    markdown += `5. Implement secure OTP generation and storage\n`;
    markdown += `6. Add CSRF protection for cookie-based authentication\n`;
    markdown += `7. Sanitize all user input to prevent XSS\n\n`;
    markdown += `### Medium Priority\n`;
    markdown += `8. Add security headers using helmet middleware\n`;
    markdown += `9. Configure CORS properly instead of using wildcards\n`;
    markdown += `10. Implement rate limiting on all endpoints\n\n`;

    fs.writeFileSync("SECURITY_REPORT.md", markdown);
    console.log("✅ Markdown report saved to: SECURITY_REPORT.md");
  }

  generateHtmlReport(grouped) {
    let html = `<!DOCTYPE html>
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
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
            margin-right: 10px;
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
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
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
            <p style="margin-top: 10px; opacity: 0.9;">Files Scanned: ${
              this.scannedFiles
            } | Issues Found: ${this.issues.length}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3 class="critical">${
                  this.issues.filter((i) => i.severity === "CRITICAL").length
                }</h3>
                <p>Critical Issues</p>
            </div>
            <div class="summary-card">
                <h3 class="high">${
                  this.issues.filter((i) => i.severity === "HIGH").length
                }</h3>
                <p>High Issues</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">${
                  this.issues.filter((i) => i.severity === "MEDIUM").length
                }</h3>
                <p>Medium Issues</p>
            </div>
            <div class="summary-card">
                <h3>${this.issues.length}</h3>
                <p>Total Issues</p>
            </div>
        </div>
        
        <div class="content">`;

    Object.entries(grouped)
      .sort()
      .forEach(([category, issues]) => {
        const severity = issues[0].severity;
        const severityClass = severity.toLowerCase();

        html += `
            <div class="category">
                <div class="category-header">
                    <h2>${category}</h2>
                    <span class="badge badge-${severityClass}">${severity}</span>
                    <span style="color: #666;">${issues.length} issue(s) found</span>
                </div>`;

        issues.forEach((issue, index) => {
          html += `
                <div class="issue">
                    <div><strong>Issue #${index + 1}</strong></div>
                    <div class="issue-location">📁 ${issue.file}:${
            issue.line
          }</div>
                    <div class="issue-message">⚠️ ${issue.message}</div>`;

          if (issue.code) {
            html += `
                    <div class="code-block">${issue.code
                      .replace(/</g, "&lt;")
                      .replace(/>/g, "&gt;")}</div>`;
          }

          html += `
                </div>`;
        });

        html += `
            </div>`;
      });

    html += `
        </div>
        <div class="timestamp">
            Report generated on ${new Date().toLocaleString()}
        </div>
    </div>
</body>
</html>`;

    fs.writeFileSync("security-report.html", html);
    console.log("✅ HTML report saved to: security-report.html");
  }

  generateJsonReport(grouped) {
    const report = {
      scanDate: new Date().toISOString(),
      filesScanned: this.scannedFiles,
      summary: {
        total: this.issues.length,
        critical: this.issues.filter((i) => i.severity === "CRITICAL").length,
        high: this.issues.filter((i) => i.severity === "HIGH").length,
        medium: this.issues.filter((i) => i.severity === "MEDIUM").length,
      },
      categories: grouped,
    };

    fs.writeFileSync("security-report.json", JSON.stringify(report, null, 2));
    console.log("✅ JSON report saved to: security-report.json");
  }
}

// Main execution
async function main() {
  const scanner = new SecurityScanner();

  console.log("🔍 Starting security scan...\n");

  // Scan API directory
  const apiDir = path.join(__dirname, "api");
  if (fs.existsSync(apiDir)) {
    await scanner.scanDirectory(apiDir);
  }

  // Generate reports
  const grouped = scanner.generateReport();
  scanner.generateMarkdownReport(grouped);
  scanner.generateHtmlReport(grouped);
  scanner.generateJsonReport(grouped);

  console.log("\n✨ Security scan completed!\n");

  // Exit with error code if critical issues found
  const criticalCount = scanner.issues.filter(
    (i) => i.severity === "CRITICAL"
  ).length;
  if (criticalCount > 0) {
    console.log(
      `⚠️  WARNING: Found ${criticalCount} CRITICAL security issues!\n`
    );
    process.exit(1);
  }
}

main().catch(console.error);
