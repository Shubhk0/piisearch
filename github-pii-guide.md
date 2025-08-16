# GitHub PII Discovery Engine - User Guide

## Overview

The GitHub PII Discovery Engine is a specialized security tool designed to identify Personally Identifiable Information (PII) and sensitive data within GitHub organization repositories. This tool is specifically focused on organizational security auditing and helps security teams identify potential information disclosure risks.

## 🎯 Key Features

### Organization-Focused Scanning
- **Organization Repositories Only**: Specifically targets repositories belonging to GitHub organizations
- **Public Repository Access**: Scans publicly accessible organizational repositories without authentication
- **Strategic Scanning**: Uses intelligent prioritization to maximize effectiveness within API rate limits

### Comprehensive PII Detection
- **19 Different PII Types**: Detects emails, SSNs, credit cards, API keys, tokens, and more
- **Severity Classification**: Critical, High, Medium, and Low severity levels
- **Context Awareness**: Provides file location and surrounding code context
- **Pattern-Based Detection**: Uses proven regex patterns for accurate identification

## 🚀 How to Use

### 1. Access the Tool
Open the GitHub PII Discovery Engine in your web browser. The tool runs entirely client-side and requires no installation.

### 2. Understand the Limitations
- **60 API Requests/Hour**: Unauthenticated GitHub API limit
- **Public Repositories Only**: Cannot access private or internal repositories
- **Rate Limit Awareness**: Monitor remaining requests carefully

### 3. Start a Scan
1. Enter the **organization name** (e.g., "microsoft", "google", "facebook")
2. Select **scan strategy**:
   - **Quick Scan**: 5 repos, 10 files each, high-priority file types only
   - **Thorough Scan**: 10 repos, 20 files each, broader file type coverage
3. Click **"Discover Repositories"** to fetch organization repos
4. Select specific repositories from the discovered list
5. Click **"Start PII Scan"** to begin analysis

### 4. Monitor Progress
- Track API quota consumption in real-time
- View scan progress and current repository being analyzed
- Pause/resume scans to manage rate limits

### 5. Review Results
- **Real-time findings** appear as they're discovered
- **Severity-based filtering** to focus on critical issues
- **Export capabilities** for compliance reporting

## 🔍 What Gets Detected

### Critical Severity (Immediate Action Required)
- **Social Security Numbers (SSN)**: `123-45-6789`
- **Credit Card Numbers**: `4111-1111-1111-1111`
- **AWS Access Keys**: `AKIA...`
- **GitHub Tokens**: `ghp_...`
- **Private Keys**: `-----BEGIN PRIVATE KEY-----`
- **JWT Tokens**: `eyJ...`

### High Severity (Review Required)
- **API Keys**: Generic 20+ character strings
- **Database URLs**: Connection strings with credentials
- **Hardcoded Passwords**: `password="secret123"`
- **Third-party Service Keys**: Slack, Stripe, Twilio, SendGrid, Mailgun

### Medium Severity (Information Disclosure)
- **Email Addresses**: `user@company.com`
- **Phone Numbers**: `(555) 123-4567`
- **Dates of Birth**: `01/15/1985`

### Low Severity (Contextual Risk)
- **IP Addresses**: `192.168.1.100`

## 📊 File Type Prioritization

### Critical Priority
- `.env` - Environment files
- `.config` - Configuration files
- `.secret` - Secret files
- `.key` - Key files

### High Priority
- `.json` - JSON configuration
- `.yaml`, `.yml` - YAML files
- `.properties` - Properties files
- `.ini` - Initialization files

### Medium Priority
- `.txt` - Text files
- `.md` - Markdown files
- `.sql` - SQL scripts
- `.log` - Log files

### Low Priority
- `.js`, `.ts` - JavaScript/TypeScript
- `.py` - Python files
- `.java` - Java source
- `.php`, `.rb`, `.go` - Other source code

## ⚠️ Important Limitations

### API Rate Limiting
- **Unauthenticated limit**: 60 requests/hour
- **Request cost**: Each file scan = 1-2 requests
- **Recovery time**: Full quota restored every hour
- **Strategic use**: Plan scans carefully

### Access Restrictions
- **Public repos only**: No private repository access
- **Organization focus**: Individual user repos not supported
- **Content limitations**: Large files may be truncated
- **CORS restrictions**: May require demo mode in some browsers

### Detection Accuracy
- **Regex-based**: Pattern matching may produce false positives
- **Context-dependent**: Manual review required for validation
- **File type focus**: Some formats may be missed
- **Encoding issues**: Base64 or encrypted content not decoded

## 🛡️ Security Best Practices

### For Security Teams
1. **Regular Scanning**: Schedule periodic scans of critical organization repos
2. **Priority Focus**: Start with recently updated repositories
3. **Cross-Reference**: Validate findings manually before taking action
4. **Documentation**: Export results for compliance and audit trails
5. **Follow-up**: Track remediation of identified issues

### For Development Teams
1. **Prevention First**: Use pre-commit hooks to prevent PII commits
2. **Secret Management**: Use proper secret management tools (HashiCorp Vault, AWS Secrets Manager)
3. **Code Reviews**: Include PII checks in peer review processes
4. **Environment Variables**: Never hardcode secrets in source code
5. **Access Controls**: Limit repository access to necessary personnel

### Responsible Disclosure
When PII is discovered in public repositories:

1. **Contact the organization** through responsible disclosure channels
2. **Provide specific details** about the location and type of PII found
3. **Allow reasonable time** for remediation before public disclosure
4. **Follow industry standards** for responsible security research
5. **Document the process** for compliance and legal requirements

## 📈 Interpreting Results

### Severity Assessment
- **Critical findings** require immediate attention and secret rotation
- **High findings** should be reviewed within 24-48 hours
- **Medium findings** need assessment for business impact
- **Low findings** may be acceptable depending on context

### False Positive Management
Common false positives include:
- **Test data**: Dummy emails, phone numbers in test files
- **Documentation**: Examples in README files
- **Comments**: Placeholder values in code comments
- **Generated content**: Automatically generated IDs that match patterns

### Remediation Steps
1. **Verify the finding** through manual review
2. **Assess the impact** - Is this real sensitive data?
3. **Rotate affected secrets** immediately if confirmed
4. **Remove from repository** using tools like `git filter-repo`
5. **Update security practices** to prevent recurrence
6. **Monitor for abuse** of potentially compromised credentials

## 🔧 Technical Implementation

### Architecture
- **Client-side execution**: All processing happens in the browser
- **No data storage**: No PII data is stored or transmitted to third parties
- **GitHub API integration**: Uses public GitHub REST API endpoints
- **Pattern matching**: Comprehensive regex library for PII detection

### Performance Optimization
- **Intelligent queuing**: Manages API requests efficiently
- **Content prioritization**: Scans high-risk files first
- **Caching**: Avoids duplicate API requests
- **Progressive loading**: Updates results in real-time

## 📚 Additional Resources

### GitHub Security Features
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [Push Protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations)

### Security Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security/getting-started/securing-your-repository)

### Legal and Compliance
- [GDPR Compliance](https://gdpr-info.eu/)
- [CCPA Requirements](https://oag.ca.gov/privacy/ccpa)
- [SOX Compliance](https://www.sec.gov/about/laws/soa2002.pdf)

## 🤝 Contributing

This tool is designed for educational and security research purposes. When contributing to security tools:

1. **Test thoroughly** with sample data
2. **Document new patterns** with examples
3. **Consider false positive rates** in pattern design
4. **Follow responsible disclosure** practices
5. **Maintain compatibility** with existing workflows

## ⚖️ Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for:

- **Obtaining proper authorization** before scanning repositories
- **Complying with applicable laws** and regulations
- **Respecting privacy rights** and terms of service
- **Using findings responsibly** through proper disclosure channels
- **Understanding limitations** and potential for false positives

Always ensure you have appropriate permission before scanning repositories that don't belong to your organization.

---

**Version**: 1.0  
**Last Updated**: August 2025  
**License**: Educational Use Only