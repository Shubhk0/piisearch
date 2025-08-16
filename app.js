// SecureDisclose - PII Exposure Discovery & Responsible Disclosure Platform

class SecureDiscloseApp {
    constructor() {
        // Application data storage (in-memory since localStorage not available)
        this.findings = [];
        this.organizations = [];
        this.disclosures = [];
        this.activities = [];
        
        // PII patterns and severity mapping from application data
        this.piiPatterns = {
            ssn: /\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-\s]?)\d{2}\3\d{4}\b/g,
            credit_card: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
            aws_access_key: /AKIA[0-9A-Z]{16}/g,
            github_token: /ghp_[0-9a-zA-Z]{36}/g,
            private_key: /-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY/g,
            jwt_token: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
            api_key: /\b[A-Za-z0-9_-]{20,}\b/g,
            database_url: /(mongodb|mysql|postgres|redis):\/\/[^\s]+/g,
            password: /(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{6,}['"]/gi,
            slack_token: /xox[bpoa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/g,
            stripe_key: /sk_(test|live)_[0-9a-zA-Z]{24}/g,
            twilio_key: /SK[0-9a-fA-F]{32}/g,
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            phone: /\b(?:\+?1[-\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-\s]?\d{3}[-\s]?\d{4}\b/g,
            date_birth: /\b(0[1-9]|1[0-2])[\/\-](0[1-9]|[12][0-9]|3[01])[\/\-](19|20)\d{2}\b/g,
            ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
        };

        this.severityMapping = {
            ssn: 'critical',
            credit_card: 'critical', 
            aws_access_key: 'critical',
            github_token: 'critical',
            private_key: 'critical',
            jwt_token: 'critical',
            api_key: 'high',
            database_url: 'high',
            password: 'high',
            slack_token: 'high',
            stripe_key: 'high',
            twilio_key: 'high',
            email: 'medium',
            phone: 'medium',
            date_birth: 'medium',
            ipv4: 'low'
        };

        // Mock data for demonstration
        this.mockOrganizations = [
            {
                id: 1,
                name: 'Microsoft',
                domain: 'microsoft.com',
                github: 'microsoft',
                securityEmail: 'secure@microsoft.com',
                bugBounty: 'private',
                hasProgram: true
            },
            {
                id: 2,
                name: 'Google',
                domain: 'google.com',
                github: 'google',
                securityEmail: 'security@google.com',
                bugBounty: 'hackerone',
                hasProgram: true
            },
            {
                id: 3,
                name: 'Meta',
                domain: 'meta.com',
                github: 'facebook',
                securityEmail: 'security@meta.com',
                bugBounty: 'hackerone',
                hasProgram: true
            }
        ];

        this.mockRepositories = {
            microsoft: ['TypeScript', 'vscode', 'PowerToys', 'dotnet', 'terminal'],
            google: ['material-design-lite', 'guava', 'gson', 'angular', 'tensorflow'],
            facebook: ['react', 'create-react-app', 'metro', 'relay', 'jest']
        };

        this.mockFileContents = {
            'config.json': `{
    "database": {
        "url": "mongodb://admin:password123@cluster.mongodb.net/myapp",
        "host": "192.168.1.100"
    },
    "keys": {
        "aws": "AKIAIOSFODNN7EXAMPLE",
        "github": "ghp_1234567890abcdef1234567890abcdef123456",
        "stripe": "sk_test_1234567890abcdef1234567890abcdef"
    },
    "contacts": {
        "admin": "admin@company.com",
        "support": "(555) 123-4567"
    }
}`,
            '.env': `DATABASE_URL=postgres://user:secretpass@localhost:5432/mydb
API_KEY=sk_live_1234567890abcdef1234567890abcdef
GITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890abcd
AWS_ACCESS_KEY=AKIAJ7K4L5M6N7O8P9Q0R
ADMIN_EMAIL=admin@example.com
SUPPORT_PHONE=555-123-4567`,
            'database.sql': `INSERT INTO users (name, email, phone, ssn, dob) VALUES 
('John Doe', 'john.doe@example.com', '555-123-4567', '123-45-6789', '01/15/1985'),
('Jane Smith', 'jane.smith@company.org', '(555) 987-6543', '987-65-4321', '03/22/1990');

UPDATE config SET jwt_secret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';`
        };

        this.reportTemplates = {
            initial_disclosure: {
                subject: "Security Vulnerability Disclosure - PII Exposure in {organization} Repository",
                content: `Subject: Security Vulnerability Disclosure - PII Exposure in {organization} Repository

Dear {organization} Security Team,

EXECUTIVE SUMMARY
We have identified a potential security vulnerability involving the exposure of personally identifiable information (PII) and sensitive data in one of your public repositories. This disclosure follows responsible security research practices.

TECHNICAL DETAILS
Repository: {repository}
File: {file}
Vulnerability Type: {pii_type}
Severity: {severity}
Discovery Date: {date}

IMPACT ASSESSMENT
The exposed data could potentially:
- Compromise user privacy and security
- Lead to unauthorized access to systems or accounts
- Result in regulatory compliance violations
- Damage organizational reputation

AFFECTED DATA
{findings_details}

REMEDIATION RECOMMENDATIONS
1. Immediately remove sensitive data from the repository
2. Rotate any exposed credentials, API keys, or tokens
3. Review repository history and clean using tools like BFG Repo-Cleaner
4. Implement pre-commit hooks to prevent future exposures
5. Consider using environment variables or secret management systems

DISCLOSURE TIMELINE
We follow a 90-day responsible disclosure timeline:
- Day 0: Initial notification (today)
- Day 30: First follow-up if no response
- Day 60: Escalation notice
- Day 90: Public disclosure consideration

We are committed to working with your team to resolve this issue promptly and professionally.

Best regards,
Security Researcher
Contact: researcher@securedisclose.com`
            },
            followup_reminder: {
                subject: "Follow-up: Security Vulnerability Report - {reference_id}",
                content: `Subject: Follow-up: Security Vulnerability Report - {reference_id}

Dear {organization} Security Team,

REFERENCE
This is a follow-up to our security vulnerability disclosure sent on {initial_date}.
Reference ID: {reference_id}

TIMELINE UPDATE
- Initial disclosure: {initial_date}
- Current date: {current_date}
- Days since disclosure: {days_elapsed}
- Next escalation: {next_milestone}

URGENCY
We have not yet received acknowledgment of this security vulnerability report. The issue involves exposure of {pii_type} in your public repository {repository}.

NEXT STEPS
Please confirm receipt of this report and provide an estimated timeline for remediation. We remain committed to responsible disclosure and are available to provide additional technical details if needed.

If this message has reached you in error or you need to redirect to the appropriate security contact, please let us know immediately.

Best regards,
Security Researcher
Contact: researcher@securedisclose.com`
            },
            public_disclosure: {
                subject: "Public Security Advisory - {organization} PII Exposure",
                content: `SECURITY ADVISORY
Advisory ID: {advisory_id}
Date: {date}
Severity: {severity}

SUMMARY
A security vulnerability was discovered in {organization}'s public repository that exposed personally identifiable information (PII) and sensitive data.

DETAILS
Repository: {repository}
File: {file}
Vulnerability: {pii_type} exposure
Discovery Date: {discovery_date}
Public Disclosure Date: {disclosure_date}

TIMELINE
- {discovery_date}: Vulnerability discovered
- {initial_contact}: Initial disclosure to {organization}
- {followup_dates}: Follow-up communications
- {disclosure_date}: Public disclosure

VENDOR RESPONSE
{vendor_response_status}

MITIGATION
Users and administrators should:
1. Rotate any potentially exposed credentials
2. Monitor accounts for suspicious activity
3. Review similar repositories for additional exposures

This advisory follows responsible disclosure practices with a 90-day timeline.`
            }
        };

        this.isScanning = false;
        this.scanProgress = 0;
        this.currentScanOrg = null;
        this.currentFinding = null;

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadInitialData();
        this.initializeCharts();
        this.updateDashboard();
        this.addActivity('Platform initialized and ready for security research');
    }

    setupEventListeners() {
        // Navigation - use event delegation to avoid conflicts
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('nav-item')) {
                e.preventDefault();
                e.stopPropagation();
                const section = e.target.dataset.section;
                if (section) {
                    this.showSection(section);
                }
            }
        });

        // Discovery section
        const startDiscoveryBtn = document.getElementById('start-discovery-btn');
        if (startDiscoveryBtn) {
            startDiscoveryBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.startDiscovery();
            });
        }

        const pauseScanBtn = document.getElementById('pause-scan-btn');
        if (pauseScanBtn) {
            pauseScanBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.toggleScan();
            });
        }

        // Organization management
        const addOrgBtn = document.getElementById('add-org-btn');
        if (addOrgBtn) {
            addOrgBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.showAddOrganizationModal();
            });
        }

        const orgForm = document.getElementById('org-form');
        if (orgForm) {
            orgForm.addEventListener('submit', (e) => this.handleAddOrganization(e));
        }

        // Findings filters
        const severityFilter = document.getElementById('severity-filter');
        if (severityFilter) {
            severityFilter.addEventListener('change', () => this.filterFindings());
        }

        const statusFilter = document.getElementById('status-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', () => this.filterFindings());
        }

        const orgFilter = document.getElementById('org-filter');
        if (orgFilter) {
            orgFilter.addEventListener('input', () => this.filterFindings());
        }

        // Report templates
        document.addEventListener('click', (e) => {
            if (e.target.closest('.template-card')) {
                e.preventDefault();
                e.stopPropagation();
                const template = e.target.closest('.template-card').dataset.template;
                if (template) {
                    this.selectReportTemplate(template);
                }
            }
        });

        // Modal handling
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal-close') || e.target.classList.contains('modal-overlay')) {
                e.preventDefault();
                e.stopPropagation();
                this.closeModal();
            }
        });

        // Finding details
        const startDisclosureBtn = document.getElementById('start-disclosure-btn');
        if (startDisclosureBtn) {
            startDisclosureBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.startDisclosureProcess();
            });
        }

        // Download report button
        const downloadReportBtn = document.getElementById('download-report-btn');
        if (downloadReportBtn) {
            downloadReportBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.downloadReport();
            });
        }
    }

    loadInitialData() {
        // Load mock organizations
        this.organizations = [...this.mockOrganizations];
        this.renderOrganizations();
    }

    showSection(sectionName) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        const activeNavItem = document.querySelector(`[data-section="${sectionName}"]`);
        if (activeNavItem) {
            activeNavItem.classList.add('active');
        }

        // Update content
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });
        const activeSection = document.getElementById(sectionName);
        if (activeSection) {
            activeSection.classList.add('active');
        }

        // Section-specific actions
        if (sectionName === 'organizations') {
            this.renderOrganizations();
        } else if (sectionName === 'findings') {
            this.renderFindings();
        } else if (sectionName === 'timeline') {
            this.renderTimeline();
        }
    }

    async startDiscovery() {
        const orgName = document.getElementById('org-search').value.trim().toLowerCase();
        const scanDepth = document.getElementById('scan-depth').value;
        const selectedPiiTypes = this.getSelectedPiiTypes();

        if (!orgName) {
            this.showNotification('Please enter an organization name', 'error');
            return;
        }

        if (selectedPiiTypes.length === 0) {
            this.showNotification('Please select at least one PII type to detect', 'error');
            return;
        }

        this.isScanning = true;
        this.currentScanOrg = orgName;
        this.scanProgress = 0;

        const progressSection = document.getElementById('scan-progress');
        if (progressSection) {
            progressSection.classList.remove('hidden');
        }

        const startBtn = document.getElementById('start-discovery-btn');
        if (startBtn) {
            startBtn.disabled = true;
            startBtn.textContent = 'Scanning...';
        }

        try {
            await this.performDiscoveryScan(orgName, scanDepth, selectedPiiTypes);
            this.addActivity(`Completed PII discovery scan for ${orgName}`);
            this.showNotification(`Scan completed! Found ${this.findings.length} potential PII exposures`, 'success');
        } catch (error) {
            this.showNotification(`Scan failed: ${error.message}`, 'error');
        } finally {
            this.isScanning = false;
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.textContent = 'Start Discovery Scan';
            }
            this.updateDashboard();
        }
    }

    async performDiscoveryScan(orgName, scanDepth, piiTypes) {
        const repos = this.mockRepositories[orgName] || [];
        if (repos.length === 0) {
            throw new Error(`No repositories found for ${orgName}. Try: microsoft, google, or facebook`);
        }

        const maxRepos = scanDepth === 'quick' ? 3 : scanDepth === 'thorough' ? 5 : 8;
        const maxFiles = scanDepth === 'quick' ? 5 : scanDepth === 'thorough' ? 10 : 15;

        const reposToScan = repos.slice(0, maxRepos);
        const totalSteps = reposToScan.length * maxFiles;
        let currentStep = 0;

        for (const repo of reposToScan) {
            if (!this.isScanning) break;

            const progressText = document.getElementById('progress-text');
            if (progressText) {
                progressText.textContent = `Scanning ${orgName}/${repo}...`;
            }
            
            await this.scanRepository(orgName, repo, maxFiles, piiTypes);
            
            currentStep += maxFiles;
            this.scanProgress = (currentStep / totalSteps) * 100;
            const progressFill = document.getElementById('progress-fill');
            if (progressFill) {
                progressFill.style.width = `${this.scanProgress}%`;
            }
            
            await this.delay(800);
        }

        const progressText = document.getElementById('progress-text');
        if (progressText) {
            progressText.textContent = `Scan completed! Found ${this.findings.length} findings.`;
        }
    }

    async scanRepository(orgName, repoName, maxFiles, piiTypes) {
        const mockFiles = ['config.json', '.env', 'database.sql', 'settings.yaml', 'secrets.txt'];
        const filesToScan = mockFiles.slice(0, maxFiles);

        for (const fileName of filesToScan) {
            if (!this.isScanning) break;

            const content = this.mockFileContents[fileName] || this.generateMockContent(fileName);
            await this.analyzeFileContent(orgName, repoName, fileName, content, piiTypes);
            await this.delay(200);
        }
    }

    analyzeFileContent(orgName, repoName, fileName, content, piiTypes) {
        for (const [piiType, pattern] of Object.entries(this.piiPatterns)) {
            const severity = this.severityMapping[piiType];
            
            if (!piiTypes.includes(severity)) continue;

            const matches = content.match(pattern);
            if (matches) {
                matches.forEach((match) => {
                    const finding = {
                        id: Date.now() + Math.random(),
                        piiType: piiType,
                        severity: severity,
                        organization: orgName,
                        repository: `${orgName}/${repoName}`,
                        file: fileName,
                        content: match,
                        context: this.getContext(content, match),
                        status: 'new',
                        discoveryDate: new Date().toISOString(),
                        timeline: {
                            discovered: new Date().toISOString()
                        }
                    };
                    
                    this.findings.push(finding);
                });
            }
        }
    }

    getContext(content, match) {
        const index = content.indexOf(match);
        const start = Math.max(0, index - 50);
        const end = Math.min(content.length, index + match.length + 50);
        return content.substring(start, end);
    }

    generateMockContent(fileName) {
        const templates = {
            'settings.yaml': `database:
  host: 192.168.1.50
  password: "super_secret_2024"
  api_key: "AKIAEXAMPLE1234567890"
contacts:
  admin: admin@${Math.random().toString(36).substr(2, 8)}.com
  phone: "555-${Math.floor(Math.random() * 1000)}-${Math.floor(Math.random() * 10000)}"`,
            'secrets.txt': `# Application secrets
API_KEY=sk_test_${Math.random().toString(36).substr(2, 24)}
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example
ADMIN_SSN=123-45-6789
CREDIT_CARD=4532015112830366`,
            'config.php': `<?php
$config = array(
    'db_password' => 'password123',
    'api_key' => 'AKIAIOSFODNN7EXAMPLE',
    'admin_email' => 'admin@example.com'
);`
        };
        
        return templates[fileName] || templates['secrets.txt'];
    }

    getSelectedPiiTypes() {
        const checkboxes = document.querySelectorAll('.pii-types-grid input[type="checkbox"]:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }

    toggleScan() {
        this.isScanning = !this.isScanning;
        const btn = document.getElementById('pause-scan-btn');
        if (btn) {
            btn.textContent = this.isScanning ? 'Pause' : 'Resume';
            btn.className = this.isScanning ? 'btn btn--secondary btn--sm' : 'btn btn--primary btn--sm';
        }
    }

    renderFindings() {
        const container = document.getElementById('findings-list');
        if (!container) return;
        
        if (this.findings.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <h3>No Findings Yet</h3>
                    <p>Start a discovery scan to find PII exposures in public repositories</p>
                    <button class="btn btn--primary" onclick="window.app.showSection('discovery')">Start Discovery</button>
                </div>
            `;
            return;
        }

        container.innerHTML = this.findings.map(finding => `
            <div class="finding-card ${finding.severity}" onclick="window.app.showFindingDetails('${finding.id}')">
                <div class="finding-header">
                    <h4 class="finding-title">${finding.piiType.replace(/_/g, ' ').toUpperCase()} Exposure</h4>
                    <span class="finding-severity ${finding.severity}">${finding.severity}</span>
                </div>
                <div class="finding-meta">
                    <strong>Repository:</strong> ${finding.repository}<br>
                    <strong>File:</strong> ${finding.file}<br>
                    <strong>Status:</strong> ${finding.status}
                </div>
                <div class="finding-preview">${this.truncateText(finding.context, 100)}</div>
            </div>
        `).join('');
    }

    filterFindings() {
        const severity = document.getElementById('severity-filter').value;
        const status = document.getElementById('status-filter').value;
        const org = document.getElementById('org-filter').value.toLowerCase();

        let filtered = this.findings;

        if (severity) {
            filtered = filtered.filter(f => f.severity === severity);
        }
        if (status) {
            filtered = filtered.filter(f => f.status === status);
        }
        if (org) {
            filtered = filtered.filter(f => f.organization.toLowerCase().includes(org));
        }

        // Update display with filtered results
        const container = document.getElementById('findings-list');
        if (!container) return;

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <h3>No Matching Findings</h3>
                    <p>Try adjusting your filters or starting a new discovery scan</p>
                </div>
            `;
        } else {
            container.innerHTML = filtered.map(finding => `
                <div class="finding-card ${finding.severity}" onclick="window.app.showFindingDetails('${finding.id}')">
                    <div class="finding-header">
                        <h4 class="finding-title">${finding.piiType.replace(/_/g, ' ').toUpperCase()} Exposure</h4>
                        <span class="finding-severity ${finding.severity}">${finding.severity}</span>
                    </div>
                    <div class="finding-meta">
                        <strong>Repository:</strong> ${finding.repository}<br>
                        <strong>File:</strong> ${finding.file}<br>
                        <strong>Status:</strong> ${finding.status}
                    </div>
                    <div class="finding-preview">${this.truncateText(finding.context, 100)}</div>
                </div>
            `).join('');
        }
    }

    showFindingDetails(findingId) {
        const finding = this.findings.find(f => f.id == findingId);
        if (!finding) return;

        this.currentFinding = finding;
        const modal = document.getElementById('finding-modal');
        const body = document.getElementById('finding-modal-body');
        
        if (!modal || !body) return;
        
        body.innerHTML = `
            <div class="finding-details">
                <h4>${finding.piiType.replace(/_/g, ' ').toUpperCase()} Exposure</h4>
                <div class="detail-grid">
                    <div><strong>Severity:</strong> <span class="finding-severity ${finding.severity}">${finding.severity}</span></div>
                    <div><strong>Organization:</strong> ${finding.organization}</div>
                    <div><strong>Repository:</strong> ${finding.repository}</div>
                    <div><strong>File:</strong> ${finding.file}</div>
                    <div><strong>Status:</strong> ${finding.status}</div>
                    <div><strong>Discovered:</strong> ${new Date(finding.discoveryDate).toLocaleDateString()}</div>
                </div>
                <div class="finding-content">
                    <h5>Exposed Content:</h5>
                    <pre>${finding.context}</pre>
                </div>
                <div class="impact-assessment">
                    <h5>Impact Assessment:</h5>
                    <ul>
                        ${this.getImpactAssessment(finding.severity, finding.piiType)}
                    </ul>
                </div>
            </div>
        `;

        modal.classList.remove('hidden');
    }

    getImpactAssessment(severity, piiType) {
        const impacts = {
            critical: [
                '<li>Immediate security risk - credentials or keys may be compromised</li>',
                '<li>Potential unauthorized access to systems and data</li>',
                '<li>High regulatory compliance risk (GDPR, CCPA, HIPAA)</li>',
                '<li>Significant reputational damage potential</li>'
            ],
            high: [
                '<li>Elevated security risk - sensitive data exposed</li>',
                '<li>Potential for account takeover or data access</li>',
                '<li>Moderate regulatory compliance risk</li>',
                '<li>Reputational damage potential</li>'
            ],
            medium: [
                '<li>Privacy risk - personal information exposed</li>',
                '<li>Potential for social engineering attacks</li>',
                '<li>GDPR/privacy regulation concerns</li>',
                '<li>Minor reputational impact</li>'
            ],
            low: [
                '<li>Limited privacy risk</li>',
                '<li>Minimal security impact</li>',
                '<li>Best practice violation</li>',
                '<li>Housekeeping issue</li>'
            ]
        };

        return impacts[severity].join('');
    }

    startDisclosureProcess() {
        if (!this.currentFinding) return;

        const finding = this.currentFinding;
        
        // Update finding status
        finding.status = 'disclosed';
        finding.timeline.disclosed = new Date().toISOString();

        // Create disclosure record
        const disclosure = {
            id: Date.now(),
            findingId: finding.id,
            organization: finding.organization,
            status: 'initial_contact',
            timeline: {
                initial_contact: new Date().toISOString(),
                first_followup: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
                escalation: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
                public_disclosure: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
            }
        };

        this.disclosures.push(disclosure);
        this.addActivity(`Started disclosure process for ${finding.piiType} exposure in ${finding.organization}`);
        
        this.closeModal();
        this.showNotification('Disclosure process started! Check the Timeline section to track progress.', 'success');
        this.updateDashboard();
    }

    renderOrganizations() {
        const container = document.getElementById('organizations-grid');
        if (!container) return;
        
        container.innerHTML = this.organizations.map(org => `
            <div class="org-card" onclick="window.app.showOrganizationDetails('${org.id}')">
                <div class="org-header">
                    <h4 class="org-name">${org.name}</h4>
                    <span class="org-status ${org.hasProgram ? 'has-bounty' : 'no-bounty'}">
                        ${org.hasProgram ? 'Bug Bounty' : 'No Program'}
                    </span>
                </div>
                <div class="org-details">
                    <div><strong>Domain:</strong> ${org.domain}</div>
                    <div><strong>GitHub:</strong> ${org.github}</div>
                    ${org.bugBounty !== 'none' ? `<div><strong>Platform:</strong> ${org.bugBounty}</div>` : ''}
                </div>
                <div class="org-contact">
                    <div class="contact-item">
                        <span>📧</span> ${org.securityEmail}
                    </div>
                    <div class="contact-item">
                        <span>🔗</span> security.txt available
                    </div>
                </div>
            </div>
        `).join('');
    }

    showOrganizationDetails(orgId) {
        const org = this.organizations.find(o => o.id == orgId);
        if (!org) return;
        
        this.showNotification(`Organization details for ${org.name}`, 'info');
    }

    showAddOrganizationModal() {
        const modal = document.getElementById('org-modal');
        const title = document.getElementById('org-modal-title');
        const form = document.getElementById('org-form');
        
        if (title) title.textContent = 'Add Organization';
        if (form) form.reset();
        if (modal) modal.classList.remove('hidden');
    }

    handleAddOrganization(e) {
        e.preventDefault();
        
        const newOrg = {
            id: Date.now(),
            name: document.getElementById('org-name').value,
            domain: document.getElementById('org-domain').value,
            github: document.getElementById('org-github').value,
            securityEmail: document.getElementById('org-security-email').value,
            bugBounty: document.getElementById('org-bug-bounty').value,
            hasProgram: document.getElementById('org-bug-bounty').value !== 'none'
        };

        this.organizations.push(newOrg);
        this.renderOrganizations();
        this.closeModal();
        this.addActivity(`Added new organization: ${newOrg.name}`);
        this.showNotification(`Organization ${newOrg.name} added successfully`, 'success');
    }

    selectReportTemplate(templateType) {
        const template = this.reportTemplates[templateType];
        if (!template) return;

        // Show preview with sample data
        const sampleData = {
            organization: 'Example Corp',
            repository: 'example-corp/web-app',
            file: 'config/database.yml',
            pii_type: 'API Key',
            severity: 'High',
            date: new Date().toLocaleDateString(),
            reference_id: 'SD-' + Date.now().toString().slice(-6),
            findings_details: 'AWS API key exposed in configuration file'
        };

        let content = template.content;
        Object.entries(sampleData).forEach(([key, value]) => {
            content = content.replace(new RegExp(`{${key}}`, 'g'), value);
        });

        const reportContent = document.getElementById('report-content');
        const reportPreview = document.getElementById('report-preview');
        
        if (reportContent) reportContent.textContent = content;
        if (reportPreview) reportPreview.classList.remove('hidden');

        // Update button states
        document.querySelectorAll('.template-card').forEach(card => {
            card.style.borderColor = 'var(--color-card-border)';
        });
        const selectedCard = document.querySelector(`[data-template="${templateType}"]`);
        if (selectedCard) {
            selectedCard.style.borderColor = 'var(--color-primary)';
        }
    }

    downloadReport() {
        const reportContent = document.getElementById('report-content');
        if (!reportContent) return;

        const content = reportContent.textContent;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-disclosure-report-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Report downloaded successfully', 'success');
    }

    renderTimeline() {
        const container = document.getElementById('active-timeline-list');
        if (!container) return;
        
        if (this.disclosures.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">⏱️</div>
                    <h3>No Active Disclosures</h3>
                    <p>Create findings and start the responsible disclosure process</p>
                    <button class="btn btn--primary" onclick="window.app.showSection('findings')">Manage Findings</button>
                </div>
            `;
            return;
        }

        container.innerHTML = this.disclosures.map(disclosure => {
            const finding = this.findings.find(f => f.id === disclosure.findingId);
            const daysElapsed = Math.floor((Date.now() - new Date(disclosure.timeline.initial_contact)) / (1000 * 60 * 60 * 24));
            
            return `
                <div class="timeline-item">
                    <div class="timeline-header">
                        <h4>${disclosure.organization} - ${finding ? finding.piiType.replace(/_/g, ' ').toUpperCase() : 'Unknown'}</h4>
                        <span class="timeline-status">${disclosure.status.replace(/_/g, ' ')}</span>
                    </div>
                    <div class="timeline-progress">
                        <div class="timeline-days">Day ${daysElapsed} of 90</div>
                        <div class="timeline-bar">
                            <div class="timeline-fill" style="width: ${(daysElapsed / 90) * 100}%"></div>
                        </div>
                    </div>
                    <div class="timeline-next">
                        <strong>Next milestone:</strong> ${this.getNextMilestone(disclosure, daysElapsed)}
                    </div>
                </div>
            `;
        }).join('');
    }

    getNextMilestone(disclosure, daysElapsed) {
        if (daysElapsed < 30) return `First follow-up (Day 30)`;
        if (daysElapsed < 60) return `Escalation (Day 60)`;
        if (daysElapsed < 90) return `Public disclosure consideration (Day 90)`;
        return 'Timeline exceeded - Public disclosure eligible';
    }

    initializeCharts() {
        // Severity Chart
        const severityCtx = document.getElementById('severity-chart');
        if (severityCtx) {
            this.severityChart = new Chart(severityCtx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#DC2626', '#EA580C', '#D97706', '#16A34A'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }

        // Timeline Chart
        const timelineCtx = document.getElementById('timeline-chart');
        if (timelineCtx) {
            this.timelineChart = new Chart(timelineCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                    datasets: [{
                        label: 'New Findings',
                        data: [0, 0, 0, 0],
                        borderColor: '#1FB8CD',
                        backgroundColor: 'rgba(31, 184, 205, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Resolved',
                        data: [0, 0, 0, 0],
                        borderColor: '#FFC185',
                        backgroundColor: 'rgba(255, 193, 133, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }

    updateDashboard() {
        // Update stats
        const totalFindingsEl = document.getElementById('total-findings');
        const activeDisclosuresEl = document.getElementById('active-disclosures');
        const resolvedIssuesEl = document.getElementById('resolved-issues');
        const avgResponseTimeEl = document.getElementById('avg-response-time');

        if (totalFindingsEl) totalFindingsEl.textContent = this.findings.length;
        if (activeDisclosuresEl) activeDisclosuresEl.textContent = this.disclosures.filter(d => d.status !== 'resolved').length;
        if (resolvedIssuesEl) resolvedIssuesEl.textContent = this.disclosures.filter(d => d.status === 'resolved').length;
        
        // Calculate average response time (mock data)
        const avgResponse = this.disclosures.length > 0 ? '3.2 days' : '--';
        if (avgResponseTimeEl) avgResponseTimeEl.textContent = avgResponse;

        // Update severity chart
        if (this.severityChart) {
            const severityCounts = [0, 0, 0, 0];
            this.findings.forEach(finding => {
                switch (finding.severity) {
                    case 'critical': severityCounts[0]++; break;
                    case 'high': severityCounts[1]++; break;
                    case 'medium': severityCounts[2]++; break;
                    case 'low': severityCounts[3]++; break;
                }
            });
            
            this.severityChart.data.datasets[0].data = severityCounts;
            this.severityChart.update();
        }
    }

    addActivity(message) {
        const activity = {
            id: Date.now(),
            message: message,
            timestamp: new Date()
        };
        
        this.activities.unshift(activity);
        
        // Keep only last 10 activities
        if (this.activities.length > 10) {
            this.activities = this.activities.slice(0, 10);
        }
        
        this.renderActivities();
    }

    renderActivities() {
        const container = document.getElementById('activity-list');
        if (!container) return;
        
        container.innerHTML = this.activities.map(activity => `
            <div class="activity-item">
                <div class="activity-icon">🔍</div>
                <div class="activity-content">
                    <div class="activity-title">${activity.message}</div>
                    <div class="activity-time">${this.getRelativeTime(activity.timestamp)}</div>
                </div>
            </div>
        `).join('');
    }

    getRelativeTime(date) {
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);

        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        return `${days}d ago`;
    }

    closeModal() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.add('hidden');
        });
        this.currentFinding = null;
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification--${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--color-${type === 'error' ? 'error' : type === 'success' ? 'success' : 'info'});
            color: white;
            padding: var(--space-12) var(--space-16);
            border-radius: var(--radius-base);
            z-index: 1100;
            animation: slideIn 0.3s ease;
            box-shadow: var(--shadow-lg);
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }, 3000);
    }

    truncateText(text, maxLength) {
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .detail-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: var(--space-12);
        margin-bottom: var(--space-16);
    }
    
    .timeline-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: var(--space-12);
    }
    
    .timeline-status {
        background: var(--color-primary);
        color: var(--color-btn-primary-text);
        padding: var(--space-4) var(--space-8);
        border-radius: var(--radius-sm);
        font-size: var(--font-size-xs);
        text-transform: capitalize;
    }
    
    .timeline-progress {
        margin-bottom: var(--space-12);
    }
    
    .timeline-days {
        font-size: var(--font-size-sm);
        color: var(--color-text-secondary);
        margin-bottom: var(--space-8);
    }
    
    .timeline-bar {
        height: 8px;
        background: var(--color-secondary);
        border-radius: var(--radius-full);
        overflow: hidden;
    }
    
    .timeline-fill {
        height: 100%;
        background: var(--color-primary);
        transition: width var(--duration-normal) var(--ease-standard);
    }
    
    .timeline-next {
        font-size: var(--font-size-sm);
        color: var(--color-text-secondary);
    }
`;
document.head.appendChild(style);

// Global app instance
let app;

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    app = new SecureDiscloseApp();
    
    // Make app globally available
    window.app = app;
});