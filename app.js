// Enhanced SecureDisclose - Professional Security Research Platform

class SecureDiscloseApp {
    constructor() {
        // Application data storage
        this.findings = [];
        this.disclosures = [];
        this.activities = [];
        this.selectedCompanies = [];
        this.currentFinding = null;
        this.currentCompany = null;
        
        // Top 50 companies database from application data
        this.top50Companies = [
            {
                id: 1, name: "Microsoft", domain: "microsoft.com", github_org: "microsoft", 
                industry: "Technology", market_cap: "$3.0T",
                security_contacts: {
                    primary: "https://www.microsoft.com/en-us/msrc",
                    email: "secure@microsoft.com",
                    bug_bounty: "https://www.microsoft.com/en-us/msrc/bounty"
                },
                has_bug_bounty: true, response_time: "24-48 hours",
                disclosure_policy: "https://www.microsoft.com/en-us/msrc/cvd",
                notes: "Very responsive, excellent security team, comprehensive bug bounty program"
            },
            {
                id: 2, name: "Apple", domain: "apple.com", github_org: "apple",
                industry: "Technology", market_cap: "$3.5T",
                security_contacts: {
                    primary: "https://support.apple.com/en-us/HT201220",
                    email: "product-security@apple.com",
                    bug_bounty: "https://developer.apple.com/security-bounty/"
                },
                has_bug_bounty: true, response_time: "24-72 hours",
                disclosure_policy: "https://support.apple.com/en-us/HT201220",
                notes: "High-quality security program, selective bug bounty by invitation"
            },
            {
                id: 3, name: "Alphabet (Google)", domain: "google.com", github_org: "google",
                industry: "Technology", market_cap: "$2.1T",
                security_contacts: {
                    primary: "https://bughunters.google.com/",
                    email: "security@google.com",
                    bug_bounty: "https://bughunters.google.com/"
                },
                has_bug_bounty: true, response_time: "24-72 hours",
                disclosure_policy: "https://about.google/appsecurity/",
                notes: "Mature program, detailed guidelines, Google VRP pioneer"
            },
            {
                id: 4, name: "Amazon", domain: "amazon.com", github_org: "aws",
                industry: "E-commerce/Cloud", market_cap: "$1.6T",
                security_contacts: {
                    primary: "https://aws.amazon.com/security/vulnerability-reporting/",
                    email: "aws-security@amazon.com",
                    bug_bounty: "https://bugbounty.aws/"
                },
                has_bug_bounty: true, response_time: "24-72 hours",
                disclosure_policy: "https://aws.amazon.com/security/vulnerability-reporting/",
                notes: "Separate programs for AWS vs retail, very professional"
            },
            {
                id: 5, name: "Meta (Facebook)", domain: "meta.com", github_org: "facebook",
                industry: "Social Media", market_cap: "$1.3T",
                security_contacts: {
                    primary: "https://www.facebook.com/whitehat",
                    email: "security@fb.com",
                    bug_bounty: "https://www.facebook.com/whitehat"
                },
                has_bug_bounty: true, response_time: "48-96 hours",
                disclosure_policy: "https://www.facebook.com/whitehat/policy",
                notes: "Well-established program, good communication, covers Instagram/WhatsApp"
            },
            {
                id: 6, name: "Tesla", domain: "tesla.com", github_org: "teslamotors",
                industry: "Automotive/Energy", market_cap: "$800B",
                security_contacts: {
                    primary: "https://bugcrowd.com/tesla",
                    email: "security@tesla.com",
                    bug_bounty: "https://bugcrowd.com/tesla"
                },
                has_bug_bounty: true, response_time: "48-96 hours",
                disclosure_policy: "https://www.tesla.com/about/security",
                notes: "Active on Bugcrowd, covers vehicle security, innovative approach"
            },
            {
                id: 7, name: "NVIDIA", domain: "nvidia.com", github_org: "nvidia",
                industry: "Technology/AI", market_cap: "$3.2T",
                security_contacts: {
                    primary: "https://www.nvidia.com/en-us/security/",
                    email: "psirt@nvidia.com",
                    bug_bounty: "https://hackerone.com/nvidia"
                },
                has_bug_bounty: true, response_time: "24-72 hours",
                disclosure_policy: "https://www.nvidia.com/en-us/security/",
                notes: "Growing program, AI/GPU focus, professional team"
            },
            {
                id: 8, name: "Netflix", domain: "netflix.com", github_org: "netflix",
                industry: "Entertainment/Streaming", market_cap: "$200B",
                security_contacts: {
                    primary: "https://hackerone.com/netflix",
                    email: "security@netflix.com",
                    bug_bounty: "https://hackerone.com/netflix"
                },
                has_bug_bounty: true, response_time: "24-72 hours",
                disclosure_policy: "https://help.netflix.com/legal/security",
                notes: "Excellent program, responsive team, open source contributor"
            },
            {
                id: 9, name: "Uber", domain: "uber.com", github_org: "uber",
                industry: "Transportation/Technology", market_cap: "$150B",
                security_contacts: {
                    primary: "https://hackerone.com/uber",
                    email: "security-reports@uber.com",
                    bug_bounty: "https://hackerone.com/uber"
                },
                has_bug_bounty: true, response_time: "24-48 hours",
                disclosure_policy: "https://www.uber.com/us/en/about/security/",
                notes: "Pioneer in bug bounties, very responsive, comprehensive scope"
            },
            {
                id: 10, name: "Airbnb", domain: "airbnb.com", github_org: "airbnb",
                industry: "Hospitality/Technology", market_cap: "$80B",
                security_contacts: {
                    primary: "https://hackerone.com/airbnb",
                    email: "security@airbnb.com",
                    bug_bounty: "https://hackerone.com/airbnb"
                },
                has_bug_bounty: true, response_time: "24-72 hours",
                disclosure_policy: "https://www.airbnb.com/help/article/2855",
                notes: "Active program, good payouts, responsive communication"
            }
        ];

        // Add more companies to reach 50
        this.top50Companies = this.top50Companies.concat([
            { id: 11, name: "Shopify", domain: "shopify.com", github_org: "shopify", industry: "E-commerce/Cloud", market_cap: "$100B", security_contacts: { primary: "https://hackerone.com/shopify", email: "security@shopify.com", bug_bounty: "https://hackerone.com/shopify" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://www.shopify.com/security/responsible-disclosure-policy", notes: "E-commerce focused, good researcher relations" },
            { id: 12, name: "Stripe", domain: "stripe.com", github_org: "stripe", industry: "Financial Technology", market_cap: "$95B", security_contacts: { primary: "https://hackerone.com/stripe", email: "security@stripe.com", bug_bounty: "https://hackerone.com/stripe" }, has_bug_bounty: true, response_time: "24-48 hours", disclosure_policy: "https://stripe.com/docs/security", notes: "Payment security focus, excellent response times" },
            { id: 13, name: "Slack", domain: "slack.com", github_org: "slackhq", industry: "Technology", market_cap: "$50B", security_contacts: { primary: "https://hackerone.com/slack", email: "security@slack.com", bug_bounty: "https://hackerone.com/slack" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://slack.com/security-policy", notes: "Enterprise communication security, responsive team" },
            { id: 14, name: "Dropbox", domain: "dropbox.com", github_org: "dropbox", industry: "Technology", market_cap: "$25B", security_contacts: { primary: "https://hackerone.com/dropbox", email: "security@dropbox.com", bug_bounty: "https://hackerone.com/dropbox" }, has_bug_bounty: true, response_time: "48-72 hours", disclosure_policy: "https://www.dropbox.com/security", notes: "File storage security, mature program" },
            { id: 15, name: "GitHub", domain: "github.com", github_org: "github", industry: "Technology", market_cap: "$60B", security_contacts: { primary: "https://bounty.github.com/", email: "security@github.com", bug_bounty: "https://bounty.github.com/" }, has_bug_bounty: true, response_time: "24-48 hours", disclosure_policy: "https://github.com/security", notes: "Code security focus, excellent researcher experience" },
            { id: 16, name: "Twitter", domain: "twitter.com", github_org: "twitter", industry: "Social Media", market_cap: "$40B", security_contacts: { primary: "https://hackerone.com/twitter", email: "security@twitter.com", bug_bounty: "https://hackerone.com/twitter" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://help.twitter.com/en/rules-and-policies/twitter-report-violation", notes: "Social platform security, variable response times" },
            { id: 17, name: "PayPal", domain: "paypal.com", github_org: "paypal", industry: "Financial Technology", market_cap: "$120B", security_contacts: { primary: "https://www.paypal.com/us/smarthelp/article/how-do-i-report-security-issues-to-paypal-ts1236", email: "security@paypal.com", bug_bounty: "https://www.paypal.com/us/webapps/mpp/security-tools/reporting-security-issues" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://www.paypal.com/security", notes: "Financial security expertise, comprehensive program" },
            { id: 18, name: "Adobe", domain: "adobe.com", github_org: "adobe", industry: "Technology", market_cap: "$200B", security_contacts: { primary: "https://www.adobe.com/security.html", email: "psirt@adobe.com", bug_bounty: "https://www.adobe.com/security.html" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://www.adobe.com/security.html", notes: "Creative software security, established PSIRT" },
            { id: 19, name: "Salesforce", domain: "salesforce.com", github_org: "salesforce", industry: "Technology", market_cap: "$180B", security_contacts: { primary: "https://www.salesforce.com/company/disclosure/", email: "security@salesforce.com", bug_bounty: "https://www.salesforce.com/company/disclosure/" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://www.salesforce.com/company/disclosure/", notes: "CRM security focus, enterprise-grade program" },
            { id: 20, name: "Oracle", domain: "oracle.com", github_org: "oracle", industry: "Technology", market_cap: "$300B", security_contacts: { primary: "https://www.oracle.com/corporate/security-practices/assurance/vulnerability/reporting.html", email: "secalert_us@oracle.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.oracle.com/corporate/security-practices/", notes: "Enterprise software, traditional disclosure process" },
            { id: 21, name: "IBM", domain: "ibm.com", github_org: "ibm", industry: "Technology", market_cap: "$120B", security_contacts: { primary: "https://www.ibm.com/trust/security-psirt", email: "psirt@ibm.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.ibm.com/trust/security-psirt", notes: "Enterprise technology, formal PSIRT process" },
            { id: 22, name: "Cisco", domain: "cisco.com", github_org: "cisco", industry: "Technology", market_cap: "$200B", security_contacts: { primary: "https://tools.cisco.com/security/center/requestResponse.x", email: "psirt@cisco.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "48-96 hours", disclosure_policy: "https://www.cisco.com/c/en/us/about/security-center/security-vulnerability-policy.html", notes: "Network security expertise, mature PSIRT" },
            { id: 23, name: "Intel", domain: "intel.com", github_org: "intel", industry: "Technology", market_cap: "$150B", security_contacts: { primary: "https://www.intel.com/content/www/us/en/security-center/default.html", email: "secure@intel.com", bug_bounty: "https://www.intel.com/content/www/us/en/security-center/bug-bounty-program.html" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://www.intel.com/security", notes: "Hardware security focus, comprehensive disclosure process" },
            { id: 24, name: "AMD", domain: "amd.com", github_org: "amd", industry: "Technology", market_cap: "$200B", security_contacts: { primary: "https://www.amd.com/en/corporate/security", email: "security@amd.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.amd.com/en/corporate/security", notes: "Hardware security, traditional disclosure model" },
            { id: 25, name: "Zoom", domain: "zoom.us", github_org: "zoom", industry: "Technology", market_cap: "$30B", security_contacts: { primary: "https://explore.zoom.us/en/trust/security/security-bulletin/", email: "security@zoom.us", bug_bounty: "https://hackerone.com/zoom" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://zoom.us/security", notes: "Video communication security, improved program post-2020" },
            { id: 26, name: "Square", domain: "squareup.com", github_org: "square", industry: "Financial Technology", market_cap: "$40B", security_contacts: { primary: "https://hackerone.com/square", email: "security@squareup.com", bug_bounty: "https://hackerone.com/square" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://squareup.com/security", notes: "Payment processing security, active program" },
            { id: 27, name: "Snapchat", domain: "snapchat.com", github_org: "snapchat", industry: "Social Media", market_cap: "$20B", security_contacts: { primary: "https://hackerone.com/snapchat", email: "security@snap.com", bug_bounty: "https://hackerone.com/snapchat" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://snap.com/en-US/privacy/report-infringement/", notes: "Mobile-first security, privacy focused" },
            { id: 28, name: "Reddit", domain: "reddit.com", github_org: "reddit", industry: "Social Media", market_cap: "$15B", security_contacts: { primary: "https://hackerone.com/reddit", email: "security@reddit.com", bug_bounty: "https://hackerone.com/reddit" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://www.redditinc.com/policies/security-reporting", notes: "Community platform security, responsive team" },
            { id: 29, name: "TikTok", domain: "tiktok.com", github_org: "tiktok", industry: "Social Media", market_cap: "$100B", security_contacts: { primary: "https://www.tiktok.com/safety/report-a-problem", email: "security@tiktok.com", bug_bounty: "https://www.tiktok.com/safety/report-a-problem" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://www.tiktok.com/legal/report-vulnerability", notes: "Video platform security, international considerations" },
            { id: 30, name: "Pinterest", domain: "pinterest.com", github_org: "pinterest", industry: "Social Media", market_cap: "$25B", security_contacts: { primary: "https://hackerone.com/pinterest", email: "security@pinterest.com", bug_bounty: "https://hackerone.com/pinterest" }, has_bug_bounty: true, response_time: "48-72 hours", disclosure_policy: "https://policy.pinterest.com/en/report-copyright-infringement", notes: "Visual discovery platform, solid security program" },
            { id: 31, name: "Lyft", domain: "lyft.com", github_org: "lyft", industry: "Transportation/Technology", market_cap: "$15B", security_contacts: { primary: "https://www.lyft.com/security", email: "security@lyft.com", bug_bounty: "https://www.lyft.com/security" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://www.lyft.com/security", notes: "Rideshare security, growing program" },
            { id: 32, name: "DoorDash", domain: "doordash.com", github_org: "doordash", industry: "Technology", market_cap: "$50B", security_contacts: { primary: "https://hackerone.com/doordash", email: "security@doordash.com", bug_bounty: "https://hackerone.com/doordash" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://help.doordash.com/dashers/s/article/Dasher-Privacy-and-Data-Protection", notes: "Food delivery security, active on HackerOne" },
            { id: 33, name: "Spotify", domain: "spotify.com", github_org: "spotify", industry: "Entertainment/Streaming", market_cap: "$30B", security_contacts: { primary: "https://hackerone.com/spotify", email: "security@spotify.com", bug_bounty: "https://hackerone.com/spotify" }, has_bug_bounty: true, response_time: "48-72 hours", disclosure_policy: "https://www.spotify.com/us/legal/privacy-policy/", notes: "Music streaming security, European-based program" },
            { id: 34, name: "Twitch", domain: "twitch.tv", github_org: "twitchtv", industry: "Entertainment/Streaming", market_cap: "$15B", security_contacts: { primary: "https://hackerone.com/twitch", email: "security@twitch.tv", bug_bounty: "https://hackerone.com/twitch" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://safety.twitch.tv/s/", notes: "Live streaming security, part of Amazon ecosystem" },
            { id: 35, name: "Discord", domain: "discord.com", github_org: "discord", industry: "Technology", market_cap: "$15B", security_contacts: { primary: "https://hackerone.com/discord", email: "security@discord.com", bug_bounty: "https://hackerone.com/discord" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://discord.com/safety", notes: "Gaming communication platform, active security team" },
            { id: 36, name: "Roblox", domain: "roblox.com", github_org: "roblox", industry: "Technology", market_cap: "$40B", security_contacts: { primary: "https://hackerone.com/roblox", email: "security@roblox.com", bug_bounty: "https://hackerone.com/roblox" }, has_bug_bounty: true, response_time: "48-96 hours", disclosure_policy: "https://en.help.roblox.com/hc/en-us/articles/203313410", notes: "Gaming platform security, child safety focus" },
            { id: 37, name: "Coinbase", domain: "coinbase.com", github_org: "coinbase", industry: "Financial Technology", market_cap: "$20B", security_contacts: { primary: "https://hackerone.com/coinbase", email: "security@coinbase.com", bug_bounty: "https://hackerone.com/coinbase" }, has_bug_bounty: true, response_time: "24-48 hours", disclosure_policy: "https://help.coinbase.com/en/coinbase/other-topics/legal-policies/how-is-coinbase-insured", notes: "Cryptocurrency security, high-value targets" },
            { id: 38, name: "Robinhood", domain: "robinhood.com", github_org: "robinhoodmarkets", industry: "Financial Technology", market_cap: "$10B", security_contacts: { primary: "https://hackerone.com/robinhood", email: "security@robinhood.com", bug_bounty: "https://hackerone.com/robinhood" }, has_bug_bounty: true, response_time: "48-72 hours", disclosure_policy: "https://robinhood.com/us/en/support/articles/how-we-protect-your-account/", notes: "Trading platform security, financial regulations" },
            { id: 39, name: "Atlassian", domain: "atlassian.com", github_org: "atlassian", industry: "Technology", market_cap: "$50B", security_contacts: { primary: "https://www.atlassian.com/trust/security/report-a-vulnerability", email: "security@atlassian.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "48-96 hours", disclosure_policy: "https://www.atlassian.com/trust/security", notes: "Development tools security, enterprise focus" },
            { id: 40, name: "MongoDB", domain: "mongodb.com", github_org: "mongodb", industry: "Technology", market_cap: "$25B", security_contacts: { primary: "https://www.mongodb.com/security", email: "security@mongodb.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.mongodb.com/security", notes: "Database security, enterprise customers" },
            { id: 41, name: "ServiceNow", domain: "servicenow.com", github_org: "servicenow", industry: "Technology", market_cap: "$120B", security_contacts: { primary: "https://www.servicenow.com/company/trust/security-incident-response.html", email: "security@servicenow.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.servicenow.com/company/trust/", notes: "Enterprise software, traditional security approach" },
            { id: 42, name: "Workday", domain: "workday.com", github_org: "workday", industry: "Technology", market_cap: "$60B", security_contacts: { primary: "https://www.workday.com/en-us/company/trust-and-security.html", email: "security@workday.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.workday.com/en-us/company/trust-and-security.html", notes: "HR software security, enterprise compliance" },
            { id: 43, name: "Splunk", domain: "splunk.com", github_org: "splunk", industry: "Cybersecurity", market_cap: "$20B", security_contacts: { primary: "https://www.splunk.com/en_us/legal/splunk-responsible-disclosure-policy.html", email: "security@splunk.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "48-96 hours", disclosure_policy: "https://www.splunk.com/en_us/legal/splunk-responsible-disclosure-policy.html", notes: "Security analytics company, professional response" },
            { id: 44, name: "Okta", domain: "okta.com", github_org: "okta", industry: "Cybersecurity", market_cap: "$15B", security_contacts: { primary: "https://www.okta.com/security/", email: "security@okta.com", bug_bounty: "https://www.okta.com/security/" }, has_bug_bounty: true, response_time: "24-72 hours", disclosure_policy: "https://www.okta.com/security/", notes: "Identity security company, comprehensive program" },
            { id: 45, name: "CrowdStrike", domain: "crowdstrike.com", github_org: "crowdstrike", industry: "Cybersecurity", market_cap: "$60B", security_contacts: { primary: "https://www.crowdstrike.com/resources/data-security/", email: "security@crowdstrike.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "48-96 hours", disclosure_policy: "https://www.crowdstrike.com/resources/data-security/", notes: "Cybersecurity company, security-first approach" },
            { id: 46, name: "Palo Alto Networks", domain: "paloaltonetworks.com", github_org: "paloaltonetworks", industry: "Cybersecurity", market_cap: "$100B", security_contacts: { primary: "https://security.paloaltonetworks.com/", email: "psirt@paloaltonetworks.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "48-96 hours", disclosure_policy: "https://security.paloaltonetworks.com/", notes: "Network security company, mature PSIRT" },
            { id: 47, name: "Fortinet", domain: "fortinet.com", github_org: "fortinet", industry: "Cybersecurity", market_cap: "$50B", security_contacts: { primary: "https://www.fortiguard.com/psirt", email: "psirt@fortinet.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "48-96 hours", disclosure_policy: "https://www.fortiguard.com/psirt", notes: "Security appliances, established PSIRT process" },
            { id: 48, name: "Zscaler", domain: "zscaler.com", github_org: "zscaler", industry: "Cybersecurity", market_cap: "$30B", security_contacts: { primary: "https://www.zscaler.com/security", email: "security@zscaler.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.zscaler.com/security", notes: "Cloud security company, enterprise focus" },
            { id: 49, name: "Datadog", domain: "datadoghq.com", github_org: "datadog", industry: "Technology", market_cap: "$35B", security_contacts: { primary: "https://www.datadoghq.com/security/", email: "security@datadoghq.com", bug_bounty: "https://hackerone.com/datadog" }, has_bug_bounty: true, response_time: "48-72 hours", disclosure_policy: "https://www.datadoghq.com/security/", notes: "Monitoring platform, solid security team" },
            { id: 50, name: "Snowflake", domain: "snowflake.com", github_org: "snowflakedb", industry: "Technology", market_cap: "$60B", security_contacts: { primary: "https://www.snowflake.com/legal/security-vulnerability-policy/", email: "security@snowflake.com", bug_bounty: "N/A" }, has_bug_bounty: false, response_time: "72-120 hours", disclosure_policy: "https://www.snowflake.com/legal/security-vulnerability-policy/", notes: "Data warehouse security, enterprise compliance focus" }
        ]);

        // Enhanced PII patterns
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
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            phone: /\b(?:\+?1[-\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-\s]?\d{3}[-\s]?\d{4}\b/g,
            ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
        };

        this.severityMapping = {
            ssn: 'critical', credit_card: 'critical', aws_access_key: 'critical',
            github_token: 'critical', private_key: 'critical', jwt_token: 'critical',
            api_key: 'high', database_url: 'high', password: 'high',
            email: 'medium', phone: 'medium', ipv4: 'low'
        };

        // Enhanced report templates
        this.reportTemplates = {
            initial_disclosure: {
                subject: "Security Vulnerability Disclosure - PII Exposure in {organization} Repository",
                content: `Subject: Security Vulnerability Disclosure - PII Exposure in {organization} Repository

Dear {organization} Security Team,

EXECUTIVE SUMMARY
We have identified a critical security vulnerability involving the exposure of personally identifiable information (PII) and sensitive data in one of your public repositories. This disclosure follows responsible security research practices and our 90-day disclosure timeline.

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
- Result in regulatory compliance violations (GDPR, CCPA, HIPAA)
- Damage organizational reputation and customer trust

AFFECTED DATA
{findings_details}

REMEDIATION RECOMMENDATIONS
1. Immediately remove sensitive data from the repository
2. Rotate any exposed credentials, API keys, or tokens
3. Review repository history and clean using tools like BFG Repo-Cleaner
4. Implement pre-commit hooks to prevent future exposures
5. Consider using environment variables or secret management systems
6. Conduct security awareness training for development teams

RESPONSIBLE DISCLOSURE TIMELINE
We follow industry-standard responsible disclosure practices:
- Day 0: Initial notification (today)
- Day 30: First follow-up if no response received
- Day 60: Escalation notice to additional contacts
- Day 90: Public disclosure consideration

We are committed to working collaboratively with your security team to resolve this issue promptly and professionally. We can provide additional technical details, proof-of-concept demonstrations, or remediation assistance as needed.

Best regards,
Security Research Team
SecureDisclose Platform
Contact: researcher@securedisclose.com`
            },
            bulk_report: {
                subject: "Multi-Company Security Research Campaign Summary",
                content: `SECURITY RESEARCH CAMPAIGN SUMMARY

Campaign ID: {campaign_id}
Date Range: {date_range}
Companies Analyzed: {company_count}
Total Findings: {total_findings}

EXECUTIVE SUMMARY
This report summarizes findings from a comprehensive security research campaign across {company_count} major technology companies. The campaign focused on identifying PII exposures and sensitive data leaks in public repositories.

METHODOLOGY
- Automated scanning of public GitHub repositories
- Pattern matching for sensitive data types
- Manual verification of findings
- Risk assessment and impact analysis
- Responsible disclosure process initiation

FINDINGS BREAKDOWN
Critical Severity: {critical_count}
High Severity: {high_count}  
Medium Severity: {medium_count}
Low Severity: {low_count}

TOP FINDINGS BY COMPANY
{company_findings_summary}

INDUSTRY ANALYSIS
{industry_breakdown}

DISCLOSURE STATUS
- Disclosed: {disclosed_count}
- Pending Response: {pending_count}
- Resolved: {resolved_count}
- Public Consideration: {public_count}

RECOMMENDATIONS FOR INDUSTRY
1. Implement automated secret scanning in CI/CD pipelines
2. Enhance developer security training programs
3. Establish clear responsible disclosure policies
4. Improve security contact accessibility
5. Consider bug bounty programs for continuous assessment

This comprehensive analysis demonstrates the ongoing challenges of preventing sensitive data exposure in public repositories and highlights the importance of proactive security measures.

Generated by SecureDisclose Platform`
            }
        };

        // Scanning state
        this.isScanning = false;
        this.scanProgress = 0;
        this.liveCounts = { critical: 0, high: 0, medium: 0, low: 0 };

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeCharts();
        this.renderCompanies();
        this.updateDashboard();
        this.addActivity('Platform initialized with Top 50 companies database');
    }

    setupEventListeners() {
        // Navigation
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

        // Quick company selection
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('quick-company-btn')) {
                e.preventDefault();
                e.stopPropagation();
                const category = e.target.dataset.companies;
                this.selectCompanyCategory(category);
            }
        });

        // Discovery controls
        const startDiscoveryBtn = document.getElementById('start-discovery-btn');
        if (startDiscoveryBtn) {
            startDiscoveryBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.startDiscovery();
            });
        }

        // Company filters
        const companySearch = document.getElementById('company-search');
        if (companySearch) {
            companySearch.addEventListener('input', () => this.filterCompanies());
        }

        const industryFilter = document.getElementById('industry-filter');
        if (industryFilter) {
            industryFilter.addEventListener('change', () => this.filterCompanies());
        }

        const bountyFilter = document.getElementById('bounty-filter');
        if (bountyFilter) {
            bountyFilter.addEventListener('change', () => this.filterCompanies());
        }

        const responseFilter = document.getElementById('response-filter');
        if (responseFilter) {
            responseFilter.addEventListener('change', () => this.filterCompanies());
        }

        // View toggle
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('view-btn')) {
                e.preventDefault();
                e.stopPropagation();
                const view = e.target.dataset.view;
                this.toggleView(view);
            }
        });

        // Findings filters
        const severityFilter = document.getElementById('severity-filter');
        if (severityFilter) {
            severityFilter.addEventListener('change', () => this.filterFindings());
        }

        const statusFilter = document.getElementById('status-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', () => this.filterFindings());
        }

        const companyFilter = document.getElementById('company-filter');
        if (companyFilter) {
            companyFilter.addEventListener('input', () => this.filterFindings());
        }

        // Template selection
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

        // Company card clicks
        document.addEventListener('click', (e) => {
            if (e.target.closest('.company-card')) {
                e.preventDefault();
                e.stopPropagation();
                const companyElement = e.target.closest('.company-card');
                const companyId = companyElement.dataset.companyId;
                if (companyId) {
                    this.showCompanyDetails(parseInt(companyId));
                }
            }
        });
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

        // Section-specific updates
        if (sectionName === 'companies') {
            this.renderCompanies();
        } else if (sectionName === 'findings') {
            this.renderFindings();
        } else if (sectionName === 'timeline') {
            this.renderTimeline();
        }
    }

    selectCompanyCategory(category) {
        let companies = [];
        
        switch (category) {
            case 'tech-giants':
                companies = this.top50Companies.filter(c => 
                    ['Microsoft', 'Apple', 'Alphabet (Google)', 'Amazon', 'Meta (Facebook)', 'NVIDIA'].includes(c.name)
                );
                break;
            case 'financial':
                companies = this.top50Companies.filter(c => 
                    c.industry === 'Financial Technology'
                );
                break;
            case 'bug-bounty':
                companies = this.top50Companies.filter(c => c.has_bug_bounty);
                break;
            case 'responsive':
                companies = this.top50Companies.filter(c => 
                    c.response_time.includes('24-48') || c.response_time.includes('24-72')
                );
                break;
        }

        this.selectedCompanies = companies;
        this.updateSelectedCompanies();
        
        // Update button states
        document.querySelectorAll('.quick-company-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-companies="${category}"]`).classList.add('active');
        
        this.addActivity(`Selected ${companies.length} companies from ${category} category`);
    }

    updateSelectedCompanies() {
        const container = document.getElementById('selected-companies');
        if (!container) return;

        if (this.selectedCompanies.length === 0) {
            container.innerHTML = '<span class="placeholder">No companies selected</span>';
        } else {
            container.innerHTML = this.selectedCompanies.map(company => `
                <span class="company-tag">
                    ${company.name}
                    <span class="remove" onclick="window.app.removeSelectedCompany(${company.id})">&times;</span>
                </span>
            `).join('');
        }
    }

    removeSelectedCompany(companyId) {
        this.selectedCompanies = this.selectedCompanies.filter(c => c.id !== companyId);
        this.updateSelectedCompanies();
        
        // Update quick buttons
        document.querySelectorAll('.quick-company-btn').forEach(btn => {
            btn.classList.remove('active');
        });
    }

    async startDiscovery() {
        if (this.selectedCompanies.length === 0) {
            this.showNotification('Please select companies for scanning', 'error');
            return;
        }

        const scanDepth = document.getElementById('scan-depth').value;
        const priorityMode = document.getElementById('priority-mode').value;
        const selectedTypes = this.getSelectedPiiTypes();

        if (selectedTypes.length === 0) {
            this.showNotification('Please select at least one PII category', 'error');
            return;
        }

        this.isScanning = true;
        this.scanProgress = 0;
        this.liveCounts = { critical: 0, high: 0, medium: 0, low: 0 };

        const progressSection = document.getElementById('scan-progress');
        if (progressSection) {
            progressSection.classList.remove('hidden');
        }

        const startBtn = document.getElementById('start-discovery-btn');
        if (startBtn) {
            startBtn.disabled = true;
            startBtn.innerHTML = '<span>🔍</span> Scanning...';
        }

        try {
            await this.performEnhancedDiscoveryScan(scanDepth, priorityMode, selectedTypes);
            this.addActivity(`Completed discovery campaign across ${this.selectedCompanies.length} companies`);
            this.showNotification(`Campaign completed! Found ${this.findings.length} potential exposures`, 'success');
        } catch (error) {
            this.showNotification(`Scan failed: ${error.message}`, 'error');
        } finally {
            this.isScanning = false;
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = '<span>🚀</span> Start Discovery Campaign';
            }
            this.updateDashboard();
        }
    }

    async performEnhancedDiscoveryScan(scanDepth, priorityMode, piiTypes) {
        const reposPerCompany = scanDepth === 'quick' ? 5 : scanDepth === 'thorough' ? 15 : 25;
        const filesPerRepo = scanDepth === 'quick' ? 10 : scanDepth === 'thorough' ? 20 : 50;
        
        let totalSteps = this.selectedCompanies.length * reposPerCompany * filesPerRepo;
        let currentStep = 0;

        // Update scan stats
        this.updateScanStats(this.selectedCompanies.length, 
            this.selectedCompanies.length * reposPerCompany, 
            totalSteps);

        for (const company of this.selectedCompanies) {
            if (!this.isScanning) break;

            const progressText = document.getElementById('progress-text');
            if (progressText) {
                progressText.textContent = `Scanning ${company.name} repositories...`;
            }

            await this.scanCompanyRepositories(company, reposPerCompany, filesPerRepo, piiTypes);
            
            currentStep += reposPerCompany * filesPerRepo;
            this.scanProgress = (currentStep / totalSteps) * 100;
            
            const progressFill = document.getElementById('progress-fill');
            if (progressFill) {
                progressFill.style.width = `${this.scanProgress}%`;
            }

            this.updateLiveFindings();
            await this.delay(1000);
        }

        const progressText = document.getElementById('progress-text');
        if (progressText) {
            progressText.textContent = `Campaign completed! Found ${this.findings.length} findings across ${this.selectedCompanies.length} companies.`;
        }
    }

    async scanCompanyRepositories(company, reposPerCompany, filesPerRepo, piiTypes) {
        const mockRepos = this.generateMockRepositories(company.github_org, reposPerCompany);
        
        for (const repo of mockRepos) {
            if (!this.isScanning) break;
            
            const mockFiles = this.generateMockFiles(filesPerRepo);
            for (const file of mockFiles) {
                if (!this.isScanning) break;
                
                const content = this.generateMockFileContent(file.name, company);
                await this.analyzeFileContent(company, repo, file.name, content, piiTypes);
                await this.delay(50);
            }
        }
    }

    generateMockRepositories(githubOrg, count) {
        const repoTypes = ['web-app', 'mobile-app', 'api', 'docs', 'config', 'tools', 'backend', 'frontend', 'scripts', 'infrastructure'];
        return Array.from({ length: count }, (_, i) => ({
            name: `${githubOrg}-${repoTypes[i % repoTypes.length]}-${i + 1}`,
            url: `https://github.com/${githubOrg}/${repoTypes[i % repoTypes.length]}-${i + 1}`
        }));
    }

    generateMockFiles(count) {
        const fileTypes = ['.env', 'config.json', 'database.yml', 'secrets.txt', 'app.properties', 
                          'settings.py', 'credentials.xml', 'keys.js', 'config.php', 'environment.rb'];
        return Array.from({ length: count }, (_, i) => ({
            name: `${fileTypes[i % fileTypes.length]}`,
            path: `src/${fileTypes[i % fileTypes.length]}`
        }));
    }

    generateMockFileContent(fileName, company) {
        const templates = {
            '.env': `DATABASE_URL=postgres://${company.name.toLowerCase()}:secretpass@db.${company.domain}:5432/prod
API_KEY=sk_live_${Math.random().toString(36).substr(2, 24)}
AWS_ACCESS_KEY=AKIA${Math.random().toString(36).substr(2, 16).toUpperCase()}
GITHUB_TOKEN=ghp_${Math.random().toString(36).substr(2, 36)}
ADMIN_EMAIL=admin@${company.domain}
STRIPE_KEY=sk_test_${Math.random().toString(36).substr(2, 24)}`,
            'config.json': `{
  "database": {
    "host": "${company.domain}",
    "password": "prod_${Math.random().toString(36).substr(2, 12)}",
    "api_key": "AKIA${Math.random().toString(36).substr(2, 16).toUpperCase()}"
  },
  "contacts": {
    "admin": "admin@${company.domain}",
    "security": "${company.security_contacts.email}",
    "phone": "555-${Math.floor(Math.random() * 1000)}-${Math.floor(Math.random() * 10000)}"
  }
}`,
            'database.yml': `production:
  host: db.${company.domain}
  password: "super_secret_${Math.random().toString(36).substr(2, 8)}"
  api_key: "AKIA${Math.random().toString(36).substr(2, 16).toUpperCase()}"
  admin_email: "admin@${company.domain}"`
        };
        
        return templates[fileName] || templates['.env'];
    }

    analyzeFileContent(company, repo, fileName, content, piiTypes) {
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
                        company: company.name,
                        companyId: company.id,
                        repository: repo.name,
                        file: fileName,
                        content: match,
                        context: this.getContext(content, match),
                        status: 'new',
                        discoveryDate: new Date().toISOString(),
                        timeline: {
                            discovered: new Date().toISOString()
                        },
                        responseTime: company.response_time,
                        securityContact: company.security_contacts.email,
                        hasBugBounty: company.has_bug_bounty
                    };
                    
                    this.findings.push(finding);
                    this.liveCounts[severity]++;
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

    getSelectedPiiTypes() {
        const checkboxes = document.querySelectorAll('.pii-categories-grid input[type="checkbox"]:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }

    updateScanStats(companies, repos, files) {
        const statsElements = {
            companies: document.getElementById('scan-companies'),
            repos: document.getElementById('scan-repos'),
            files: document.getElementById('scan-files')
        };

        if (statsElements.companies) statsElements.companies.textContent = `${companies} companies`;
        if (statsElements.repos) statsElements.repos.textContent = `${repos} repositories`;
        if (statsElements.files) statsElements.files.textContent = `${files} files`;
    }

    updateLiveFindings() {
        const counters = {
            critical: document.querySelector('.counter.critical'),
            high: document.querySelector('.counter.high'),
            medium: document.querySelector('.counter.medium'),
            low: document.querySelector('.counter.low')
        };

        Object.entries(counters).forEach(([severity, element]) => {
            if (element) {
                element.textContent = this.liveCounts[severity];
            }
        });
    }

    renderCompanies() {
        const container = document.getElementById('companies-container');
        if (!container) return;

        container.innerHTML = this.top50Companies.map(company => `
            <div class="company-card" data-company-id="${company.id}">
                <div class="company-header">
                    <div>
                        <div class="company-name">${company.name}</div>
                        <div class="company-domain">${company.domain}</div>
                    </div>
                    <div class="company-badges">
                        <span class="company-badge ${company.has_bug_bounty ? 'bounty' : 'no-bounty'}">
                            ${company.has_bug_bounty ? 'Bug Bounty' : 'No Program'}
                        </span>
                        ${company.response_time.includes('24-48') || company.response_time.includes('24-72') ? 
                            '<span class="company-badge fast-response">Fast Response</span>' : ''}
                    </div>
                </div>
                <div class="company-details">
                    <div class="company-info-grid">
                        <div class="info-item">
                            <span class="info-icon">🏭</span>
                            <span>${company.industry}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-icon">💰</span>
                            <span>${company.market_cap}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-icon">📧</span>
                            <span>${company.security_contacts.email}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-icon">⏱️</span>
                            <span>${company.response_time}</span>
                        </div>
                    </div>
                </div>
                <div class="company-footer">
                    ${company.notes}
                </div>
            </div>
        `).join('');

        this.updateCompanyCount(this.top50Companies.length);
    }

    filterCompanies() {
        const search = document.getElementById('company-search')?.value.toLowerCase() || '';
        const industry = document.getElementById('industry-filter')?.value || '';
        const bounty = document.getElementById('bounty-filter')?.value || '';
        const response = document.getElementById('response-filter')?.value || '';

        let filtered = this.top50Companies.filter(company => {
            const matchesSearch = company.name.toLowerCase().includes(search) ||
                                company.domain.toLowerCase().includes(search) ||
                                company.industry.toLowerCase().includes(search);
            const matchesIndustry = !industry || company.industry === industry;
            const matchesBounty = !bounty || company.has_bug_bounty.toString() === bounty;
            const matchesResponse = !response || company.response_time === response;

            return matchesSearch && matchesIndustry && matchesBounty && matchesResponse;
        });

        const container = document.getElementById('companies-container');
        if (!container) return;

        container.innerHTML = filtered.map(company => `
            <div class="company-card" data-company-id="${company.id}">
                <div class="company-header">
                    <div>
                        <div class="company-name">${company.name}</div>
                        <div class="company-domain">${company.domain}</div>
                    </div>
                    <div class="company-badges">
                        <span class="company-badge ${company.has_bug_bounty ? 'bounty' : 'no-bounty'}">
                            ${company.has_bug_bounty ? 'Bug Bounty' : 'No Program'}
                        </span>
                        ${company.response_time.includes('24-48') || company.response_time.includes('24-72') ? 
                            '<span class="company-badge fast-response">Fast Response</span>' : ''}
                    </div>
                </div>
                <div class="company-details">
                    <div class="company-info-grid">
                        <div class="info-item">
                            <span class="info-icon">🏭</span>
                            <span>${company.industry}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-icon">💰</span>
                            <span>${company.market_cap}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-icon">📧</span>
                            <span>${company.security_contacts.email}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-icon">⏱️</span>
                            <span>${company.response_time}</span>
                        </div>
                    </div>
                </div>
                <div class="company-footer">
                    ${company.notes}
                </div>
            </div>
        `).join('');

        this.updateCompanyCount(filtered.length);
    }

    updateCompanyCount(count) {
        const countElement = document.getElementById('company-count');
        if (countElement) {
            countElement.textContent = `${count} companies`;
        }
    }

    toggleView(view) {
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-view="${view}"]`).classList.add('active');

        const container = document.getElementById('companies-container');
        if (container) {
            container.className = view === 'grid' ? 'companies-grid' : 'companies-list';
        }
    }

    showCompanyDetails(companyId) {
        const company = this.top50Companies.find(c => c.id === companyId);
        if (!company) return;

        this.currentCompany = company;
        const modal = document.getElementById('company-modal');
        const title = document.getElementById('company-modal-title');
        const body = document.getElementById('company-modal-body');
        
        if (title) title.textContent = `${company.name} - Security Intelligence`;
        
        if (body) {
            body.innerHTML = `
                <div class="company-intelligence">
                    <div class="intel-section">
                        <h4>Company Overview</h4>
                        <div class="intel-grid">
                            <div class="intel-item">
                                <strong>Name:</strong> ${company.name}
                            </div>
                            <div class="intel-item">
                                <strong>Domain:</strong> ${company.domain}
                            </div>
                            <div class="intel-item">
                                <strong>Industry:</strong> ${company.industry}
                            </div>
                            <div class="intel-item">
                                <strong>Market Cap:</strong> ${company.market_cap}
                            </div>
                        </div>
                    </div>
                    
                    <div class="intel-section">
                        <h4>Security Program Details</h4>
                        <div class="intel-grid">
                            <div class="intel-item">
                                <strong>Bug Bounty:</strong> ${company.has_bug_bounty ? 'Yes' : 'No'}
                            </div>
                            <div class="intel-item">
                                <strong>Response Time:</strong> ${company.response_time}
                            </div>
                            <div class="intel-item">
                                <strong>GitHub Org:</strong> ${company.github_org}
                            </div>
                        </div>
                    </div>
                    
                    <div class="intel-section">
                        <h4>Security Contacts</h4>
                        <div class="contact-list">
                            <div class="contact-item">
                                <strong>Primary:</strong> <a href="${company.security_contacts.primary}" target="_blank">${company.security_contacts.primary}</a>
                            </div>
                            <div class="contact-item">
                                <strong>Email:</strong> <a href="mailto:${company.security_contacts.email}">${company.security_contacts.email}</a>
                            </div>
                            ${company.security_contacts.bug_bounty ? `
                            <div class="contact-item">
                                <strong>Bug Bounty:</strong> <a href="${company.security_contacts.bug_bounty}" target="_blank">${company.security_contacts.bug_bounty}</a>
                            </div>` : ''}
                        </div>
                    </div>
                    
                    <div class="intel-section">
                        <h4>Research Notes</h4>
                        <div class="notes-content">
                            ${company.notes}
                        </div>
                    </div>
                    
                    <div class="intel-section">
                        <h4>Disclosure Policy</h4>
                        <div class="policy-link">
                            <a href="${company.disclosure_policy}" target="_blank">${company.disclosure_policy}</a>
                        </div>
                    </div>
                </div>
            `;
        }

        if (modal) modal.classList.remove('hidden');
    }

    renderFindings() {
        const container = document.getElementById('findings-list');
        if (!container) return;
        
        if (this.findings.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <h3>No Findings Yet</h3>
                    <p>Start a discovery campaign to find PII exposures across company repositories</p>
                    <button class="btn btn--primary" onclick="window.app.showSection('discovery')">Start Discovery Campaign</button>
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
                    <div><strong>Company:</strong> ${finding.company}</div>
                    <div><strong>Repository:</strong> ${finding.repository}</div>
                    <div><strong>File:</strong> ${finding.file}</div>
                </div>
                <div class="finding-preview">${this.truncateText(finding.context, 150)}</div>
            </div>
        `).join('');

        this.updateFindingsAnalytics();
    }

    updateFindingsAnalytics() {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        this.findings.forEach(finding => {
            counts[finding.severity]++;
        });

        Object.entries(counts).forEach(([severity, count]) => {
            const element = document.getElementById(`${severity}-count`);
            if (element) element.textContent = count;
        });
    }

    filterFindings() {
        const severity = document.getElementById('severity-filter')?.value || '';
        const status = document.getElementById('status-filter')?.value || '';
        const company = document.getElementById('company-filter')?.value.toLowerCase() || '';

        let filtered = this.findings.filter(finding => {
            const matchesSeverity = !severity || finding.severity === severity;
            const matchesStatus = !status || finding.status === status;
            const matchesCompany = !company || finding.company.toLowerCase().includes(company);
            return matchesSeverity && matchesStatus && matchesCompany;
        });

        const container = document.getElementById('findings-list');
        if (!container) return;

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <h3>No Matching Findings</h3>
                    <p>Try adjusting your filters or starting a new discovery campaign</p>
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
                        <div><strong>Company:</strong> ${finding.company}</div>
                        <div><strong>Repository:</strong> ${finding.repository}</div>
                        <div><strong>File:</strong> ${finding.file}</div>
                    </div>
                    <div class="finding-preview">${this.truncateText(finding.context, 150)}</div>
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
        
        if (body) {
            body.innerHTML = `
                <div class="finding-details">
                    <div class="finding-summary">
                        <h4>${finding.piiType.replace(/_/g, ' ').toUpperCase()} Exposure</h4>
                        <div class="summary-badges">
                            <span class="finding-severity ${finding.severity}">${finding.severity}</span>
                            ${finding.hasBugBounty ? '<span class="program-badge">Bug Bounty Available</span>' : ''}
                        </div>
                    </div>
                    
                    <div class="detail-sections">
                        <div class="detail-section">
                            <h5>Company Information</h5>
                            <div class="detail-grid">
                                <div><strong>Company:</strong> ${finding.company}</div>
                                <div><strong>Security Contact:</strong> ${finding.securityContact}</div>
                                <div><strong>Response Time:</strong> ${finding.responseTime}</div>
                                <div><strong>Bug Bounty:</strong> ${finding.hasBugBounty ? 'Yes' : 'No'}</div>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h5>Technical Details</h5>
                            <div class="detail-grid">
                                <div><strong>Repository:</strong> ${finding.repository}</div>
                                <div><strong>File:</strong> ${finding.file}</div>
                                <div><strong>Discovery Date:</strong> ${new Date(finding.discoveryDate).toLocaleDateString()}</div>
                                <div><strong>Status:</strong> ${finding.status}</div>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h5>Exposed Content</h5>
                            <div class="content-preview">
                                <pre>${finding.context}</pre>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h5>Impact Assessment</h5>
                            <ul class="impact-list">
                                ${this.getImpactAssessment(finding.severity, finding.piiType)}
                            </ul>
                        </div>
                    </div>
                </div>
            `;
        }

        if (modal) modal.classList.remove('hidden');
    }

    getImpactAssessment(severity, piiType) {
        const impacts = {
            critical: [
                '<li>🔴 Immediate security risk - credentials or keys may be compromised</li>',
                '<li>🚨 Potential unauthorized access to systems and data</li>',
                '<li>⚖️ High regulatory compliance risk (GDPR, CCPA, HIPAA)</li>',
                '<li>📰 Significant reputational damage potential</li>',
                '<li>💰 Potential financial losses and penalties</li>'
            ],
            high: [
                '<li>🟠 Elevated security risk - sensitive data exposed</li>',
                '<li>🔓 Potential for account takeover or data access</li>',
                '<li>📋 Moderate regulatory compliance risk</li>',
                '<li>⚠️ Reputational damage potential</li>',
                '<li>🏢 Business continuity risk</li>'
            ],
            medium: [
                '<li>🟡 Privacy risk - personal information exposed</li>',
                '<li>📞 Potential for social engineering attacks</li>',
                '<li>🛡️ GDPR/privacy regulation concerns</li>',
                '<li>📊 Data analytics and profiling risks</li>',
                '<li>🤝 Minor reputational impact</li>'
            ],
            low: [
                '<li>🟢 Limited privacy risk</li>',
                '<li>🔍 Minimal security impact</li>',
                '<li>📝 Best practice violation</li>',
                '<li>🧹 Housekeeping issue</li>',
                '<li>📈 Informational finding</li>'
            ]
        };

        return impacts[severity].join('');
    }

    selectReportTemplate(templateType) {
        const template = this.reportTemplates[templateType];
        if (!template) return;

        // Sample data for preview
        const sampleData = {
            organization: this.currentFinding?.company || 'Example Corp',
            repository: this.currentFinding?.repository || 'example-corp/web-app',
            file: this.currentFinding?.file || 'config/database.yml',
            pii_type: this.currentFinding?.piiType?.replace(/_/g, ' ').toUpperCase() || 'API Key',
            severity: this.currentFinding?.severity || 'High',
            date: new Date().toLocaleDateString(),
            campaign_id: 'SDCAMP-' + Date.now().toString().slice(-6),
            date_range: `${new Date(Date.now() - 7*24*60*60*1000).toLocaleDateString()} - ${new Date().toLocaleDateString()}`,
            company_count: this.selectedCompanies.length || 10,
            total_findings: this.findings.length || 25,
            critical_count: this.findings.filter(f => f.severity === 'critical').length || 5,
            high_count: this.findings.filter(f => f.severity === 'high').length || 8,
            medium_count: this.findings.filter(f => f.severity === 'medium').length || 10,
            low_count: this.findings.filter(f => f.severity === 'low').length || 2,
            findings_details: this.currentFinding?.content || 'AWS API key exposed in configuration file'
        };

        let content = template.content;
        Object.entries(sampleData).forEach(([key, value]) => {
            content = content.replace(new RegExp(`{${key}}`, 'g'), value);
        });

        const reportContent = document.getElementById('report-content');
        const reportPreview = document.getElementById('report-preview');
        
        if (reportContent) reportContent.textContent = content;
        if (reportPreview) reportPreview.classList.remove('hidden');

        // Update template selection
        document.querySelectorAll('.template-card').forEach(card => {
            card.classList.remove('selected');
        });
        const selectedCard = document.querySelector(`[data-template="${templateType}"]`);
        if (selectedCard) {
            selectedCard.classList.add('selected');
        }
    }

    renderTimeline() {
        const container = document.getElementById('timeline-list');
        if (!container) return;
        
        if (this.disclosures.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">⏱️</div>
                    <h3>No Active Disclosures</h3>
                    <p>Start disclosure processes from your findings to track them here</p>
                    <button class="btn btn--primary" onclick="window.app.showSection('findings')">View Findings</button>
                </div>
            `;
            return;
        }

        container.innerHTML = this.disclosures.map(disclosure => {
            const finding = this.findings.find(f => f.id === disclosure.findingId);
            const daysElapsed = Math.floor((Date.now() - new Date(disclosure.timeline.initial_contact)) / (1000 * 60 * 60 * 24));
            
            return `
                <div class="timeline-item">
                    <div class="timeline-item-header">
                        <h4>${disclosure.company} - ${finding ? finding.piiType.replace(/_/g, ' ').toUpperCase() : 'Unknown'}</h4>
                        <span class="timeline-status ${disclosure.status}">${disclosure.status.replace(/_/g, ' ')}</span>
                    </div>
                    <div class="timeline-progress-section">
                        <div class="timeline-days">Day ${daysElapsed} of 90-day disclosure timeline</div>
                        <div class="timeline-progress-bar">
                            <div class="timeline-progress-fill" style="width: ${Math.min((daysElapsed / 90) * 100, 100)}%"></div>
                        </div>
                    </div>
                    <div class="timeline-details">
                        <div><strong>Next milestone:</strong> ${this.getNextMilestone(disclosure, daysElapsed)}</div>
                        <div><strong>Security Contact:</strong> ${finding?.securityContact || 'N/A'}</div>
                        <div><strong>Bug Bounty:</strong> ${finding?.hasBugBounty ? 'Available' : 'Not Available'}</div>
                    </div>
                </div>
            `;
        }).join('');
    }

    getNextMilestone(disclosure, daysElapsed) {
        if (daysElapsed < 30) return `First follow-up in ${30 - daysElapsed} days`;
        if (daysElapsed < 60) return `Escalation in ${60 - daysElapsed} days`;
        if (daysElapsed < 90) return `Public disclosure consideration in ${90 - daysElapsed} days`;
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
                        backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }

        // Industry Chart
        const industryCtx = document.getElementById('industry-chart');
        if (industryCtx) {
            this.industryChart = new Chart(industryCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: ['Technology', 'Social Media', 'E-commerce/Cloud', 'Financial Tech', 'Cybersecurity'],
                    datasets: [{
                        label: 'Companies',
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5', '#5D878F']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } }
                }
            });
            this.updateIndustryChart();
        }
    }

    updateIndustryChart() {
        if (!this.industryChart) return;
        
        const industries = {};
        this.top50Companies.forEach(company => {
            const industry = company.industry;
            industries[industry] = (industries[industry] || 0) + 1;
        });
        
        const topIndustries = Object.entries(industries)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5);
        
        this.industryChart.data.labels = topIndustries.map(([industry]) => industry);
        this.industryChart.data.datasets[0].data = topIndustries.map(([,count]) => count);
        this.industryChart.update();
    }

    updateDashboard() {
        // Update stats
        const elements = {
            totalFindings: document.getElementById('total-findings'),
            activeDisclosures: document.getElementById('active-disclosures'),
            avgResponseTime: document.getElementById('avg-response-time')
        };

        if (elements.totalFindings) elements.totalFindings.textContent = this.findings.length;
        if (elements.activeDisclosures) elements.activeDisclosures.textContent = this.disclosures.length;
        
        const avgResponse = this.findings.length > 0 ? this.calculateAverageResponseTime() : '--';
        if (elements.avgResponseTime) elements.avgResponseTime.textContent = avgResponse;

        // Update severity chart
        if (this.severityChart) {
            const counts = [0, 0, 0, 0];
            this.findings.forEach(finding => {
                switch (finding.severity) {
                    case 'critical': counts[0]++; break;
                    case 'high': counts[1]++; break;
                    case 'medium': counts[2]++; break;
                    case 'low': counts[3]++; break;
                }
            });
            
            this.severityChart.data.datasets[0].data = counts;
            this.severityChart.update();
        }
    }

    calculateAverageResponseTime() {
        const responseTimes = this.findings.map(f => f.responseTime).filter(Boolean);
        if (responseTimes.length === 0) return '--';
        
        // Parse response times and calculate average
        const hours = responseTimes.map(rt => {
            const match = rt.match(/(\d+)-(\d+)/);
            return match ? (parseInt(match[1]) + parseInt(match[2])) / 2 : 48;
        });
        
        const avgHours = hours.reduce((sum, h) => sum + h, 0) / hours.length;
        return avgHours < 48 ? `${Math.round(avgHours)}h` : `${Math.round(avgHours / 24)}d`;
    }

    addActivity(message) {
        const activity = {
            id: Date.now(),
            message: message,
            timestamp: new Date()
        };
        
        this.activities.unshift(activity);
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
                <div class="activity-icon">${this.getActivityIcon(activity.message)}</div>
                <div class="activity-content">
                    <div class="activity-title">${activity.message}</div>
                    <div class="activity-time">${this.getRelativeTime(activity.timestamp)}</div>
                </div>
            </div>
        `).join('');
    }

    getActivityIcon(message) {
        if (message.includes('campaign') || message.includes('scan')) return '🔍';
        if (message.includes('disclosure')) return '📋';
        if (message.includes('companies')) return '🏢';
        if (message.includes('initialized')) return '🚀';
        return '📝';
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
        this.currentCompany = null;
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
            padding: var(--space-16) var(--space-20);
            border-radius: var(--radius-base);
            z-index: 1100;
            animation: slideIn 0.3s ease;
            box-shadow: var(--shadow-lg);
            max-width: 400px;
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }, 4000);
    }

    truncateText(text, maxLength) {
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Additional CSS for enhanced features
const enhancedStyles = document.createElement('style');
enhancedStyles.textContent = `
    .intel-section {
        margin-bottom: var(--space-24);
        padding-bottom: var(--space-16);
        border-bottom: 1px solid var(--color-border);
    }
    
    .intel-section:last-child {
        border-bottom: none;
    }
    
    .intel-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: var(--space-12);
        margin-top: var(--space-12);
    }
    
    .intel-item {
        font-size: var(--font-size-sm);
        color: var(--color-text-secondary);
    }
    
    .contact-list {
        margin-top: var(--space-12);
    }
    
    .contact-item {
        margin-bottom: var(--space-8);
        font-size: var(--font-size-sm);
    }
    
    .contact-item a {
        color: var(--color-primary);
        text-decoration: none;
    }
    
    .notes-content {
        background: var(--color-bg-3);
        padding: var(--space-16);
        border-radius: var(--radius-base);
        font-size: var(--font-size-sm);
        line-height: 1.6;
        margin-top: var(--space-12);
    }
    
    .policy-link {
        margin-top: var(--space-12);
    }
    
    .policy-link a {
        color: var(--color-primary);
        text-decoration: none;
        font-size: var(--font-size-sm);
    }
    
    .finding-summary {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: var(--space-20);
        padding-bottom: var(--space-16);
        border-bottom: 1px solid var(--color-border);
    }
    
    .summary-badges {
        display: flex;
        gap: var(--space-8);
    }
    
    .program-badge {
        background: var(--color-success);
        color: var(--color-btn-primary-text);
        padding: var(--space-4) var(--space-12);
        border-radius: var(--radius-full);
        font-size: var(--font-size-xs);
        font-weight: var(--font-weight-bold);
        text-transform: uppercase;
    }
    
    .detail-sections {
        display: flex;
        flex-direction: column;
        gap: var(--space-20);
    }
    
    .detail-section h5 {
        color: var(--color-text);
        margin-bottom: var(--space-12);
        font-size: var(--font-size-lg);
    }
    
    .content-preview {
        background: var(--color-bg-8);
        border: 1px solid var(--color-border);
        border-radius: var(--radius-base);
        padding: var(--space-16);
    }
    
    .content-preview pre {
        margin: 0;
        font-family: var(--font-family-mono);
        font-size: var(--font-size-sm);
        white-space: pre-wrap;
        word-break: break-all;
    }
    
    .impact-list {
        margin: 0;
        padding-left: var(--space-20);
    }
    
    .impact-list li {
        margin-bottom: var(--space-8);
        font-size: var(--font-size-sm);
        line-height: 1.5;
    }
    
    .timeline-item-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: var(--space-16);
    }
    
    .timeline-progress-section {
        margin-bottom: var(--space-16);
    }
    
    .timeline-days {
        font-size: var(--font-size-sm);
        color: var(--color-text-secondary);
        margin-bottom: var(--space-8);
    }
    
    .timeline-progress-bar {
        height: 8px;
        background: var(--color-secondary);
        border-radius: var(--radius-full);
        overflow: hidden;
    }
    
    .timeline-progress-fill {
        height: 100%;
        background: linear-gradient(90deg, var(--color-primary), var(--color-teal-300));
        transition: width var(--duration-normal) var(--ease-standard);
    }
    
    .timeline-details {
        font-size: var(--font-size-sm);
        color: var(--color-text-secondary);
        display: flex;
        flex-direction: column;
        gap: var(--space-4);
    }
    
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(enhancedStyles);

// Initialize the application
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new SecureDiscloseApp();
    window.app = app;
});