# 🔒 Security Checklist

This checklist helps track security tasks, tools, and learning resources.

## ✅ 1. Pre-Engagement
- [ ] Secure a **Non-Disclosure Agreement (NDA)**.
- [ ] Obtain **formal authorization** for testing.
- [ ] Ensure **legal compliance** (GDPR, HIPAA, PCI-DSS).
- [ ] Define the **scope and rules of engagement**.

## ✅ 2. Reconnaissance & Subdomain Enumeration
- [ ] Run **Amass** for passive subdomain enumeration.
- [ ] Use **Subfinder** and **HTTPX** to find live subdomains.
- [ ] Identify the **tech stack** using **Wappalyzer**.
  - 🔗 [Wappalyzer Docs](https://www.wappalyzer.com/)
- [ ] Scan **Shodan** for exposed assets.

## ✅ 3. Automated Web Scanning
- [ ] Run **Nessus** for vulnerability assessment.
- [ ] Perform **OWASP ZAP scan**.
- [ ] Use **Nuclei** for CVE-based scanning.
  - 🔗 [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

## ✅ 4. Manual Pentesting & Exploitation
- [ ] Check for **SQL Injection** using **SQLMap**.
- [ ] Test for **Cross-Site Scripting (XSS)** manually.
- [ ] Use **Burp Suite** for advanced manual testing.
- [ ] Analyze **JS libraries** with **Retire.js**.

## ✅ 5. DevSecOps & CI/CD Security
- [ ] Integrate **SAST (Static Analysis)** (SonarQube, Semgrep).
- [ ] Implement **SCA (Software Composition Analysis)** (Snyk, Trivy).
- [ ] Scan for **secrets in code** using **GitLeaks**.
- [ ] Secure **Terraform & IaC** with **Checkov**.
  - 🔗 [Checkov Documentation](https://github.com/bridgecrewio/checkov)

## ✅ 6. Threat Intelligence & Incident Response
- [ ] Monitor **threat feeds** (Exploit DB, CVE Database).
- [ ] Use **Sigma Rules & YARA** for malware detection.
- [ ] Investigate **Shodan & Censys** results for security gaps.

## ✅ 7. Reporting & Documentation
- [ ] Generate a **detailed security report**.
- [ ] Present findings to stakeholders.
- [ ] Maintain an **updated knowledge base**.
