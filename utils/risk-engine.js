// ============================================================
//              EMAIL VERIFIER - RISK ENGINE & REPORTS
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.RiskEngine = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    /**
     * Aggregates findings from all security modules into a consolidated,
     * explainable risk assessment.
     */
    function evaluateRisk(params) {
        const {
            senderName = "",
            senderEmail = "",
            replyTo = "",
            isSafe = false,
            safeMatch = "",
            isSelf = false,
            domainAnalysis = {},
            authAnalysis = {},
            linkFindings = [],
            attachmentFindings = [],
            phishingFindings = [],
            academicFindings = {},
            dnsFindings = {},
            historyFindings = {}
        } = params;

        // Self-sent internal message handling
        if (isSelf) {
            return {
                category: "SAFE",
                categoryLabel: "NO MAJOR INDICATORS DETECTED",
                badgeClass: "badge-safe",
                score: 0,
                summary: "Internal message sent from your own logged-in account.",
                evidence: [],
                recommendation: "Internal self-sent email. No security concerns detected.",
                unavailableChecks: []
            };
        }

        const evidence = [];
        const seenEvidenceKeys = new Set();

        function addEvidence(item) {
            if (!item || !item.title) return;
            const key = `${item.category}_${item.title}`;
            if (seenEvidenceKeys.has(key)) return;
            seenEvidenceKeys.add(key);
            evidence.push(item);
        }

        // 1. Domain & Identity Evidence
        if (domainAnalysis.homoglyphs && domainAnalysis.homoglyphs.hasHomoglyphs) {
            addEvidence({
                category: "Identity & Domain",
                severity: "high",
                title: "Homoglyph / Confusable Characters in Domain",
                explanation: `Domain contains deceptive Unicode characters mimicking Latin letters: "${domainAnalysis.domain}" -> "${domainAnalysis.homoglyphs.normalized}".`,
                recommendation: "Do not trust this sender. Homoglyphs are used to spoof legitimate brand domains."
            });
        }

        if (domainAnalysis.isPunycode) {
            addEvidence({
                category: "Identity & Domain",
                severity: "medium",
                title: "Internationalized (Punycode) Domain",
                explanation: `Sender domain uses Punycode ("${domainAnalysis.domain}"), which may conceal internationalized characters.`,
                recommendation: "Verify that this domain is genuinely operated by the intended party."
            });
        }

        if (domainAnalysis.typosquatting && domainAnalysis.typosquatting.isTypo) {
            addEvidence({
                category: "Identity & Domain",
                severity: "high",
                title: "Lookalike / Typo-squatting Domain",
                explanation: domainAnalysis.typosquatting.reason || "Domain name is suspiciously similar to a well-known brand.",
                recommendation: "Compare domain spelling carefully against the official company address."
            });
        }

        if (domainAnalysis.deceptiveSubdomain && domainAnalysis.deceptiveSubdomain.isDeceptive) {
            addEvidence({
                category: "Identity & Domain",
                severity: "high",
                title: "Deceptive Subdomain / Brand Mimicry",
                explanation: domainAnalysis.deceptiveSubdomain.reason,
                recommendation: "Notice the root domain. Subdomains can be created by anyone to mimic famous brands."
            });
        }

        if (domainAnalysis.freeEmailImpersonation && domainAnalysis.freeEmailImpersonation.isImpersonation) {
            addEvidence({
                category: "Identity & Domain",
                severity: "high",
                title: "Free Email Impersonating Organization",
                explanation: domainAnalysis.freeEmailImpersonation.reason,
                recommendation: "Legitimate organizations communicate from official domain names, not free personal email services."
            });
        }

        if (domainAnalysis.replyToMismatch && domainAnalysis.replyToMismatch.hasMismatch) {
            addEvidence({
                category: "Identity & Domain",
                severity: domainAnalysis.replyToMismatch.severity || "medium",
                title: "Reply-To Address Mismatch",
                explanation: domainAnalysis.replyToMismatch.reason,
                recommendation: "If you reply to this message, your message will go to a different recipient than the displayed sender."
            });
        }

        // 2. Sender History Drift
        if (historyFindings && historyFindings.warnings) {
            for (const warn of historyFindings.warnings) {
                addEvidence({
                    category: "Sender History",
                    severity: warn.severity || "medium",
                    title: warn.title,
                    explanation: warn.message,
                    recommendation: warn.recommendation
                });
            }
        }

        // 3. Authentication & Header Alignment
        if (authAnalysis && authAnalysis.alignment) {
            if (authAnalysis.alignment.spfAligned === false && authAnalysis.mailedBy) {
                addEvidence({
                    category: "Authentication",
                    severity: "medium",
                    title: "SPF / Envelope Domain Mismatch",
                    explanation: `Mailed-by domain (${authAnalysis.mailedBy}) does not match sender domain (${authAnalysis.fromDomain}).`,
                    recommendation: "The message may have been relayed through a third-party service or spoofed."
                });
            }

            if (authAnalysis.alignment.dkimAligned === false && authAnalysis.signedBy) {
                addEvidence({
                    category: "Authentication",
                    severity: "medium",
                    title: "DKIM Signature Alignment Mismatch",
                    explanation: `Digital signature domain (${authAnalysis.signedBy}) differs from From domain (${authAnalysis.fromDomain}).`,
                    recommendation: "Verify whether the signing service is an authorized email relay for this sender."
                });
            }
        }

        // 4. Link Findings
        if (Array.isArray(linkFindings)) {
            for (const item of linkFindings) {
                for (const iss of item.issues) {
                    addEvidence({
                        category: "Links & URLs",
                        severity: iss.severity || "medium",
                        title: iss.type.replace(/_/g, " "),
                        explanation: iss.message,
                        recommendation: "Do not click unverified links. Navigate to the website manually."
                    });
                }
            }
        }

        // 5. Attachment Findings
        if (Array.isArray(attachmentFindings)) {
            for (const item of attachmentFindings) {
                for (const iss of item.issues) {
                    addEvidence({
                        category: "Attachments",
                        severity: iss.severity || "high",
                        title: iss.type.replace(/_/g, " "),
                        explanation: iss.message,
                        recommendation: iss.recommendation
                    });
                }
            }
        }

        // 6. Phishing & Social Engineering Heuristics
        if (Array.isArray(phishingFindings)) {
            for (const p of phishingFindings) {
                addEvidence({
                    category: "Social Engineering",
                    severity: p.severity || "high",
                    title: p.title,
                    explanation: `${p.explanation} Matched: "${p.matchedPhrase}"`,
                    recommendation: p.recommendation
                });
            }
        }

        // 7. Academic Protection Findings
        if (academicFindings && Array.isArray(academicFindings.issues)) {
            for (const a of academicFindings.issues) {
                addEvidence({
                    category: "Academic Security",
                    severity: a.severity || "high",
                    title: a.title,
                    explanation: a.message,
                    recommendation: a.recommendation
                });
            }
        }

        // 8. DNS / Infrastructure Findings
        if (dnsFindings && dnsFindings.mx) {
            if (dnsFindings.mx.status === "NO_MX") {
                addEvidence({
                    category: "DNS & Infrastructure",
                    severity: "high",
                    title: "Domain Lacks MX Records",
                    explanation: "This domain has no mail exchanger (MX) records published and cannot legitimately receive emails.",
                    recommendation: "Attackers frequently send spoofed mail from nonexistent or unconfigured domains."
                });
            } else if (dnsFindings.mx.status === "NXDOMAIN") {
                addEvidence({
                    category: "DNS & Infrastructure",
                    severity: "high",
                    title: "Domain Does Not Exist (NXDOMAIN)",
                    explanation: "The sender domain does not exist in public domain name servers.",
                    recommendation: "This sender address is fabricated or spoofed. Do not interact with this email."
                });
            }
        }

        // Record unavailable checks honestly
        const unavailableChecks = [];
        if (!dnsFindings || dnsFindings.mx?.status === "QUERY_FAILED") {
            unavailableChecks.push("Live DNS MX/SPF/DMARC resolution (offline or network query blocked).");
        }
        if (!authAnalysis.hasRawHeaders) {
            unavailableChecks.push("Raw RFC 822 MIME headers (Gmail standard reading pane exposes visible metadata only).");
        }

        // Risk Category Determination
        const highCount = evidence.filter(e => e.severity === "high").length;
        const mediumCount = evidence.filter(e => e.severity === "medium").length;

        let category = "SAFE";
        let categoryLabel = "NO MAJOR INDICATORS DETECTED";
        let badgeClass = "badge-safe";
        let summary = "No known deceptive indicators, dangerous attachments, or phishing patterns were detected.";
        let recommendation = "Standard vigilance applies. Always exercise caution with unsolicited attachments and links.";

        // For trusted senders, NEVER classify as HIGH RISK
        if (isSafe) {
            category = "TRUSTED";
            categoryLabel = "TRUSTED SENDER";
            badgeClass = "badge-trusted";
            summary = `Sender matches your local safe senders list ("${safeMatch}").`;
            recommendation = "Sender is marked as trusted in your local configuration.";
        } else if (highCount > 0) {
            category = "HIGH_RISK";
            categoryLabel = "HIGH RISK";
            badgeClass = "badge-danger";
            summary = `${highCount} critical indicator(s) detected that strongly suggest spoofing, phishing, or malicious content.`;
            recommendation = "Do NOT click links, open attachments, or reply. Independently verify the sender before taking any action.";
        } else if (mediumCount > 0) {
            category = "CAUTION";
            categoryLabel = "CAUTION";
            badgeClass = "badge-warning";
            summary = `${mediumCount} suspicious indicator(s) require caution before proceeding.`;
            recommendation = "Inspect links and verify the sender through trusted official contacts.";
        }

        return {
            category,
            categoryLabel,
            badgeClass,
            highCount,
            mediumCount,
            totalIssues: evidence.length,
            summary,
            evidence,
            recommendation,
            unavailableChecks,
            isSafe,
            safeMatch
        };
    }

    /**
     * Generates a privacy-conscious security report (Text or JSON).
     * Excludes full email bodies, attachments, or personal address books.
     */
    function generateReport(assessment, metadata = {}, format = "text") {
        const timestamp = new Date().toISOString();
        const safeSender = metadata.senderEmail || "N/A";
        const safeDomain = metadata.senderDomain || "N/A";
        const safeName = metadata.senderName || "N/A";

        if (format === "json") {
            return JSON.stringify({
                reportTitle: "Email Security Assessment Report",
                generatedAt: timestamp,
                assessmentCategory: assessment.categoryLabel,
                sender: {
                    name: safeName,
                    email: safeSender,
                    domain: safeDomain,
                    isTrustedInSafeList: !!assessment.isSafe
                },
                summary: assessment.summary,
                recommendation: assessment.recommendation,
                evidenceCount: assessment.evidence.length,
                evidenceList: assessment.evidence.map(e => ({
                    category: e.category,
                    severity: e.severity,
                    title: e.title,
                    explanation: e.explanation
                })),
                unavailableChecks: assessment.unavailableChecks,
                disclaimer: "Generated locally by Email Verifier Chrome Extension. No message body or personal data was transmitted to third parties."
            }, null, 2);
        }

        // Plain Text Format
        let report = `=================================================\n`;
        report += `       EMAIL SECURITY ASSESSMENT REPORT\n`;
        report += `=================================================\n`;
        report += `Generated At: ${timestamp}\n`;
        report += `Risk Category: [${assessment.categoryLabel}]\n`;
        report += `Sender Name:   ${safeName}\n`;
        report += `Sender Email:  ${safeSender}\n`;
        report += `Sender Domain: ${safeDomain}\n`;
        report += `Trusted List:  ${assessment.isSafe ? "Yes (" + assessment.safeMatch + ")" : "No"}\n\n`;

        report += `SUMMARY:\n${assessment.summary}\n\n`;
        report += `RECOMMENDED ACTION:\n${assessment.recommendation}\n\n`;

        if (assessment.evidence.length > 0) {
            report += `FINDINGS & EVIDENCE (${assessment.evidence.length}):\n`;
            assessment.evidence.forEach((item, idx) => {
                report += `  ${idx + 1}. [${item.severity.toUpperCase()}] ${item.title}\n`;
                report += `     Category:    ${item.category}\n`;
                report += `     Explanation: ${item.explanation}\n`;
                if (item.recommendation) {
                    report += `     Action:      ${item.recommendation}\n`;
                }
                report += `\n`;
            });
        } else {
            report += `FINDINGS: No deceptive or suspicious indicators detected.\n\n`;
        }

        if (assessment.unavailableChecks && assessment.unavailableChecks.length > 0) {
            report += `UNAVAILABLE / NOT PERFORMED CHECKS:\n`;
            assessment.unavailableChecks.forEach(c => {
                report += `  - ${c}\n`;
            });
            report += `\n`;
        }

        report += `PRIVACY DISCLAIMER:\n`;
        report += `This assessment was conducted locally inside your browser.\n`;
        report += `Email content and attachments were NOT uploaded to any external server.\n`;
        report += `=================================================\n`;

        return report;
    }

    return {
        evaluateRisk,
        generateReport
    };
});
