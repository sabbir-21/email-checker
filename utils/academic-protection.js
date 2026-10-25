// ============================================================
//              EMAIL VERIFIER - ACADEMIC PROTECTION MODE
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory(require("./domain-utils"));
    } else {
        root.AcademicProtection = factory(root.DomainUtils);
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function (DomainUtils) {
    "use strict";

    // Common recognized higher-education TLDs and SLDs
    const ACADEMIC_TLD_PATTERNS = [
        /\.edu$/i,
        /\.edu\.[a-z]{2}$/i,
        /\.ac\.[a-z]{2}$/i,
        /\.uni-[a-z0-9-]+\.[a-z]{2,}$/i
    ];

    // Predatory journal, conference, and paper solicitation indicators
    const PREDATORY_PUBLISHING_PATTERNS = [
        /\b(?:call\s+for\s+papers?|special\s+issue\s+(?:editor|invitation)|submit\s+your\s+manuscript\s+within\s+\d+\s*(?:hours?|days?)|guaranteed\s+fast\s+(?:peer\s+)?review|fast-track\s+publication|waived\s+apc|publication\s+in\s+\d+\s*days?)\b/i,
        /\b(?:outstanding\s+contribution\s+to\s+research|eminent\s+scholar|distinguished\s+researcher|editorial\s+board\s+member\s+invitation|keynote\s+speaker\s+invitation)\b/i,
        /(?:গবেষণাপত্র\s*আহ্বান|দ্রুত\s*প্রকাশনা|জার্নাল\s*আমন্ত্রণ|কনফারেন্স\s*নিবন্ধন)/i
    ];

    // Fraudulent scholarship, fellowship, and admissions fee indicators
    const ACADEMIC_FEE_PATTERNS = [
        /\b(?:application\s+fee|processing\s+fee|admissions\s+fee|visa\s+processing\s+fee|acceptance\s+fee|scholarship\s+registration\s+fee|tuition\s+deposit|wire\s+the\s+fee\s+to\s+secure\s+your\s+(?:seat|phd|scholarship|admission))\b/i,
        /\b(?:unconditional\s+(?:offer|admission)\s+with\s+(?:full\s+)?scholarship|guaranteed\s+phd\s+(?:fellowship|position))\b/i,
        /(?:ভর্তি\s*ফি|প্রসেসিং\s*ফি|আবেদন\s*ফি|স্কলারশিপ\s*ফি|ভিসা\s*ফি\s*পাঠান)/i
    ];

    // Academic authority titles used in impersonation
    const ACADEMIC_TITLES = [
        "professor", "prof.", "prof ", "associate professor", "assistant professor",
        "dean", "head of department", "hod", "department chair", "admissions office",
        "admissions committee", "registrar", "provost", "vice chancellor", "supervisor",
        "principal investigator", "director of admissions"
    ];

    /**
     * Checks if a domain is recognized as an academic domain (e.g. .edu, .ac.uk, .edu.bd, etc.)
     */
    function isAcademicDomain(domain) {
        if (!domain) return false;
        const clean = DomainUtils ? DomainUtils.normalizeDomain(domain) : domain.toLowerCase().trim();
        return ACADEMIC_TLD_PATTERNS.some(regex => regex.test(clean));
    }

    /**
     * Analyzes an email for academic security issues.
     */
    function analyzeAcademicContext(params) {
        const {
            senderName = "",
            senderEmail = "",
            replyToEmail = "",
            bodyText = "",
            links = [],
            trustedAcademicContacts = [],
            trustedInstitutions = []
        } = params;

        const issues = [];
        const cleanSender = DomainUtils ? DomainUtils.extractEmailAddress(senderEmail) : senderEmail.toLowerCase().trim();
        const senderDomain = cleanSender.split("@")[1] || "";
        const senderRoot = DomainUtils ? DomainUtils.getRootDomain(senderDomain) : senderDomain;
        const senderIsFree = DomainUtils ? DomainUtils.isFreeEmailProvider(senderDomain) : false;
        const senderIsAcademic = isAcademicDomain(senderDomain);

        // 1. Match against configured trusted academic contacts (exact email match)
        const matchedContact = trustedAcademicContacts.find(c => {
            const entry = typeof c === "string" ? c.toLowerCase().trim() : (c.email || "").toLowerCase().trim();
            return entry === cleanSender;
        });

        // 2. Match against configured trusted institutions
        const matchedInstitution = trustedInstitutions.find(inst => {
            const domainEntry = typeof inst === "string" ? inst.toLowerCase().trim() : (inst.domain || "").toLowerCase().trim();
            return domainEntry && (senderDomain === domainEntry || senderDomain.endsWith("." + domainEntry));
        });

        // 3. Faculty / Professor Impersonation Check:
        // Sender's display name or message header claims an academic title, but sender is using a free webmail provider or non-academic domain
        const nameLower = (senderName || "").toLowerCase().trim();
        const matchedTitle = ACADEMIC_TITLES.find(title => {
            const regex = new RegExp(`\\b${title.replace(".", "\\.")}\\b`, "i");
            return regex.test(nameLower);
        });

        if (matchedTitle && (senderIsFree || !senderIsAcademic) && !matchedContact) {
            issues.push({
                type: "ACADEMIC_IMPERSONATION",
                severity: "high",
                title: "Potential Faculty / University Impersonation",
                message: `Sender claims academic title ("${matchedTitle}") in their display name ("${senderName}"), but the email comes from a non-institutional address (@${senderDomain}).`,
                recommendation: "Universities and professors communicate through official institutional (.edu / .ac) email accounts. Verify through the official departmental directory."
            });
        }

        // 4. Predatory Journal / Conference Solicitation
        if (bodyText) {
            for (const pattern of PREDATORY_PUBLISHING_PATTERNS) {
                const match = bodyText.match(pattern);
                if (match) {
                    issues.push({
                        type: "PREDATORY_PUBLISHING",
                        severity: "medium",
                        title: "Predatory Publishing / Unsolicited Journal Invitation",
                        message: `Email contains predatory publishing indicators ("${match[0]}"). Such solicitations often promise rapid publication in exchange for exorbitant author fees without peer review.`,
                        recommendation: "Check the journal or conference indexation in reputable databases (e.g. Scopus, Web of Science, DOAJ) before submitting work or paying fees."
                    });
                    break;
                }
            }

            // 5. Academic Admissions / Scholarship Fee Scam
            for (const pattern of ACADEMIC_FEE_PATTERNS) {
                const match = bodyText.match(pattern);
                if (match) {
                    const isHigh = senderIsFree || !senderIsAcademic;
                    issues.push({
                        type: "ACADEMIC_FEE_SCAM",
                        severity: isHigh ? "high" : "medium",
                        title: "Academic Fee / Scholarship Payment Request",
                        message: `Email mentions application, processing, or visa fees ("${match[0]}").`,
                        recommendation: "Legitimate scholarships and universities never ask applicants to wire processing fees or tuition deposits to personal accounts or via untrusted links. Verify on the institution's official portal."
                    });
                    break;
                }
            }
        }

        // 6. Institutional Link Alignment Check:
        // If an institution is claimed, do links in the email point to that institution's official domain?
        if (matchedInstitution && links && links.length > 0) {
            const instDomain = typeof matchedInstitution === "string" ? matchedInstitution : matchedInstitution.domain;
            const externalLinks = [];

            for (const link of links) {
                const href = typeof link === "string" ? link : link.href;
                if (!href) continue;
                try {
                    const url = new URL(href);
                    const linkHost = url.hostname.toLowerCase();
                    if (!linkHost.endsWith(instDomain) && !linkHost.endsWith("google.com") && !linkHost.endsWith("microsoft.com")) {
                        externalLinks.push(linkHost);
                    }
                } catch {
                    // ignore invalid URL
                }
            }

            if (externalLinks.length > 0 && issues.length > 0) {
                issues.push({
                    type: "EXTERNAL_LINK_IN_ACADEMIC_EMAIL",
                    severity: "medium",
                    title: "Links Point Outside Institutional Domain",
                    message: `Email claiming institutional affiliation contains links pointing to external domains (${externalLinks.slice(0, 3).join(", ")}).`,
                    recommendation: "Ensure application and payment links reside on the university's official domain."
                });
            }
        }

        return {
            isAcademicSender: senderIsAcademic,
            matchedContact: !!matchedContact,
            matchedInstitution: !!matchedInstitution,
            contactDetails: matchedContact || null,
            institutionDetails: matchedInstitution || null,
            hasIssues: issues.length > 0,
            issues
        };
    }

    return {
        ACADEMIC_TLD_PATTERNS,
        PREDATORY_PUBLISHING_PATTERNS,
        ACADEMIC_FEE_PATTERNS,
        ACADEMIC_TITLES,
        isAcademicDomain,
        analyzeAcademicContext
    };
});
