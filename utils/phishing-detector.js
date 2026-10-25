// ============================================================
//              EMAIL VERIFIER - PHISHING DETECTOR
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.PhishingDetector = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    // Phishing and Social Engineering Indicator Rule Sets
    const RULES = [
        {
            id: "URGENT_PAYMENT",
            severity: "high",
            category: "Financial Pressure",
            patterns: [
                /\b(?:wire\s+transfer|wire\s+funds|urgent\s+payment|pay\s+within\s+\d+\s*(?:hours?|days?)|payment\s+overdue|gift\s+card(?:s)?|bitcoin|crypto\s+payment|western\s+union|moneygram)\b/i,
                /\b(?:remit\s+payment|immediate\s+remittance|bank\s+transfer\s+required|send\s+money\s+urgently)\b/i,
                /(?:জরুরি\s*টাকা|টাকা\s*পাঠান|বিকাশ\s*করুন|নগদ\s*করুন|ব্যাংক\s*ট্রান্সফার|বিলম্বিত\s*ফি|জরুরি\s*পেমেন্ট)/i
            ],
            title: "Urgent Payment / Wire Transfer Demand",
            explanation: "The message pressures you to make an immediate monetary transfer, cryptocurrency deposit, or purchase gift cards.",
            recommendation: "Never send money or wire funds based solely on email instructions. Always verify financial requests through a trusted secondary channel."
        },
        {
            id: "CREDENTIAL_HARVESTING",
            severity: "high",
            category: "Credential Theft",
            patterns: [
                /\b(?:reset\s+your\s+password|verify\s+your\s+(?:account|identity|credentials|login)|confirm\s+your\s+credentials|login\s+to\s+verify|update\s+your\s+password\s+immediately)\b/i,
                /\b(?:password\s+expires?\s+(?:today|soon|in\s+\d+\s*hours?)|keep\s+same\s+password|mailbox\s+quota\s+exceeded|click\s+here\s+to\s+keep\s+your\s+account)\b/i,
                /(?:পাসওয়ার্ড\s*রিসেট|একাউন্ট\s*যাচাই|লগইন\s*করুন|পাসওয়ার্ড\s*পরিবর্তন|ইউজারনেম\s*ও\s*পাসওয়ার্ড)/i
            ],
            title: "Urgent Credential / Password Verification Request",
            explanation: "The message claims your account or password requires urgent verification, renewal, or login to avoid disruption.",
            recommendation: "Legitimate organizations do not request password verification via email links. Navigate to the service's official website directly."
        },
        {
            id: "ACCOUNT_SUSPENSION_THREAT",
            severity: "high",
            category: "Intimidation & Coercion",
            patterns: [
                /\b(?:account\s+will\s+be\s+(?:suspended|terminated|closed|disabled|deleted)|immediate\s+action\s+required\s+to\s+prevent|legal\s+action\s+will\s+be\s+taken|failure\s+to\s+respond\s+within\s+\d+\s*hours?)\b/i,
                /\b(?:security\s+alert:\s*unauthorized\s+access|account\s+is\s+temporarily\s+locked|suspended\s+due\s+to\s+inactivity)\b/i,
                /(?:একাউন্ট\s*স্থগিত|একাউন্ট\s*বন্ধ\s*হয়ে\s*যাবে|২৪\s*ঘণ্টার\s*মধ্যে|আইনি\s*ব্যবস্থা|জরুরি\s*পদক্ষেপ\s*নিন)/i
            ],
            title: "Threat of Account Suspension or Legal Action",
            explanation: "The message uses coercive threats of immediate account termination or penalties to cause panic and bypass scrutiny.",
            recommendation: "Pause and check your account status by logging into the legitimate provider in a separate browser tab."
        },
        {
            id: "PRIZE_LOTTERY_SCAM",
            severity: "high",
            category: "Advance-Fee Fraud",
            patterns: [
                /\b(?:congratulations\s+you(?:'ve|\s+have)?\s+won|lottery\s+winner|selected\s+to\s+receive\s+(?:\$|£|€)?\d+|unclaimed\s+funds|grant\s+award|beneficiary\s+of\s+(?:\$|£|€)?\d+|next\s+of\s+kin\s+inheritance)\b/i,
                /\b(?:cryptocurrency\s+giveaway|free\s+crypto\s+airdrop|claim\s+your\s+prize\s+now)\b/i,
                /(?:অভিনন্দন\s*আপনি\s*জিতেছেন|লটারি\s*বিজয়ী|পুরস্কার\s*জিতেছেন|বিনামূল্যে\s*অনুদান|টাকা\s*দাবি\s*করুন)/i
            ],
            title: "Unexpected Prize, Grant, or Lottery Award",
            explanation: "The message claims you have won an unexpected fortune, lottery, or grant that you did not enter or apply for.",
            recommendation: "Unsolicited prize and inheritance notifications are fraudulent advance-fee scams. Do not reply or send fees to claim prizes."
        },
        {
            id: "SENSITIVE_DOC_REQUEST",
            severity: "high",
            category: "Identity Theft",
            patterns: [
                /\b(?:send\s+(?:a\s+copy\s+of\s+)?your\s+passport|attach\s+driver'?s\s+license|national\s+id\s+card|social\s+security\s+number|ssn|nid\s+card|bank\s+statement|front\s+and\s+back\s+of\s+your\s+card)\b/i,
                /(?:পাসপোর্টের\s*কপি|জাতীয়\s*পরিচয়পত্র|এনআইডি|ড্রাইভিং\s*লাইসেন্স|ব্যাংক\s*স্টেটমেন্ট\s*পাঠান)/i
            ],
            title: "Request for Sensitive Identification Documents",
            explanation: "The sender requests high-value personal identity documents (passport, national ID, SSN, bank statements).",
            recommendation: "Do not transmit sensitive identity documents via email unless you have verified the recipient's identity through official institutional channels."
        },
        {
            id: "SECRECY_AND_BYPASS",
            severity: "medium",
            category: "Social Engineering",
            patterns: [
                /\b(?:keep\s+this\s+(?:strictly\s+)?confidential|do\s+not\s+(?:tell|consult|discuss\s+with)\s+anyone|bypass\s+(?:normal\s+)?(?:procedures|channels)|treat\s+this\s+with\s+utmost\s+discretion|urgent\s+personal\s+favor)\b/i,
                /(?:সম্পূর্ণ\s*গোপন\s*রাখুন|কাউকে\s*জানাবেন\s*না|নিয়ম\s*ছাড়াই|ব্যক্তিগত\s*অনুরোধ)/i
            ],
            title: "Unusual Secrecy or Procedure Bypass Request",
            explanation: "The message asks you to keep the matter strictly secret and bypass established verification or communication procedures.",
            recommendation: "Demands for secrecy are a hallmark of executive impersonation (BEC). Consult a manager or colleague before acting."
        },
        {
            id: "EXECUTIVE_IMPERSONATION",
            severity: "medium",
            category: "Executive Impersonation",
            patterns: [
                /\b(?:are\s+you\s+at\s+your\s+desk|need\s+a\s+quick\s+favor|in\s+a\s+meeting\s+cannot\s+take\s+calls|urgent\s+task\s+from\s+(?:the\s+)?(?:ceo|director|president|dean|head\s+of\s+dept))\b/i,
                /(?:জরুরি\s*কাজে\s*ব্যস্ত|মিটিংয়ে\s*আছি|কথা\s*বলা\s*সম্ভব\s*নয়|তাড়াতাড়ি\s*একটি\s*কাজ\s*করুন)/i
            ],
            title: "Potential Executive / Supervisor Impersonation",
            explanation: "The message imitates a senior figure claiming to be in a meeting and urgently requesting a quick favor.",
            recommendation: "Confirm the request directly with the sender via phone, SMS, or an internal messaging app before proceeding."
        },
        {
            id: "INVOICE_PAYMENT_CHANGE",
            severity: "high",
            category: "Financial Fraud",
            patterns: [
                /\b(?:updated\s+bank\s+(?:account|details)|new\s+banking\s+instructions|wire\s+to\s+new\s+account|remit\s+to\s+alternative\s+bank|revised\s+invoice\s+details)\b/i,
                /(?:নতুন\s*ব্যাংক\s*হিসাব|ব্যাংক\s*অ্যাকাউন্ট\s*পরিবর্তন|নতুন\s*পেমেন্ট\s*নির্দেশনা)/i
            ],
            title: "Unexpected Change in Payment / Banking Instructions",
            explanation: "The email claims payment details or bank accounts have changed and instructs you to wire money to a new destination.",
            recommendation: "Always verbally confirm modified bank account or routing details using known, pre-existing phone numbers."
        },
        {
            id: "SUSPICIOUS_RECRUITMENT",
            severity: "medium",
            category: "Recruitment Fraud",
            patterns: [
                /\b(?:work\s+from\s+home\s+(?:\$|£|€)?\d+\s*(?:\/day|\/hour)|no\s+experience\s+(?:needed|required)|immediate\s+hire\s+no\s+interview|earn\s+(?:\$|£|€)?\d+\s+weekly\s+from\s+home|package\s+reshipping\s+agent)\b/i,
                /(?:ঘরে\s*বসে\s*আয়|কোনো\s*অভিজ্ঞতা\s*ছাড়াই|দৈনিক\s*\d+\s*টাকা|অনলাইন\s*চাকরি|সহজ\s*কাজে\s*আয়)/i
            ],
            title: "Unsolicited Work-From-Home / Recruitment Offer",
            explanation: "The message promises unrealistically high compensation for minimal effort with no formal hiring process.",
            recommendation: "Legitimate employers do not hire or request banking details without a formal recruitment process."
        }
    ];

    /**
     * Inspects email body text or subject for social engineering and phishing indicators.
     * Returns an array of matched rules with evidence excerpts.
     */
    function detectPhishingPatterns(text = "") {
        if (!text || typeof text !== "string") return [];

        const clean = text.trim();
        if (clean.length < 15) return [];

        const matches = [];

        for (const rule of RULES) {
            for (const pattern of rule.patterns) {
                const match = clean.match(pattern);
                if (match) {
                    // Extract a surrounding context excerpt for transparency
                    const matchIndex = match.index || 0;
                    const start = Math.max(0, matchIndex - 30);
                    const end = Math.min(clean.length, matchIndex + match[0].length + 30);
                    const excerpt = "..." + clean.substring(start, end).replace(/\s+/g, " ") + "...";

                    matches.push({
                        id: rule.id,
                        severity: rule.severity,
                        category: rule.category,
                        title: rule.title,
                        explanation: rule.explanation,
                        recommendation: rule.recommendation,
                        matchedPhrase: match[0],
                        excerpt
                    });
                    break; // Move to next rule once one pattern matches
                }
            }
        }

        return matches;
    }

    return {
        RULES,
        detectPhishingPatterns
    };
});
