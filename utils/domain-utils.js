// ============================================================
//              EMAIL VERIFIER - DOMAIN UTILITIES
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.DomainUtils = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    // Known popular brands and domains targeted by phishing / typo-squatting
    const HIGH_PROFILE_TARGETS = [
        "google.com",
        "gmail.com",
        "microsoft.com",
        "outlook.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "paypal.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        "netflix.com",
        "facebook.com",
        "meta.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "github.com",
        "gitlab.com",
        "dropbox.com",
        "stripe.com",
        "adobe.com",
        "yahoo.com",
        "proton.me",
        "protonmail.com",
        "zoom.us",
        "whatsapp.com",
        "instagram.com"
    ];

    // Common free / public webmail domains
    const FREE_EMAIL_PROVIDERS = new Set([
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "ymail.com",
        "rocketmail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "msn.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "zoho.com",
        "mail.com",
        "gmx.com",
        "gmx.net",
        "yandex.com",
        "tutanota.com",
        "tuta.io",
        "fastmail.com"
    ]);

    // Common multi-part public suffixes (SLDs)
    const KNOWN_SLDS = new Set([
        "co.uk", "ac.uk", "gov.uk", "org.uk", "ltd.uk", "me.uk", "net.uk",
        "edu.bd", "gov.bd", "org.bd", "ac.bd", "com.bd", "net.bd",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.za", "gov.za", "ac.za",
        "co.in", "net.in", "org.in", "gen.in", "ac.in", "edu.in", "res.in", "gov.in",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.sg", "edu.sg", "gov.sg",
        "co.kr", "ne.kr", "re.kr", "ac.kr",
        "com.mx", "gob.mx", "edu.mx",
        "com.tr", "edu.tr", "gov.tr"
    ]);

    // Homoglyph & Confusable Unicode Characters (Cyrillic, Greek, lookalikes -> Latin)
    const HOMOGLYPH_MAP = {
        // Cyrillic
        "\u0430": "a", "\u0410": "A", // а, А
        "\u0432": "b", "\u0412": "B", // в, В
        "\u0441": "c", "\u0421": "C", // с, С
        "\u0434": "d",                // д
        "\u0435": "e", "\u0415": "E", // е, Е
        "\u0451": "e", "\u0401": "E", // ё, Ё
        "\u0433": "r", "\u0413": "r", // г
        "\u0456": "i", "\u0406": "I", // і, І
        "\u0458": "j", "\u0408": "J", // ј, Ј
        "\u043A": "k", "\u041A": "K", // к, К
        "\u043C": "m", "\u041C": "M", // м, М
        "\u043D": "h", "\u041D": "H", // н, Н
        "\u043E": "o", "\u041E": "O", // о, О
        "\u0440": "p", "\u0420": "P", // р, Р
        "\u0442": "t", "\u0422": "T", // т, Т
        "\u0443": "y", "\u0423": "Y", // у, У
        "\u0445": "x", "\u0425": "X", // х, Х
        "\u0455": "s", "\u0405": "S", // ѕ, Ѕ

        // Greek
        "\u03B1": "a", "\u0391": "A", // α, Α
        "\u03B2": "b", "\u0392": "B", // β, Β
        "\u03B5": "e", "\u0395": "E", // ε, Ε
        "\u03B7": "n", "\u0397": "H", // η, Η
        "\u03B9": "i", "\u0399": "I", // ι, Ι
        "\u03BA": "k", "\u039A": "K", // κ, Κ
        "\u03BD": "v", "\u039D": "N", // ν, Ν
        "\u03BF": "o", "\u039F": "O", // ο, Ο
        "\u03C1": "p", "\u03A1": "P", // ρ, Ρ
        "\u03C4": "t", "\u03A4": "T", // τ, Τ
        "\u03C5": "u", "\u03A5": "Y", // υ, Υ
        "\u03C7": "x", "\u03A7": "X"  // χ, Χ
    };

    /**
     * Extracts email address from a string (e.g. "Name <user@example.com>" -> "user@example.com")
     */
    function extractEmailAddress(raw) {
        if (!raw) return "";
        const str = String(raw).trim();
        const angleMatch = str.match(/<([^>]+)>/);
        if (angleMatch) return angleMatch[1].trim().toLowerCase();
        const match = str.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        return match ? match[1].toLowerCase() : str.toLowerCase();
    }

    /**
     * Normalizes a domain name (lowercase, strip trailing dots, trim).
     */
    function normalizeDomain(domain) {
        if (!domain) return "";
        let clean = String(domain).toLowerCase().trim();
        clean = clean.replace(/\.$/, "");
        clean = clean.replace(/^[a-z]+:\/\//i, ""); // strip scheme if present
        clean = clean.split("/")[0]; // strip path if present
        clean = clean.split(":")[0]; // strip port if present
        return clean;
    }

    /**
     * Extracts the registrable root domain considering multi-part SLDs.
     * e.g. "mail.google.com" -> "google.com"
     *      "cs.ox.ac.uk" -> "ox.ac.uk"
     *      "sub.example.co.uk" -> "example.co.uk"
     */
    function getRootDomain(domain) {
        const clean = normalizeDomain(domain);
        if (!clean) return "";

        const parts = clean.split(".");
        if (parts.length <= 2) return clean;

        // Check if the last two parts form a known SLD
        const lastTwo = parts.slice(-2).join(".");
        if (KNOWN_SLDS.has(lastTwo)) {
            return parts.slice(-3).join(".");
        }

        return parts.slice(-2).join(".");
    }

    /**
     * Checks if a domain contains Punycode (e.g. xn--...)
     */
    function isPunycode(domain) {
        const clean = normalizeDomain(domain);
        return clean.split(".").some(part => part.startsWith("xn--"));
    }

    /**
     * Checks if a domain contains Unicode homoglyphs / confusable characters.
     */
    function detectHomoglyphs(domain) {
        if (!domain) return { hasHomoglyphs: false, normalized: domain, details: [] };

        const clean = normalizeDomain(domain);
        const details = [];
        let normalized = "";
        let hasHomoglyphs = false;

        for (let i = 0; i < clean.length; i++) {
            const ch = clean[i];
            if (HOMOGLYPH_MAP[ch]) {
                hasHomoglyphs = true;
                const latin = HOMOGLYPH_MAP[ch];
                details.push({
                    char: ch,
                    code: "U+" + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0"),
                    replacedWith: latin,
                    position: i
                });
                normalized += latin;
            } else {
                normalized += ch;
            }
        }

        // Also check if domain has non-ASCII characters that aren't mapped
        const nonAscii = clean.match(/[^\x00-\x7F]/g);
        if (nonAscii && !hasHomoglyphs) {
            hasHomoglyphs = true;
            details.push({
                char: nonAscii.join(", "),
                code: "Non-ASCII",
                replacedWith: "?",
                position: -1
            });
        }

        return {
            hasHomoglyphs,
            normalized,
            details
        };
    }

    /**
     * Computes Damerau-Levenshtein distance between two strings.
     * Accounts for insertions, deletions, substitutions, and transpositions.
     */
    function damerauLevenshtein(a, b) {
        if (!a || !b) return (a || "").length + (b || "").length;
        if (a === b) return 0;

        const al = a.length;
        const bl = b.length;
        const matrix = [];

        for (let i = 0; i <= al; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= bl; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= al; i++) {
            for (let j = 1; j <= bl; j++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,      // deletion
                    matrix[i][j - 1] + 1,      // insertion
                    matrix[i - 1][j - 1] + cost // substitution
                );

                // Transposition
                if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                    matrix[i][j] = Math.min(matrix[i][j], matrix[i - 2][j - 2] + 1);
                }
            }
        }

        return matrix[al][bl];
    }

    /**
     * Converts common visual typo substitutions:
     * 0 -> o, 1 -> l, rn -> m, vv -> w, etc.
     */
    function normalizeVisualLookalikes(str) {
        if (!str) return "";
        return str
            .replace(/0/g, "o")
            .replace(/1/g, "l")
            .replace(/5/g, "s")
            .replace(/rn/g, "m")
            .replace(/vv/g, "w")
            .replace(/cl/g, "d");
    }

    /**
     * Inspects a domain for typosquatting against high-profile target brands.
     */
    function checkTyposquatting(domain, customTargets = []) {
        const clean = normalizeDomain(domain);
        const root = getRootDomain(clean);
        const rootName = root.split(".")[0];

        const allTargets = [...HIGH_PROFILE_TARGETS, ...customTargets];
        const homoglyphResult = detectHomoglyphs(root);
        const candidateToTest = homoglyphResult.normalized;
        const candidateRootName = candidateToTest.split(".")[0];
        const visualCandidate = normalizeVisualLookalikes(candidateRootName);

        for (const target of allTargets) {
            const targetRoot = getRootDomain(target);
            const targetName = targetRoot.split(".")[0];

            // If it is identical to the target, it is not a typosquat of itself
            if (root === targetRoot) {
                continue;
            }

            // 1. Damerau-Levenshtein distance check on domain name
            const dist = damerauLevenshtein(candidateRootName, targetName);
            if (dist === 1 && targetName.length >= 4) {
                return {
                    isTypo: true,
                    target: targetRoot,
                    reason: `High similarity to "${targetRoot}" (edit distance 1)`,
                    dist
                };
            }

            // 2. Visual lookalike normalization (e.g. "arnazon" -> "amazon", "paypa1" -> "paypal")
            if (visualCandidate === targetName && candidateRootName !== targetName) {
                return {
                    isTypo: true,
                    target: targetRoot,
                    reason: `Visual character substitution detected targeting "${targetRoot}"`,
                    dist: 1
                };
            }

            // 3. Repeated character typo (e.g. "googgle.com", "paypall.com")
            const dedupCandidate = candidateRootName.replace(/(.)\1+/g, "$1");
            const dedupTarget = targetName.replace(/(.)\1+/g, "$1");
            if (dedupCandidate === dedupTarget && candidateRootName !== targetName) {
                return {
                    isTypo: true,
                    target: targetRoot,
                    reason: `Repeated character variation targeting "${targetRoot}"`,
                    dist: Math.abs(candidateRootName.length - targetName.length)
                };
            }
        }

        // 4. Fallback checks for legacy heuristic patterns
        const legacyTriggers = ["rn", "vv", "0", "1", "lll", "–"];
        const hasLegacy = legacyTriggers.some(x => clean.includes(x));
        if (hasLegacy && (clean.includes("google") || clean.includes("paypal") || clean.includes("bank") || clean.includes("apple") || clean.includes("mail"))) {
            return {
                isTypo: true,
                target: "known brand",
                reason: "Suspicious character substitution in brand-related domain",
                dist: 1
            };
        }

        return { isTypo: false };
    }

    /**
     * Checks for deceptive subdomains where a trusted brand is embedded in an unrelated domain.
     * e.g. "paypal.com.account-update.xyz" -> root is "account-update.xyz"
     *      "google.com-support.net" -> root is "google.com-support.net"
     */
    function checkDeceptiveSubdomain(domain) {
        const clean = normalizeDomain(domain);
        const root = getRootDomain(clean);

        for (const target of HIGH_PROFILE_TARGETS) {
            const targetRoot = getRootDomain(target);
            const targetName = targetRoot.split(".")[0];

            if (root === targetRoot) continue; // Legitimate root domain

            // Subdomain contains full target domain or target name
            // e.g. "paypal.com.verify.xyz" or "paypal-update.xyz"
            const parts = clean.split(".");
            const subdomains = parts.slice(0, parts.length - root.split(".").length);

            for (const sub of subdomains) {
                if (sub === targetName || sub === targetRoot.replace(".", "-") || sub.startsWith(targetName + "-") || sub.endsWith("-" + targetName)) {
                    return {
                        isDeceptive: true,
                        brand: targetRoot,
                        rootDomain: root,
                        fullDomain: clean,
                        reason: `Brand name "${targetRoot}" appears as a subdomain or label of unrelated root domain "${root}"`
                    };
                }
            }

            // Check if root domain itself is a compound trick like "paypal-security.com"
            const rootName = root.split(".")[0];
            if (rootName.includes(targetName) && rootName !== targetName && targetName.length >= 4) {
                // If the root domain has targetName hyphenated (e.g. paypal-login, amazon-support)
                if (rootName.startsWith(targetName + "-") || rootName.endsWith("-" + targetName) || rootName.includes("-" + targetName + "-")) {
                    return {
                        isDeceptive: true,
                        brand: targetRoot,
                        rootDomain: root,
                        fullDomain: clean,
                        reason: `Brand name "${targetRoot}" is embedded in hyphenated domain "${root}"`
                    };
                }
            }
        }

        return { isDeceptive: false };
    }

    /**
     * Checks if a domain is a known free webmail provider.
     */
    function isFreeEmailProvider(domain) {
        const root = getRootDomain(domain);
        return FREE_EMAIL_PROVIDERS.has(root) || FREE_EMAIL_PROVIDERS.has(normalizeDomain(domain));
    }

    /**
     * Detects when a sender's display name claims an organizational or official identity,
     * but the sender's actual address uses a generic free email provider.
     * Note: Normal personal emails from free providers are NOT flagged.
     */
    function checkFreeEmailImpersonation(displayName, senderEmail) {
        if (!senderEmail || !displayName) return { isImpersonation: false };

        const email = extractEmailAddress(senderEmail);
        const domain = email.split("@")[1] || "";

        if (!isFreeEmailProvider(domain)) {
            return { isImpersonation: false };
        }

        const nameLower = displayName.toLowerCase().trim();

        // Organizational identity indicator keywords
        const orgKeywords = [
            "support", "service", "helpdesk", "security", "security team", "billing",
            "department", "account team", "customer care", "official", "administrator",
            "admin", "bank", "payroll", "finance", "hr team", "human resources",
            "university", "registrar", "admissions", "paypal", "google", "apple",
            "microsoft", "amazon", "netflix", "facebook", "meta", "chase"
        ];

        const matchedKeyword = orgKeywords.find(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "i");
            return regex.test(nameLower);
        });

        if (matchedKeyword) {
            return {
                isImpersonation: true,
                keyword: matchedKeyword,
                displayName,
                senderEmail,
                domain,
                reason: `Sender uses free email provider (@${domain}) while display name "${displayName}" claims an organizational/official role ("${matchedKeyword}").`
            };
        }

        return { isImpersonation: false };
    }

    /**
     * Checks for significant mismatch between sender From address and Reply-To address.
     */
    function checkReplyToMismatch(senderEmail, replyToEmail) {
        if (!senderEmail || !replyToEmail) return { hasMismatch: false };

        const cleanSender = extractEmailAddress(senderEmail);
        const cleanReplyTo = extractEmailAddress(replyToEmail);

        if (!cleanSender || !cleanReplyTo) return { hasMismatch: false };
        if (cleanSender === cleanReplyTo) return { hasMismatch: false };

        const senderDomain = cleanSender.split("@")[1] || "";
        const replyDomain = cleanReplyTo.split("@")[1] || "";

        const senderRoot = getRootDomain(senderDomain);
        const replyRoot = getRootDomain(replyDomain);

        // Same root domain (e.g. support@mail.google.com and reply@google.com) is acceptable
        if (senderRoot && replyRoot && senderRoot === replyRoot) {
            return { hasMismatch: false, isSubdomainDiff: senderDomain !== replyDomain };
        }

        // Suspicious scenario 1: Corporate/institutional sender with free email Reply-To
        const replyIsFree = isFreeEmailProvider(replyDomain);
        const senderIsFree = isFreeEmailProvider(senderDomain);

        let severity = "medium";
        let reason = `Replies will be sent to a completely different domain: ${replyDomain} (instead of ${senderDomain}).`;

        if (!senderIsFree && replyIsFree) {
            severity = "high";
            reason = `Sender claims institutional domain (${senderDomain}) but Reply-To redirects to a free webmail account (${replyDomain}).`;
        }

        return {
            hasMismatch: true,
            severity,
            senderEmail: cleanSender,
            replyToEmail: cleanReplyTo,
            senderDomain,
            replyDomain,
            reason
        };
    }

    return {
        HIGH_PROFILE_TARGETS,
        FREE_EMAIL_PROVIDERS,
        KNOWN_SLDS,
        HOMOGLYPH_MAP,
        extractEmailAddress,
        normalizeDomain,
        getRootDomain,
        isPunycode,
        detectHomoglyphs,
        damerauLevenshtein,
        normalizeVisualLookalikes,
        checkTyposquatting,
        checkDeceptiveSubdomain,
        isFreeEmailProvider,
        checkFreeEmailImpersonation,
        checkReplyToMismatch
    };
});
