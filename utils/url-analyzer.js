// ============================================================
//              EMAIL VERIFIER - URL ANALYZER
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory(require("./domain-utils"));
    } else {
        root.UrlAnalyzer = factory(root.DomainUtils);
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function (DomainUtils) {
    "use strict";

    // Known URL shortener services
    const URL_SHORTENERS = new Set([
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "rebrand.ly",
        "tiny.cc",
        "qr.ae",
        "shorte.st"
    ]);

    // Suspicious URL schemes
    const DANGEROUS_SCHEMES = new Set([
        "javascript:",
        "data:",
        "vbscript:",
        "file:",
        "blob:"
    ]);

    // Sensitive keyword indicators in URL paths and queries
    const SENSITIVE_KEYWORDS = [
        "login", "signin", "sign-in", "log-in", "verify", "verification",
        "account-update", "secure-update", "password-reset", "reset-password",
        "banking", "wallet", "authenticate", "confirm-identity", "wp-login.php",
        "update-billing", "restore-access"
    ];

    // Redirect parameters commonly used in open redirects or phishing
    const REDIRECT_PARAM_KEYS = [
        "url", "redirect", "redirect_to", "redirect_url", "dest", "destination",
        "next", "target", "link", "goto", "r", "u", "return_to"
    ];

    /**
     * Checks if a host is an IPv4 or IPv6 address.
     */
    function isIpAddress(hostname) {
        if (!hostname) return false;
        // IPv4 regex (handles standard dotted-quad)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        // IPv6 enclosed in brackets or raw hex
        const cleanHost = hostname.replace(/^\[|\]$/g, "");
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(cleanHost) || ipv6Regex.test(cleanHost);
    }

    /**
     * Parses a raw URL safely without executing or throwing.
     */
    function safeParseUrl(rawUrl) {
        if (!rawUrl || typeof rawUrl !== "string") return null;
        const trimmed = rawUrl.trim();

        // Check dangerous scheme before standard URL parsing
        const lower = trimmed.toLowerCase();
        for (const scheme of DANGEROUS_SCHEMES) {
            if (lower.startsWith(scheme)) {
                return {
                    isDangerousScheme: true,
                    scheme: scheme.replace(":", ""),
                    hostname: "",
                    pathname: trimmed,
                    raw: trimmed
                };
            }
        }

        try {
            const parsed = new URL(trimmed);
            return {
                isDangerousScheme: false,
                scheme: parsed.protocol.replace(":", ""),
                hostname: parsed.hostname.toLowerCase(),
                pathname: parsed.pathname,
                search: parsed.search,
                username: parsed.username,
                password: parsed.password,
                searchParams: parsed.searchParams,
                raw: trimmed
            };
        } catch {
            // URL might be missing protocol (e.g. "www.example.com/login")
            try {
                const parsed = new URL("https://" + trimmed);
                return {
                    isDangerousScheme: false,
                    scheme: "https",
                    hostname: parsed.hostname.toLowerCase(),
                    pathname: parsed.pathname,
                    search: parsed.search,
                    username: parsed.username,
                    password: parsed.password,
                    searchParams: parsed.searchParams,
                    raw: trimmed
                };
            } catch {
                return null;
            }
        }
    }

    /**
     * Extracts potential redirect destination URL from search params safely.
     */
    function extractRedirectTarget(parsedUrl) {
        if (!parsedUrl || !parsedUrl.searchParams) return null;

        for (const key of REDIRECT_PARAM_KEYS) {
            const val = parsedUrl.searchParams.get(key);
            if (val && (val.startsWith("http://") || val.startsWith("https://") || val.startsWith("//"))) {
                return {
                    param: key,
                    targetUrl: val
                };
            }
        }
        return null;
    }

    /**
     * Inspects a single link (href and visible text) for security risks.
     */
    function analyzeLink(href, linkText = "", senderDomain = "") {
        const issues = [];
        const parsed = safeParseUrl(href);

        if (!parsed) {
            return {
                url: href,
                hasRisk: false,
                issues: []
            };
        }

        // 1. Dangerous scheme check
        if (parsed.isDangerousScheme) {
            issues.push({
                type: "DANGEROUS_SCHEME",
                severity: "high",
                message: `Dangerous URL scheme detected (${parsed.scheme}:). It may execute script content.`
            });
            return { url: href, hasRisk: true, issues };
        }

        const hostname = parsed.hostname;
        const rootDomain = DomainUtils ? DomainUtils.getRootDomain(hostname) : hostname;

        // 2. IP address URL check
        if (isIpAddress(hostname)) {
            issues.push({
                type: "IP_ADDRESS_URL",
                severity: "high",
                message: `Link points directly to an IP address (${hostname}) instead of a named domain.`
            });
        }

        // 3. Embedded user-info check (e.g. https://google.com@evil.com)
        if (parsed.username || parsed.password) {
            issues.push({
                type: "EMBEDDED_USERINFO",
                severity: "high",
                message: `URL contains embedded user-info (${parsed.username}), which can be used to disguise the real destination.`
            });
        }

        // 4. URL shortener check
        if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(rootDomain)) {
            issues.push({
                type: "URL_SHORTENER",
                severity: "medium",
                message: `URL uses shortener service (${hostname}), masking the true destination.`
            });
        }

        // 5. Display text mismatch check
        // e.g. text says "https://paypal.com/verify" or "www.paypal.com" but href points to "evil.com"
        const cleanText = (linkText || "").trim().toLowerCase();
        const textIsUrlLike = cleanText.startsWith("http://") || cleanText.startsWith("https://") || cleanText.startsWith("www.") || cleanText.includes(".com") || cleanText.includes(".org");

        if (textIsUrlLike) {
            const parsedText = safeParseUrl(cleanText);
            if (parsedText && parsedText.hostname) {
                const textRoot = DomainUtils ? DomainUtils.getRootDomain(parsedText.hostname) : parsedText.hostname;
                if (textRoot && rootDomain && textRoot !== rootDomain) {
                    issues.push({
                        type: "TEXT_MISMATCH",
                        severity: "high",
                        message: `Displayed text shows "${parsedText.hostname}" but actual destination is "${hostname}".`
                    });
                }
            }
        }

        // 6. Punycode & Homoglyph check in link domain
        if (DomainUtils) {
            if (DomainUtils.isPunycode(hostname)) {
                issues.push({
                    type: "PUNYCODE_LINK",
                    severity: "medium",
                    message: `Link uses internationalized Punycode domain (${hostname}).`
                });
            }

            const homoglyph = DomainUtils.detectHomoglyphs(hostname);
            if (homoglyph.hasHomoglyphs) {
                issues.push({
                    type: "HOMOGLYPH_LINK",
                    severity: "high",
                    message: `Link domain contains confusable Unicode characters (${hostname} -> ${homoglyph.normalized}).`
                });
            }

            // 7. Deceptive subdomain check in link
            const deceptive = DomainUtils.checkDeceptiveSubdomain(hostname);
            if (deceptive.isDeceptive) {
                issues.push({
                    type: "DECEPTIVE_SUBDOMAIN_LINK",
                    severity: "high",
                    message: deceptive.reason
                });
            }

            // 8. Typosquatting in link domain
            const typo = DomainUtils.checkTyposquatting(hostname);
            if (typo.isTypo) {
                issues.push({
                    type: "TYPOSQUAT_LINK",
                    severity: "high",
                    message: `Link domain looks like typosquatting of ${typo.target} (${typo.reason}).`
                });
            }
        }

        // 9. Sensitive keywords in path
        const fullPath = (parsed.pathname + parsed.search).toLowerCase();
        const matchedKeyword = SENSITIVE_KEYWORDS.find(kw => fullPath.includes(kw));
        if (matchedKeyword) {
            // If sender domain is unrelated or free email, sensitive path is a warning
            issues.push({
                type: "SENSITIVE_PATH",
                severity: "medium",
                message: `Link leads to an authentication or credential path ("${matchedKeyword}").`
            });
        }

        // 10. Open redirect parameter
        const redirectInfo = extractRedirectTarget(parsed);
        if (redirectInfo) {
            issues.push({
                type: "REDIRECT_PARAMETER",
                severity: "medium",
                message: `Link contains a redirect parameter (?${redirectInfo.param}=...). The final landing destination remains unverified.`
            });
        }

        return {
            url: href,
            hostname,
            rootDomain,
            hasRisk: issues.length > 0,
            issues
        };
    }

    /**
     * Inspects a collection of links found in an email body.
     */
    function analyzeAllLinks(links = [], senderDomain = "") {
        const results = [];
        const seenUrls = new Set();

        for (const link of links) {
            const href = typeof link === "string" ? link : link.href;
            const text = typeof link === "object" ? link.text : "";

            if (!href || seenUrls.has(href)) continue;
            seenUrls.add(href);

            const analysis = analyzeLink(href, text, senderDomain);
            if (analysis.hasRisk) {
                results.push(analysis);
            }
        }

        return results;
    }

    return {
        URL_SHORTENERS,
        DANGEROUS_SCHEMES,
        SENSITIVE_KEYWORDS,
        isIpAddress,
        safeParseUrl,
        extractRedirectTarget,
        analyzeLink,
        analyzeAllLinks
    };
});
