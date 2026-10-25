// ============================================================
//              EMAIL VERIFIER - DNS VERIFIER (DoH)
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.DnsVerifier = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    const DOH_ENDPOINT = "https://dns.google/resolve";
    const DEFAULT_TIMEOUT_MS = 4500;

    /**
     * Executes a DNS-over-HTTPS query via Google Public DNS with a safe timeout.
     */
    async function queryDoH(name, type = "MX", timeoutMs = DEFAULT_TIMEOUT_MS) {
        if (!name || typeof name !== "string") {
            return { success: false, status: -1, error: "Invalid domain name." };
        }

        const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

        try {
            const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
            const fetchOptions = {
                headers: { "Accept": "application/dns-json" }
            };
            if (controller) {
                fetchOptions.signal = controller.signal;
            }

            const response = await fetch(url, fetchOptions);
            if (timer) clearTimeout(timer);

            if (!response.ok) {
                return {
                    success: false,
                    status: response.status,
                    error: `DoH query failed with HTTP ${response.status}`
                };
            }

            const data = await response.json();
            return {
                success: true,
                status: data.Status, // 0 = NOERROR, 3 = NXDOMAIN
                answers: Array.isArray(data.Answer) ? data.Answer : [],
                authorities: Array.isArray(data.Authority) ? data.Authority : []
            };
        } catch (err) {
            if (timer) clearTimeout(timer);
            const isTimeout = err && (err.name === "AbortError" || String(err).includes("aborted"));
            return {
                success: false,
                status: -1,
                isTimeout,
                error: isTimeout ? "DNS query timed out." : (err ? err.message : "Network error.")
            };
        }
    }

    /**
     * Checks MX records for a domain.
     */
    async function checkMxRecords(domain) {
        const query = await queryDoH(domain, "MX");

        if (!query.success) {
            return {
                status: "QUERY_FAILED",
                hasMx: false,
                records: [],
                error: query.error,
                explanation: "Could not query MX records (network error, offline, or DNS blocked)."
            };
        }

        if (query.status === 3) {
            return {
                status: "NXDOMAIN",
                hasMx: false,
                records: [],
                explanation: "Domain does not exist in public DNS (NXDOMAIN)."
            };
        }

        const mxRecords = query.answers
            .filter(a => a.type === 15) // Type 15 = MX
            .map(a => a.data)
            .filter(Boolean);

        if (mxRecords.length > 0) {
            return {
                status: "PASS",
                hasMx: true,
                records: mxRecords,
                explanation: `Valid MX records found: ${mxRecords[0]}`
            };
        }

        return {
            status: "NO_MX",
            hasMx: false,
            records: [],
            explanation: "No MX records found; this domain is not configured to receive email."
        };
    }

    /**
     * Checks published SPF policy via TXT records on the domain.
     */
    async function checkSpfPolicy(domain) {
        const query = await queryDoH(domain, "TXT");

        if (!query.success) {
            return {
                status: "NOT_CHECKED",
                policy: null,
                rawRecord: null,
                explanation: "SPF policy query unavailable (offline or DNS error)."
            };
        }

        const txtRecords = query.answers
            .filter(a => a.type === 16) // Type 16 = TXT
            .map(a => a.data ? a.data.replace(/^"|"$/g, "") : "")
            .filter(Boolean);

        const spfRecord = txtRecords.find(t => t.startsWith("v=spf1"));

        if (!spfRecord) {
            return {
                status: "NONE",
                policy: null,
                rawRecord: null,
                explanation: "No published SPF record found in public DNS."
            };
        }

        let policy = "neutral";
        if (spfRecord.includes("-all")) policy = "strict_reject (-all)";
        else if (spfRecord.includes("~all")) policy = "softfail (~all)";
        else if (spfRecord.includes("+all")) policy = "permissive (+all)";

        return {
            status: "FOUND",
            policy,
            rawRecord: spfRecord,
            explanation: `Published SPF policy found (${policy}).`
        };
    }

    /**
     * Checks published DMARC policy via TXT records on _dmarc.<domain>.
     */
    async function checkDmarcPolicy(domain) {
        const dmarcHost = `_dmarc.${domain}`;
        const query = await queryDoH(dmarcHost, "TXT");

        if (!query.success) {
            return {
                status: "NOT_CHECKED",
                policy: null,
                rawRecord: null,
                explanation: "DMARC policy query unavailable."
            };
        }

        const txtRecords = query.answers
            .filter(a => a.type === 16)
            .map(a => a.data ? a.data.replace(/^"|"$/g, "") : "")
            .filter(Boolean);

        const dmarcRecord = txtRecords.find(t => t.startsWith("v=DMARC1"));

        if (!dmarcRecord) {
            return {
                status: "NONE",
                policy: null,
                rawRecord: null,
                explanation: "No published DMARC record found on _dmarc." + domain
            };
        }

        const pMatch = dmarcRecord.match(/p=([a-z]+)/i);
        const policy = pMatch ? pMatch[1].toLowerCase() : "unknown";

        return {
            status: "FOUND",
            policy,
            rawRecord: dmarcRecord,
            explanation: `Published DMARC policy found: p=${policy}.`
        };
    }

    /**
     * Runs full DNS verification for a domain (MX, SPF, DMARC).
     */
    async function verifyDomain(domain) {
        if (!domain) {
            return {
                domain: "",
                mx: { status: "NONE", hasMx: false, records: [] },
                spf: { status: "NOT_CHECKED" },
                dmarc: { status: "NOT_CHECKED" }
            };
        }

        const [mx, spf, dmarc] = await Promise.all([
            checkMxRecords(domain),
            checkSpfPolicy(domain),
            checkDmarcPolicy(domain)
        ]);

        return {
            domain,
            mx,
            spf,
            dmarc,
            disclaimer: "DNS records verify domain configuration; they do not guarantee individual message legitimacy."
        };
    }

    return {
        queryDoH,
        checkMxRecords,
        checkSpfPolicy,
        checkDmarcPolicy,
        verifyDomain
    };
});
