// ============================================================
//              EMAIL VERIFIER - SENDER HISTORY & TRUST
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory(require("./domain-utils"));
    } else {
        root.SenderHistory = factory(root.DomainUtils);
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function (DomainUtils) {
    "use strict";

    const MAX_HISTORY_ENTRIES = 500;

    /**
     * Normalizes and validates a trusted entry (domain or email).
     */
    function normalizeTrustedEntry(val) {
        if (!val || typeof val !== "string") return "";
        let clean = val.trim().toLowerCase();
        clean = clean.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "").replace(/^@/, "");
        return clean;
    }

    /**
     * Checks if a value is a valid domain or email.
     */
    function isValidEntry(val) {
        const clean = normalizeTrustedEntry(val);
        if (!clean) return false;
        if (clean.includes("@")) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean);
        }
        return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(clean);
    }

    /**
     * Migrates legacy chrome.storage.local schema to support extended trusted records.
     * Preserves raw safeSenders string array for 100% backward compatibility!
     */
    function migrateStorageData(rawStorage = {}) {
        const safeSenders = Array.isArray(rawStorage.safeSenders) ? rawStorage.safeSenders : [];
        let trustedRecords = Array.isArray(rawStorage.trustedRecords) ? rawStorage.trustedRecords : [];
        const senderHistory = (rawStorage.senderHistory && typeof rawStorage.senderHistory === "object")
            ? rawStorage.senderHistory
            : {};

        // If trustedRecords is empty or out of sync with safeSenders, populate it
        const recordMap = new Map();
        for (const rec of trustedRecords) {
            if (rec && rec.value) {
                recordMap.set(rec.value.toLowerCase().trim(), rec);
            }
        }

        const mergedRecords = [];
        for (const s of safeSenders) {
            const clean = normalizeTrustedEntry(s);
            if (!clean) continue;

            if (recordMap.has(clean)) {
                mergedRecords.push(recordMap.get(clean));
            } else {
                const isEmail = clean.includes("@");
                mergedRecords.push({
                    value: clean,
                    type: isEmail ? "email" : "domain",
                    category: "general",
                    note: "Default safe sender",
                    addedAt: new Date().toISOString()
                });
            }
        }

        return {
            safeSenders: mergedRecords.map(r => r.value),
            trustedRecords: mergedRecords,
            senderHistory
        };
    }

    /**
     * Updates sender observation history in memory.
     */
    function recordSenderObservation(historyMap = {}, email, name, replyTo) {
        if (!email) return historyMap;

        const cleanEmail = DomainUtils ? DomainUtils.extractEmailAddress(email) : email.toLowerCase().trim();
        if (!cleanEmail) return historyMap;

        const now = new Date().toISOString();
        const existing = historyMap[cleanEmail] || {
            email: cleanEmail,
            firstSeen: now,
            lastSeen: now,
            count: 0,
            observedNames: [],
            observedReplyTos: []
        };

        existing.lastSeen = now;
        existing.count = (existing.count || 0) + 1;

        if (name && !existing.observedNames.includes(name)) {
            existing.observedNames.push(name);
            if (existing.observedNames.length > 5) existing.observedNames.shift();
        }

        if (replyTo) {
            const cleanReply = DomainUtils ? DomainUtils.extractEmailAddress(replyTo) : replyTo.toLowerCase().trim();
            if (cleanReply && !existing.observedReplyTos.includes(cleanReply)) {
                existing.observedReplyTos.push(cleanReply);
                if (existing.observedReplyTos.length > 5) existing.observedReplyTos.shift();
            }
        }

        historyMap[cleanEmail] = existing;

        // Cap history size to prevent storage bloat
        const keys = Object.keys(historyMap);
        if (keys.length > MAX_HISTORY_ENTRIES) {
            const oldestKey = keys.sort((a, b) => (historyMap[a].lastSeen || "").localeCompare(historyMap[b].lastSeen || ""))[0];
            delete historyMap[oldestKey];
        }

        return historyMap;
    }

    /**
     * Detects sudden changes or drift in sender behavior based on history.
     */
    function detectSenderDrift(historyMap = {}, email, name, replyTo) {
        if (!email || !historyMap) return { hasDrift: false, warnings: [] };

        const cleanEmail = DomainUtils ? DomainUtils.extractEmailAddress(email) : email.toLowerCase().trim();
        const record = historyMap[cleanEmail];
        const warnings = [];

        if (record && record.count >= 2) {
            // Check for new, unexpected Reply-To address on a familiar contact
            if (replyTo) {
                const cleanReply = DomainUtils ? DomainUtils.extractEmailAddress(replyTo) : replyTo.toLowerCase().trim();
                if (cleanReply && cleanReply !== cleanEmail) {
                    const previouslySeenReply = (record.observedReplyTos || []).includes(cleanReply);
                    if (!previouslySeenReply && record.observedReplyTos.length > 0) {
                        warnings.push({
                            type: "UNEXPECTED_REPLYTO_CHANGE",
                            severity: "medium",
                            title: "Unexpected Reply-To Address Change",
                            message: `This familiar sender is using a new Reply-To address (${cleanReply}) not seen in previous conversations.`,
                            recommendation: "Ensure replies are intended for this new address before responding."
                        });
                    }
                }
            }
        }

        return {
            hasDrift: warnings.length > 0,
            warnings,
            historyStats: record ? { count: record.count, firstSeen: record.firstSeen, lastSeen: record.lastSeen } : null
        };
    }

    /**
     * Validates imported JSON data for safe senders and academic records.
     */
    function validateImportData(rawJson) {
        let parsed;
        try {
            parsed = typeof rawJson === "string" ? JSON.parse(rawJson) : rawJson;
        } catch {
            return { valid: false, error: "Invalid JSON format." };
        }

        if (!parsed || typeof parsed !== "object") {
            return { valid: false, error: "Import data must be a valid JSON object." };
        }

        const validTrusted = [];
        const validAcademic = [];

        // Validate trustedRecords or safeSenders
        const rawList = Array.isArray(parsed.trustedRecords)
            ? parsed.trustedRecords
            : (Array.isArray(parsed.safeSenders) ? parsed.safeSenders : []);

        for (const item of rawList) {
            const val = typeof item === "string" ? item : (item && item.value);
            if (isValidEntry(val)) {
                const clean = normalizeTrustedEntry(val);
                validTrusted.push({
                    value: clean,
                    type: clean.includes("@") ? "email" : "domain",
                    category: (item && item.category) || "general",
                    note: String((item && item.note) || "").substring(0, 150),
                    addedAt: (item && item.addedAt) || new Date().toISOString()
                });
            }
        }

        // Validate academic records if present
        if (Array.isArray(parsed.trustedInstitutions)) {
            for (const inst of parsed.trustedInstitutions) {
                const domain = typeof inst === "string" ? inst : (inst && inst.domain);
                if (isValidEntry(domain)) {
                    validAcademic.push({
                        domain: normalizeTrustedEntry(domain),
                        name: String((inst && inst.name) || domain).substring(0, 100),
                        note: String((inst && inst.note) || "").substring(0, 150)
                    });
                }
            }
        }

        return {
            valid: true,
            trustedRecords: validTrusted,
            safeSenders: validTrusted.map(r => r.value),
            trustedInstitutions: validAcademic
        };
    }

    /**
     * Prepares exportable JSON object for backup.
     */
    function createExportPayload(trustedRecords = [], trustedInstitutions = []) {
        return {
            exportVersion: "1.0",
            exportDate: new Date().toISOString(),
            trustedRecords,
            safeSenders: trustedRecords.map(r => r.value),
            trustedInstitutions
        };
    }

    return {
        normalizeTrustedEntry,
        isValidEntry,
        migrateStorageData,
        recordSenderObservation,
        detectSenderDrift,
        validateImportData,
        createExportPayload
    };
});
