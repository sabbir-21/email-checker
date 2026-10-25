// ============================================================
//              EMAIL VERIFIER - CONTENT SCRIPT
// ============================================================

const DEFAULT_SAFE_DOMAINS = [
    "google.com",
    "gmail.com",
    "googlemail.com",
    "microsoft.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "office.com",
    "office365.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "aws.amazon.com",
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebookmail.com",
    "paypal.com",
    "stripe.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "netflix.com",
    "spotify.com",
    "adobe.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com"
];

let cachedSafeList = [...DEFAULT_SAFE_DOMAINS];
let cachedTrustedRecords = [];
let cachedSenderHistory = {};
let cachedInstitutions = [];
let cachedSettings = { lang: "en", dohEnabled: true, academicProtection: true };

let currentEmailKey = "";
let popupClosed = false;
let lastURL = location.href;
let lastAnalysisParams = null;
let lastPopupData = null;
let updateTimer = null;

// Persistent UI states across re-renders
let mismatchAreaOpen = false;
let mismatchInputVal = "";
let mismatchResultHtml = "";
let technicalEvidenceExpanded = false;

// Initialize Storage & Safe Senders Cache
initStorage();

function initStorage() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get([
            "safeSenders",
            "trustedRecords",
            "senderHistory",
            "trustedInstitutions",
            "settings"
        ], (result) => {
            if (result) {
                if (Array.isArray(result.safeSenders) && result.safeSenders.length > 0) {
                    cachedSafeList = result.safeSenders;
                } else {
                    chrome.storage.local.set({ safeSenders: DEFAULT_SAFE_DOMAINS });
                    cachedSafeList = [...DEFAULT_SAFE_DOMAINS];
                }

                if (Array.isArray(result.trustedRecords)) {
                    cachedTrustedRecords = result.trustedRecords;
                }
                if (result.senderHistory && typeof result.senderHistory === "object") {
                    cachedSenderHistory = result.senderHistory;
                }
                if (Array.isArray(result.trustedInstitutions)) {
                    cachedInstitutions = result.trustedInstitutions;
                }
                if (result.settings && typeof result.settings === "object") {
                    cachedSettings = { ...cachedSettings, ...result.settings };
                    if (cachedSettings.lang && typeof EmailVerifierI18n !== "undefined") {
                        EmailVerifierI18n.setLang(cachedSettings.lang);
                    }
                }
            }
        });

        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === "local") {
                if (changes.safeSenders) {
                    cachedSafeList = changes.safeSenders.newValue || DEFAULT_SAFE_DOMAINS;
                }
                if (changes.trustedRecords) {
                    cachedTrustedRecords = changes.trustedRecords.newValue || [];
                }
                if (changes.senderHistory) {
                    cachedSenderHistory = changes.senderHistory.newValue || {};
                }
                if (changes.trustedInstitutions) {
                    cachedInstitutions = changes.trustedInstitutions.newValue || [];
                }
                if (changes.settings) {
                    cachedSettings = { ...cachedSettings, ...(changes.settings.newValue || {}) };
                    if (cachedSettings.lang && typeof EmailVerifierI18n !== "undefined") {
                        EmailVerifierI18n.setLang(cachedSettings.lang);
                    }
                }

                // ONLY re-analyze if trusted lists or institutions changed
                const isTrustedChange = !!(changes.safeSenders || changes.trustedRecords || changes.trustedInstitutions);
                if (isTrustedChange && lastAnalysisParams && !popupClosed && isEmailViewActive()) {
                    analyzeEmail(
                        lastAnalysisParams.name,
                        lastAnalysisParams.email,
                        lastAnalysisParams.replyTo,
                        lastAnalysisParams.targetMsgNode,
                        lastAnalysisParams.contextMeta
                    );
                }
            }
        });
    }
}


// ============================================================
//              NAVIGATION & VIEW DETECTION
// ============================================================

/**
 * Checks whether Gmail is currently displaying an open email conversation view.
 */
function isEmailViewActive() {
    const hash = window.location.hash || "";
    const cleanHash = hash.replace(/^#/, "");
    const parts = cleanHash.split("/").filter(Boolean);

    if (parts.length === 0) return false;

    if (["category", "label", "search", "sect"].includes(parts[0])) {
        if (parts.length < 3) return false;
    } else {
        if (parts.length < 2) return false;
    }

    const mainEl = document.querySelector("div[role='main']");
    if (!mainEl) return false;

    const hasEmailDom = !!mainEl.querySelector(".adn, h2.hP, .ha");
    return hasEmailDom;
}

/**
 * Removes the popup immediately and resets tracking state when user leaves an email.
 */
function removePopup() {
    const box = document.getElementById("sender-popup-box");
    if (box) {
        box.remove();
    }
    currentEmailKey = "";
    popupClosed = false;
    lastAnalysisParams = null;
    lastPopupData = null;
    mismatchAreaOpen = false;
    mismatchInputVal = "";
    mismatchResultHtml = "";
}

function handleNavigationChange() {
    if (!isEmailViewActive()) {
        removePopup();
    } else {
        if (location.href !== lastURL) {
            lastURL = location.href;
            currentEmailKey = "";
            popupClosed = false;
        }
        updateSenderInfo();
    }
}

// Immediate response to URL hash and history state changes
window.addEventListener("hashchange", handleNavigationChange);
window.addEventListener("popstate", handleNavigationChange);

// Periodic polling fallback for single-page transitions
setInterval(() => {
    if (!isEmailViewActive()) {
        if (document.getElementById("sender-popup-box")) {
            removePopup();
        }
    } else {
        if (location.href !== lastURL) {
            lastURL = location.href;
            currentEmailKey = "";
            popupClosed = false;
            updateSenderInfo();
        }
    }
}, 300);

// Mutation Observer for DOM changes - ignores mutations inside our own popup
const observer = new MutationObserver((mutations) => {
    const isOnlyPopup = mutations.every(m => {
        const target = m.target;
        return target && target.closest && target.closest("#sender-popup-box");
    });
    if (isOnlyPopup) return;

    updateSenderInfo();
});
observer.observe(document.body, { childList: true, subtree: true });


// ============================================================
//              CURRENT USER EMAIL DETECTION
// ============================================================

/**
 * Detects the logged-in user's email address from Gmail's UI to avoid inspecting own replies.
 */
function getCurrentUserEmail() {
    const accountButtons = document.querySelectorAll(
        'header a[aria-label*="@"], a[aria-label*="Google Account"], a[aria-label*="Google-Konto"], [data-identifier]'
    );
    for (const btn of accountButtons) {
        const text = (btn.getAttribute("aria-label") || "") + " " + (btn.getAttribute("data-identifier") || "");
        const match = text.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (match) return match[1].toLowerCase();
    }

    const titleMatch = document.title.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (titleMatch) return titleMatch[1].toLowerCase();

    const gbEl = document.querySelector(".gb_d[aria-label*='@'], .gb_Fa[aria-label*='@'], div.gb_m");
    if (gbEl) {
        const match = (gbEl.getAttribute("aria-label") || gbEl.innerText || "").match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (match) return match[1].toLowerCase();
    }

    return "";
}


// ============================================================
//              SAFE SENDERS MATCHING & STORAGE
// ============================================================

/**
 * Checks whether an email or its domain is registered in the safe database.
 */
function matchSafeSender(email, safeList = cachedSafeList) {
    if (!email || !safeList || !Array.isArray(safeList)) return null;
    const cleanEmail = email.toLowerCase().trim();
    const domain = cleanEmail.split("@")[1] || "";
    const rootDomain = (typeof DomainUtils !== "undefined") ? DomainUtils.getRootDomain(domain) : domain;

    for (const item of safeList) {
        const entry = (item || "").toLowerCase().trim();
        if (!entry) continue;

        if (entry.includes("@")) {
            if (cleanEmail === entry) return entry;
        } else {
            if (domain === entry || domain.endsWith("." + entry) || (rootDomain && rootDomain === entry)) {
                return entry;
            }
        }
    }
    return null;
}

/**
 * Toggles a domain or email in the safe senders database in extension storage.
 */
async function toggleSenderSafeStatus(targetValue) {
    if (!targetValue) return;
    const clean = targetValue.toLowerCase().trim();
    const matched = matchSafeSender(clean, cachedSafeList);

    let updatedList;
    let updatedRecords;

    if (matched) {
        updatedList = cachedSafeList.filter(item => item.toLowerCase().trim() !== matched);
        updatedRecords = cachedTrustedRecords.filter(r => (r.value || "").toLowerCase().trim() !== matched);
    } else {
        updatedList = [clean, ...cachedSafeList];
        const isEmail = clean.includes("@");
        const newRecord = {
            value: clean,
            type: isEmail ? "email" : "domain",
            category: "general",
            note: "Trusted via Gmail popup",
            addedAt: new Date().toISOString()
        };
        updatedRecords = [newRecord, ...cachedTrustedRecords];
    }

    cachedSafeList = updatedList;
    cachedTrustedRecords = updatedRecords;

    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.set({
            safeSenders: updatedList,
            trustedRecords: updatedRecords
        });
    }

    if (lastAnalysisParams && !popupClosed && isEmailViewActive()) {
        analyzeEmail(
            lastAnalysisParams.name,
            lastAnalysisParams.email,
            lastAnalysisParams.replyTo,
            lastAnalysisParams.targetMsgNode,
            lastAnalysisParams.contextMeta
        );
    }
}


// ============================================================
//              EXTRACT SENDER & MESSAGE INFO
// ============================================================

function updateSenderInfo() {
    if (!isEmailViewActive()) {
        removePopup();
        return;
    }

    // Debounce to prevent repeated rapid executions
    if (updateTimer) clearTimeout(updateTimer);
    updateTimer = setTimeout(extractData, 200);
}

function extractData() {
    if (!isEmailViewActive()) {
        removePopup();
        return;
    }

    const myEmail = getCurrentUserEmail();

    let msgNodes = [...document.querySelectorAll("div[role='main'] .adn")];
    if (msgNodes.length === 0) {
        msgNodes = [...document.querySelectorAll("div[role='main'] div[role='listitem']")];
    }

    let targetMsgNode = null;
    let senderName = "";
    let senderEmail = "";
    let contextType = "incoming";
    let isMultiMessage = false;

    if (msgNodes.length > 0) {
        const parsedMsgs = [];
        for (const node of msgNodes) {
            const senderEl = node.querySelector(".gD") || node.querySelector(".go");
            const email = (senderEl?.getAttribute("email") || "").toLowerCase().trim();
            const name = senderEl?.getAttribute("name") || senderEl?.innerText?.trim() || "";
            const isSelf = myEmail ? (email === myEmail) : false;
            const isExpanded = !node.classList.contains("adq") && (node.offsetHeight > 40);

            if (email) {
                parsedMsgs.push({ node, email, name, isSelf, isExpanded });
            }
        }

        if (parsedMsgs.length > 1) {
            isMultiMessage = true;
        }

        const externalMsgs = parsedMsgs.filter(m => !m.isSelf && m.email);

        if (externalMsgs.length > 0) {
            contextType = isMultiMessage ? "reply" : "incoming";
            const expandedExternal = externalMsgs.filter(m => m.isExpanded);
            const chosen = expandedExternal.length > 0
                ? expandedExternal[expandedExternal.length - 1]
                : externalMsgs[externalMsgs.length - 1];

            targetMsgNode = chosen.node;
            senderEmail = chosen.email;
            senderName = chosen.name;
        } else if (parsedMsgs.length > 0) {
            const lastSent = parsedMsgs[parsedMsgs.length - 1];
            targetMsgNode = lastSent.node;

            const recipientEl = targetMsgNode.querySelector(".g2 [email], span[email].hb, [role='gridcell'] span[email]");
            const recipientEmail = recipientEl?.getAttribute("email")?.toLowerCase().trim();

            if (recipientEmail && recipientEmail !== myEmail) {
                contextType = "outgoing";
                senderEmail = recipientEmail;
                senderName = recipientEl?.getAttribute("name") || recipientEl?.innerText?.trim() || recipientEmail;
            } else {
                contextType = "self";
                senderEmail = lastSent.email;
                senderName = lastSent.name || "You";
            }
        }
    }

    // Fallback for non-standard Gmail views
    if (!senderEmail) {
        const allGDs = [...document.querySelectorAll("div[role='main'] .gD")];
        const externalGD = allGDs.find(el => {
            const em = (el.getAttribute("email") || "").toLowerCase().trim();
            return em && em !== myEmail;
        }) || allGDs[0];

        if (externalGD) {
            senderEmail = (externalGD.getAttribute("email") || "").toLowerCase().trim();
            senderName = externalGD.innerText?.trim() || "";
            targetMsgNode = externalGD.closest(".adn") || externalGD.parentElement;
            if (allGDs.length > 1) contextType = "reply";
        }
    }

    if (!senderEmail) return;

    // Check header details row for reply-to, mailed-by, signed-by
    let replyTo = "";
    let mailedBy = "";
    let signedBy = "";
    let securityInfo = "";

    if (targetMsgNode) {
        const headerRows = [...targetMsgNode.querySelectorAll("tr.ajv")];
        for (const row of headerRows) {
            const label = (row.querySelector(".gG .gI")?.textContent || "").trim().toLowerCase();
            const valueEl = row.querySelector(".gL");
            const valueText = valueEl?.textContent?.trim() || "";

            if (label.startsWith("reply-to") || label.startsWith("reply to")) {
                replyTo = valueEl?.querySelector("[email]")?.getAttribute("email") || valueText;
            } else if (label.startsWith("mailed-by") || label.startsWith("mailed by")) {
                mailedBy = valueText;
            } else if (label.startsWith("signed-by") || label.startsWith("signed by")) {
                signedBy = valueText;
            } else if (label.startsWith("security")) {
                securityInfo = valueText;
            }
        }
    }

    const uniqueKey = `${senderName}_${senderEmail}_${contextType}`;
    if (uniqueKey === currentEmailKey) return;

    currentEmailKey = uniqueKey;
    popupClosed = false;

    analyzeEmail(senderName, senderEmail, replyTo, targetMsgNode, {
        contextType,
        myEmail,
        mailedBy,
        signedBy,
        securityInfo
    });
}


// ============================================================
//                       MAIN ANALYSIS
// ============================================================

async function analyzeEmail(name, email, replyTo, targetMsgNode, contextMeta = {}) {
    lastAnalysisParams = { name, email, replyTo, targetMsgNode, contextMeta };

    const domain = email.includes("@") ? email.split("@")[1] : "";
    const fromDomain = (typeof DomainUtils !== "undefined") ? DomainUtils.normalizeDomain(domain) : domain.toLowerCase();

    // Check Safe Senders Database
    const safeMatch = matchSafeSender(email, cachedSafeList);
    const isSafe = !!safeMatch;
    const isSelf = contextMeta.contextType === "self";

    // 1. Domain & Lookalike Analysis
    // For trusted senders, bypass typosquatting, deceptive subdomains, homoglyphs, and free email impersonation
    let domainAnalysis = { domain: fromDomain };
    if (typeof DomainUtils !== "undefined" && fromDomain) {
        domainAnalysis = {
            domain: fromDomain,
            rootDomain: DomainUtils.getRootDomain(fromDomain),
            isPunycode: isSafe ? false : DomainUtils.isPunycode(fromDomain),
            homoglyphs: isSafe ? { hasHomoglyphs: false } : DomainUtils.detectHomoglyphs(fromDomain),
            typosquatting: isSafe ? { isTypo: false } : DomainUtils.checkTyposquatting(fromDomain),
            deceptiveSubdomain: isSafe ? { isDeceptive: false } : DomainUtils.checkDeceptiveSubdomain(fromDomain),
            freeEmailImpersonation: isSafe ? { isImpersonation: false } : DomainUtils.checkFreeEmailImpersonation(name, email),
            replyToMismatch: replyTo ? DomainUtils.checkReplyToMismatch(email, replyTo) : { hasMismatch: false }
        };
    }

    // 2. Authentication & Header Alignment Analysis
    const authAnalysis = {
        hasRawHeaders: false,
        mailedBy: contextMeta.mailedBy || "",
        signedBy: contextMeta.signedBy || "",
        securityInfo: contextMeta.securityInfo || "",
        fromDomain,
        alignment: {
            spfAligned: null,
            dkimAligned: null
        }
    };

    if (typeof DomainUtils !== "undefined" && fromDomain) {
        const fromRoot = DomainUtils.getRootDomain(fromDomain);
        if (contextMeta.mailedBy) {
            const mailedRoot = DomainUtils.getRootDomain(contextMeta.mailedBy);
            authAnalysis.alignment.spfAligned = (fromRoot && mailedRoot) ? (fromRoot === mailedRoot) : false;
        }
        if (contextMeta.signedBy) {
            const signedRoot = DomainUtils.getRootDomain(contextMeta.signedBy);
            authAnalysis.alignment.dkimAligned = (fromRoot && signedRoot) ? (fromRoot === signedRoot) : false;
        }
    }

    // 3. DNS Lookup (MX, SPF policy, DMARC policy via Google DoH)
    let dnsFindings = {};
    if (cachedSettings.dohEnabled && typeof DnsVerifier !== "undefined" && fromDomain && !isSelf) {
        try {
            dnsFindings = await DnsVerifier.verifyDomain(fromDomain);
        } catch {
            dnsFindings = { mx: { status: "QUERY_FAILED" } };
        }
    }

    // 4. Attachments Analysis
    const rawAttachments = detectAttachments(targetMsgNode);
    let attachmentFindings = [];
    if (typeof AttachmentAnalyzer !== "undefined" && rawAttachments.length > 0) {
        attachmentFindings = AttachmentAnalyzer.analyzeAttachments(rawAttachments);
    }

    // 5. Links Inspection
    const rawLinks = extractLinks(targetMsgNode);
    let linkFindings = [];
    if (typeof UrlAnalyzer !== "undefined" && rawLinks.length > 0) {
        linkFindings = UrlAnalyzer.analyzeAllLinks(rawLinks, fromDomain);
    }

    // 6. Body Text Phishing Patterns (bypassed if trusted)
    const bodyText = extractBodyText(targetMsgNode);
    let phishingFindings = [];
    if (!isSafe && typeof PhishingDetector !== "undefined" && bodyText) {
        phishingFindings = PhishingDetector.detectPhishingPatterns(bodyText);
    }

    // 7. Academic Protection Analysis
    let academicFindings = {};
    if (cachedSettings.academicProtection && typeof AcademicProtection !== "undefined") {
        academicFindings = AcademicProtection.analyzeAcademicContext({
            senderName: name,
            senderEmail: email,
            replyToEmail: replyTo,
            bodyText,
            links: rawLinks,
            trustedInstitutions: cachedInstitutions
        });
    }

    // 8. Sender History Drift Check & Record
    let historyFindings = {};
    if (typeof SenderHistory !== "undefined" && email && !isSelf) {
        historyFindings = SenderHistory.detectSenderDrift(cachedSenderHistory, email, name, replyTo);
        cachedSenderHistory = SenderHistory.recordSenderObservation(cachedSenderHistory, email, name, replyTo);
    }

    // 9. Risk Assessment Aggregation
    let assessment = {
        category: "SAFE",
        categoryLabel: "NO MAJOR INDICATORS DETECTED",
        badgeClass: "badge-safe",
        summary: "No deceptive indicators detected.",
        evidence: [],
        recommendation: "Normal vigilance applies.",
        unavailableChecks: []
    };

    if (typeof RiskEngine !== "undefined") {
        assessment = RiskEngine.evaluateRisk({
            senderName: name,
            senderEmail: email,
            replyTo,
            isSafe,
            safeMatch,
            isSelf,
            domainAnalysis,
            authAnalysis,
            linkFindings,
            attachmentFindings,
            phishingFindings,
            academicFindings,
            dnsFindings,
            historyFindings
        });
    }

    // Trusted senders NEVER receive "HIGH RISK" classification
    if (isSafe) {
        assessment.category = "TRUSTED";
        assessment.categoryLabel = "TRUSTED SENDER";
        assessment.badgeClass = "badge-trusted";
        assessment.summary = `Sender matches your local safe senders list ("${safeMatch}").`;
        assessment.recommendation = "Sender is marked as trusted in your local configuration.";
    }

    lastPopupData = {
        name,
        email,
        replyTo,
        fromDomain,
        isSafe,
        safeMatch,
        isSelf,
        contextMeta,
        assessment,
        authAnalysis,
        dnsFindings,
        academicFindings,
        rawAttachments,
        rawLinks
    };

    createOrUpdatePopup(lastPopupData);
}


// ============================================================
//                   DOM EXTRACTION HELPERS
// ============================================================

function detectAttachments(targetMsgNode) {
    const scope = targetMsgNode || document.querySelector("div[role='main']") || document;
    const nodes = scope.querySelectorAll("div.aQH span.aZo, div.aQH .aV3, span.aV3, div.aQy");
    const files = [];

    nodes.forEach(node => {
        const filename = (node.innerText || node.textContent || "").trim();
        if (filename && filename.includes(".")) {
            files.push(filename);
        }
    });

    return [...new Set(files)];
}

function extractLinks(targetMsgNode) {
    const scope = targetMsgNode || document.querySelector("div[role='main']") || document;
    const anchorElements = scope.querySelectorAll("div.a3s a[href], .ii.gt a[href]");
    const links = [];

    anchorElements.forEach(a => {
        const href = a.getAttribute("href") || "";
        const text = (a.innerText || a.textContent || "").trim();
        if (href && !href.startsWith("#") && !href.startsWith("mailto:")) {
            links.push({ href, text });
        }
    });

    return links;
}

function extractBodyText(targetMsgNode) {
    const scope = targetMsgNode || document.querySelector("div[role='main']");
    if (!scope) return "";
    const bodyEl = scope.querySelector("div.a3s, .ii.gt");
    return bodyEl ? (bodyEl.innerText || bodyEl.textContent || "") : "";
}


// ============================================================
//                       POPUP RENDER
// ============================================================

function createOrUpdatePopup(data) {
    if (popupClosed) return;
    if (!isEmailViewActive()) {
        removePopup();
        return;
    }

    const {
        name,
        email,
        replyTo,
        fromDomain,
        isSafe,
        safeMatch,
        isSelf,
        contextMeta,
        assessment,
        authAnalysis,
        dnsFindings,
        academicFindings
    } = data;

    let box = document.getElementById("sender-popup-box");
    if (!box) {
        box = document.createElement("div");
        box.id = "sender-popup-box";
        box.className = "sender-popup";
        document.body.appendChild(box);
        makeDraggable(box);
    }

    const { contextType = "incoming" } = contextMeta;
    const t = (typeof EmailVerifierI18n !== "undefined") ? EmailVerifierI18n.t : (k => k);
    const currentLang = (typeof EmailVerifierI18n !== "undefined") ? EmailVerifierI18n.getLang() : "en";

    // Header context tag
    let contextTagHtml = "";
    if (contextType === "reply") {
        contextTagHtml = `<div class="context-tag reply">${t("tagReply")}</div>`;
    } else if (contextType === "outgoing") {
        contextTagHtml = `<div class="context-tag outgoing">${t("tagOutgoing")}</div>`;
    } else if (contextType === "self") {
        contextTagHtml = `<div class="context-tag self">${t("tagSelf")}</div>`;
    } else {
        contextTagHtml = `<div class="context-tag incoming">${t("tagIncoming")}</div>`;
    }

    // Risk Category Banner
    let riskBadgeColor = "#28a745";
    let riskBadgeBg = "#e9f9ee";

    if (isSafe) {
        riskBadgeColor = "#059669";
        riskBadgeBg = "#d1fae5";
    } else if (assessment.category === "HIGH_RISK") {
        riskBadgeColor = "#dc3545";
        riskBadgeBg = "#fee2e2";
    } else if (assessment.category === "CAUTION") {
        riskBadgeColor = "#d97706";
        riskBadgeBg = "#fef3c7";
    }

    const badgeLabel = isSafe ? t("badgeTrustedTitle") : escapeHtml(assessment.categoryLabel);
    const countLabel = isSafe ? `✔ ${t("badgeTrustedSub")}` : `${assessment.evidence.length} ${assessment.evidence.length === 1 ? "indicator" : "indicators"}`;

    const riskBannerHtml = `
        <div class="risk-banner" style="background:${riskBadgeBg}; border-left: 4px solid ${riskBadgeColor};">
            <div class="risk-banner-header">
                <span class="risk-title" style="color:${riskBadgeColor};">${badgeLabel}</span>
                <span class="risk-count-badge">${countLabel}</span>
            </div>
            <div class="risk-banner-desc">${escapeHtml(assessment.summary)}</div>
        </div>
    `;

    // Safe sender status banner
    let safeSectionHtml = "";
    let safeBtnHtml = "";

    if (isSelf) {
        safeSectionHtml = `
            <div class="safe-badge">
                <span class="safe-badge-icon">ℹ️</span>
                <div>
                    <div class="safe-badge-title">${t("badgeInternalTitle")}</div>
                    <div class="safe-badge-sub">${t("badgeInternalSub")}</div>
                </div>
            </div>`;
    } else if (isSafe) {
        safeSectionHtml = `
            <div class="safe-badge">
                <span class="safe-badge-icon">🛡️</span>
                <div>
                    <div class="safe-badge-title">${t("badgeTrustedTitle")}</div>
                    <div class="safe-badge-sub">Matched: <b>${escapeHtml(safeMatch)}</b> in Safe Database</div>
                </div>
            </div>`;
        safeBtnHtml = `
            <button id="toggle-safe-btn" class="safe-toggle-btn remove" data-target="${escapeHtml(safeMatch)}">
                Remove "${escapeHtml(safeMatch)}" from Safe List
            </button>`;
    } else if (fromDomain) {
        safeBtnHtml = `
            <button id="toggle-safe-btn" class="safe-toggle-btn add" data-target="${escapeHtml(fromDomain)}">
                ➕ Trust "${escapeHtml(fromDomain)}" (Add to Safe List)
            </button>`;
    }

    // Academic Verified Badge
    let academicBadgeHtml = "";
    if (academicFindings && academicFindings.matchedInstitution) {
        academicBadgeHtml = `
            <div class="academic-badge">
                <span class="academic-badge-icon">🎓</span>
                <div>
                    <div class="academic-badge-title">${t("badgeAcademicVerifiedTitle")}</div>
                    <div class="academic-badge-sub">${t("badgeAcademicVerifiedSub")}</div>
                </div>
            </div>`;
    }

    // Recommendation Section
    const recommendationHtml = `
        <div class="recommendation-section">
            <b>Recommended Action:</b>
            <div style="font-size:12px; margin-top:2px;">${escapeHtml(assessment.recommendation)}</div>
        </div>
    `;

    // Technical Evidence (Accordion)
    let evidenceItemsHtml = "";
    if (assessment.evidence.length > 0) {
        evidenceItemsHtml = assessment.evidence.map(e => `
            <div class="evidence-item ${e.severity}">
                <div class="evidence-title">
                    <span class="severity-pill ${e.severity}">${e.severity.toUpperCase()}</span>
                    <b>${escapeHtml(e.title)}</b>
                </div>
                <div class="evidence-exp">${escapeHtml(e.explanation)}</div>
                ${e.recommendation ? `<div class="evidence-rec">💡 ${escapeHtml(e.recommendation)}</div>` : ""}
            </div>
        `).join("");
    } else {
        evidenceItemsHtml = `<div class="empty-evidence">✔ No suspicious technical indicators detected.</div>`;
    }

    // Authentication & DNS Details
    let authDetailsHtml = "";
    if (authAnalysis && (authAnalysis.mailedBy || authAnalysis.signedBy)) {
        authDetailsHtml = `
            <div class="auth-details-block">
                <b>Mail Infrastructure Alignment:</b>
                ${authAnalysis.mailedBy ? `<div class="auth-line">Mailed-by: <code>${escapeHtml(authAnalysis.mailedBy)}</code> (${authAnalysis.alignment.spfAligned ? "✔ Aligned" : "⚠ Differing"})</div>` : ""}
                ${authAnalysis.signedBy ? `<div class="auth-line">Signed-by: <code>${escapeHtml(authAnalysis.signedBy)}</code> (${authAnalysis.alignment.dkimAligned ? "✔ Aligned" : "⚠ Differing"})</div>` : ""}
                <small class="auth-note">${t("authNote")}</small>
            </div>
        `;
    }

    let dnsDetailsHtml = "";
    if (dnsFindings && dnsFindings.mx) {
        const mxStatus = dnsFindings.mx.hasMx ? `✔ MX: ${dnsFindings.mx.records[0] || "Found"}` : `❗ MX: ${dnsFindings.mx.explanation}`;
        const spfStatus = dnsFindings.spf?.policy ? `✔ Published SPF: ${dnsFindings.spf.policy}` : `ℹ Published SPF: Not found / None`;
        const dmarcStatus = dnsFindings.dmarc?.policy ? `✔ Published DMARC: p=${dnsFindings.dmarc.policy}` : `ℹ Published DMARC: Not found / None`;

        dnsDetailsHtml = `
            <div class="dns-details-block">
                <b>Public DNS Records:</b>
                <div class="dns-line">${escapeHtml(mxStatus)}</div>
                <div class="dns-line">${escapeHtml(spfStatus)}</div>
                <div class="dns-line">${escapeHtml(dmarcStatus)}</div>
            </div>
        `;
    }

    const replyToHtml = replyTo ? `<b>Reply-To:</b> <span class="email-text">${escapeHtml(replyTo)}</span><br>` : "";
    const roleLabel = (contextType === "outgoing") ? "Recipient:" : "Email:";

    box.innerHTML = `
        <div class="drag-header">
            <div class="drag-title">
                <span>🛡️</span>
                <span>${t("extName")}</span>
            </div>
            <div class="header-controls">
                <button id="toggle-lang-btn" class="header-btn" type="button" title="Toggle Language (EN / বাংলা)">${currentLang === "en" ? "বাংলা" : "EN"}</button>
                <button id="close-popup" type="button" title="Close">✖</button>
            </div>
        </div>

        <div class="content">
            ${contextTagHtml}
            ${riskBannerHtml}

            <div class="info-section">
                <b>Name:</b> ${escapeHtml(name)}<br>
                <div class="email-row">
                    <b>${roleLabel}</b> <span class="email-text">${escapeHtml(email)}</span>
                </div>
                ${replyToHtml}
            </div>

            ${academicBadgeHtml}
            ${safeSectionHtml}
            ${safeBtnHtml}
            ${recommendationHtml}

            <!-- Technical Evidence Accordion -->
            <button id="toggle-evidence-btn" type="button" class="evidence-accordion-btn">
                <span>🔍 ${technicalEvidenceExpanded ? t("btnHideDetails") : t("btnShowDetails")} (${assessment.evidence.length})</span>
                <span>${technicalEvidenceExpanded ? "▲" : "▼"}</span>
            </button>

            <div id="evidence-panel" class="${technicalEvidenceExpanded ? "" : "hidden"}">
                ${evidenceItemsHtml}
                ${authDetailsHtml}
                ${dnsDetailsHtml}
            </div>

            <!-- Actions Row -->
            <div class="action-buttons-row">
                <button id="copy-report-btn" type="button" class="action-btn-secondary" title="Copy privacy-conscious security report">
                    📋 ${t("btnCopyReport")}
                </button>
                <button id="mismatch-btn" type="button" class="action-btn-secondary">
                    ${t("btnFindMismatch")}
                </button>
            </div>
            <div id="copy-status" class="copy-status-msg hidden">${t("btnCopied")}</div>

            <div id="mismatch-area" class="${mismatchAreaOpen ? "" : "hidden"}">
                <input id="original-email" type="text" placeholder="${t("placeholderMismatch")}" value="${escapeHtml(mismatchInputVal)}">
                <button id="check-mismatch" type="button" class="action-btn small">${t("btnCheckMismatch")}</button>
                <div id="mismatch-result">${mismatchResultHtml}</div>
            </div>
        </div>

        <div class="credit-box">
            <small>
                Developed by <b>Sabbir Ahmed</b><br>
                <a href="https://www.facebook.com/sabbir299" target="_blank">Facebook</a> &bull;
                <a href="https://github.com/sabbir-21" target="_blank">GitHub</a><br>
                <a href="#" id="open-options-link" class="options-link">⚙️ ${t("btnOptions")}</a>
            </small>
        </div>
    `;

    // 1. Close Button
    const closeBtn = document.getElementById("close-popup");
    if (closeBtn) {
        closeBtn.onclick = (e) => {
            e.stopPropagation();
            box.remove();
            popupClosed = true;
        };
    }

    // 2. Language Toggle Button
    const langBtn = document.getElementById("toggle-lang-btn");
    if (langBtn) {
        langBtn.onclick = (e) => {
            e.stopPropagation();
            const nextLang = currentLang === "en" ? "bn" : "en";
            if (typeof EmailVerifierI18n !== "undefined") {
                EmailVerifierI18n.setLang(nextLang);
            }
            cachedSettings.lang = nextLang;
            if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
                chrome.storage.local.set({ settings: cachedSettings });
            }
            createOrUpdatePopup(data);
        };
    }

    // 3. Safe Sender Toggle Button
    const toggleSafeBtn = document.getElementById("toggle-safe-btn");
    if (toggleSafeBtn) {
        toggleSafeBtn.onclick = (e) => {
            e.stopPropagation();
            const targetVal = toggleSafeBtn.getAttribute("data-target");
            toggleSenderSafeStatus(targetVal);
        };
    }

    // 4. Technical Evidence Accordion Button
    const toggleEvidenceBtn = document.getElementById("toggle-evidence-btn");
    if (toggleEvidenceBtn) {
        toggleEvidenceBtn.onclick = (e) => {
            e.stopPropagation();
            technicalEvidenceExpanded = !technicalEvidenceExpanded;
            const panel = document.getElementById("evidence-panel");
            if (panel) {
                panel.classList.toggle("hidden", !technicalEvidenceExpanded);
            }
            toggleEvidenceBtn.innerHTML = `
                <span>🔍 ${technicalEvidenceExpanded ? t("btnHideDetails") : t("btnShowDetails")} (${assessment.evidence.length})</span>
                <span>${technicalEvidenceExpanded ? "▲" : "▼"}</span>
            `;
        };
    }

    // 5. Copy Report Button
    const copyReportBtn = document.getElementById("copy-report-btn");
    if (copyReportBtn) {
        copyReportBtn.onclick = (e) => {
            e.stopPropagation();
            if (typeof RiskEngine !== "undefined") {
                const reportText = RiskEngine.generateReport(assessment, {
                    senderName: name,
                    senderEmail: email,
                    senderDomain: fromDomain
                }, "text");

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(reportText).then(() => {
                        showCopyStatus();
                    }).catch(() => {
                        fallbackCopy(reportText);
                    });
                } else {
                    fallbackCopy(reportText);
                }
            }
        };
    }

    function fallbackCopy(text) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
        showCopyStatus();
    }

    function showCopyStatus() {
        const statusEl = document.getElementById("copy-status");
        if (statusEl) {
            statusEl.classList.remove("hidden");
            setTimeout(() => {
                if (statusEl) statusEl.classList.add("hidden");
            }, 2500);
        }
    }

    // 6. Find Mismatch (Typo Checker) Buttons & Inputs
    const mismatchBtn = document.getElementById("mismatch-btn");
    if (mismatchBtn) {
        mismatchBtn.onclick = (e) => {
            e.stopPropagation();
            mismatchAreaOpen = !mismatchAreaOpen;
            const area = document.getElementById("mismatch-area");
            if (area) {
                area.classList.toggle("hidden", !mismatchAreaOpen);
                if (mismatchAreaOpen) {
                    const inputEl = document.getElementById("original-email");
                    if (inputEl) inputEl.focus();
                }
            }
        };
    }

    const originalEmailInput = document.getElementById("original-email");
    if (originalEmailInput) {
        originalEmailInput.oninput = (e) => {
            mismatchInputVal = e.target.value;
        };
        originalEmailInput.onkeydown = (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                executeMismatchCheck();
            }
        };
    }

    const checkMismatchBtn = document.getElementById("check-mismatch");
    if (checkMismatchBtn) {
        checkMismatchBtn.onclick = (e) => {
            e.stopPropagation();
            executeMismatchCheck();
        };
    }

    function executeMismatchCheck() {
        const inputEl = document.getElementById("original-email");
        const userInput = (inputEl ? inputEl.value : mismatchInputVal).trim().toLowerCase();
        const resultEl = document.getElementById("mismatch-result");
        mismatchInputVal = userInput;

        if (!userInput.includes("@")) {
            mismatchResultHtml = `<div class="mismatch-warn">⚠ Please enter a valid email address (e.g. support@example.com).</div>`;
            if (resultEl) resultEl.innerHTML = mismatchResultHtml;
            return;
        }

        const cleanActual = email.trim().toLowerCase();

        if (userInput === cleanActual) {
            mismatchResultHtml = `<div class="mismatch-success">✔ E-mail match. Sender matches the expected address.</div>`;
        } else {
            const userParts = userInput.split("@");
            const actualParts = cleanActual.split("@");
            const userDomain = userParts[1] || "";
            const actualDomain = actualParts[1] || "";
            let typoNote = "";

            if (userDomain && actualDomain && userDomain !== actualDomain) {
                if (typeof DomainUtils !== "undefined") {
                    const dist = DomainUtils.damerauLevenshtein(actualDomain, userDomain);
                    if (dist <= 2) {
                        typoNote = `<br>⚠ <b>Possible typo:</b> Domain differs by ${dist} character(s) from expected "<b>${escapeHtml(userDomain)}</b>".`;
                    }
                }
            }

            mismatchResultHtml = `
                <div class="mismatch-error">
                    ❗ <b>E-mail mismatch detected!</b><br>
                    Sender in Gmail: <b>${escapeHtml(email)}</b><br>
                    Expected address: <b>${escapeHtml(userInput)}</b>
                    ${typoNote}
                </div>
            `;
        }

        if (resultEl) resultEl.innerHTML = mismatchResultHtml;
    }

    // 7. Open Options Link
    const optionsLink = document.getElementById("open-options-link");
    if (optionsLink) {
        optionsLink.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (typeof chrome !== "undefined" && chrome.runtime) {
                if (chrome.runtime.openOptionsPage) {
                    chrome.runtime.openOptionsPage();
                } else {
                    window.open(chrome.runtime.getURL("options.html"));
                }
            }
        };
    }
}


// ============================================================
//                   DRAGGABLE POPUP
// ============================================================

function makeDraggable(element) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

    element.onmousedown = function (e) {
        const header = e.target.closest(".drag-header");
        // Drag only if clicking the title bar and not buttons or interactive elements
        if (!header) return;
        if (e.target.closest("button") || e.target.closest("input") || e.target.closest("a") || e.target.closest("select")) {
            return;
        }

        e.preventDefault();
        pos3 = e.clientX;
        pos4 = e.clientY;

        document.onmouseup = function () {
            document.onmouseup = null;
            document.onmousemove = null;
        };

        document.onmousemove = function (moveEvent) {
            moveEvent.preventDefault();
            pos1 = pos3 - moveEvent.clientX;
            pos2 = pos4 - moveEvent.clientY;
            pos3 = moveEvent.clientX;
            pos4 = moveEvent.clientY;

            element.style.top = (element.offsetTop - pos2) + "px";
            element.style.left = (element.offsetLeft - pos1) + "px";
            element.style.right = "auto"; // clear right constraint so left moves freely
        };
    };
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
