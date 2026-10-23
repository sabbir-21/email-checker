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
let currentEmailKey = "";
let popupClosed = false;
let lastURL = location.href;
let lastAnalysisParams = null;

// Initialize Storage & Safe Senders Cache
initStorage();

function initStorage() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(["safeSenders"], (result) => {
            if (result && Array.isArray(result.safeSenders) && result.safeSenders.length > 0) {
                cachedSafeList = result.safeSenders;
            } else {
                chrome.storage.local.set({ safeSenders: DEFAULT_SAFE_DOMAINS });
                cachedSafeList = [...DEFAULT_SAFE_DOMAINS];
            }
        });

        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === "local" && changes.safeSenders) {
                cachedSafeList = changes.safeSenders.newValue || DEFAULT_SAFE_DOMAINS;
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
        });
    }
}

// ============================================================
//              NAVIGATION & VIEW DETECTION
// ============================================================

/**
 * Checks whether Gmail is currently displaying an open email conversation view.
 * If user is on #inbox, #sent, #trash, #starred, or any list view, returns false.
 */
function isEmailViewActive() {
    const hash = window.location.hash || "";
    const cleanHash = hash.replace(/^#/, "");
    const parts = cleanHash.split("/").filter(Boolean);

    // List view hashes: #inbox (length 1), #sent (length 1), etc.
    if (parts.length === 0) return false;

    if (["category", "label", "search", "sect"].includes(parts[0])) {
        // e.g. #category/promotions (len 2 = list) vs #category/promotions/ID (len 3 = open email)
        if (parts.length < 3) return false;
    } else {
        // e.g. #inbox (len 1 = list) vs #inbox/ID (len 2 = open email)
        if (parts.length < 2) return false;
    }

    // DOM check: Ensure Gmail conversation elements exist in main area
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

// Mutation Observer for DOM changes
const observer = new MutationObserver(updateSenderInfo);
observer.observe(document.body, { childList: true, subtree: true });


// ============================================================
//              CURRENT USER EMAIL DETECTION
// ============================================================

/**
 * Detects the logged-in user's email address from Gmail's UI to avoid inspecting own replies.
 */
function getCurrentUserEmail() {
    // 1. Google Account Profile button in Gmail header (e.g. aria-label="Google Account: Name (user@gmail.com)")
    const accountButtons = document.querySelectorAll(
        'header a[aria-label*="@"], a[aria-label*="Google Account"], a[aria-label*="Google-Konto"], [data-identifier]'
    );
    for (const btn of accountButtons) {
        const text = (btn.getAttribute("aria-label") || "") + " " + (btn.getAttribute("data-identifier") || "");
        const match = text.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (match) return match[1].toLowerCase();
    }

    // 2. Gmail document.title (e.g. "Subject - user@gmail.com - Gmail" or "Inbox - user@gmail.com - Gmail")
    const titleMatch = document.title.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (titleMatch) return titleMatch[1].toLowerCase();

    // 3. Fallback: Google profile icon avatar in header
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
 * Supports exact email matches and root/subdomain matches (e.g. mail.google.com -> google.com).
 */
function matchSafeSender(email, safeList = cachedSafeList) {
    if (!email || !safeList || !Array.isArray(safeList)) return null;
    const cleanEmail = email.toLowerCase().trim();
    const domain = cleanEmail.split("@")[1] || "";

    for (const item of safeList) {
        const entry = (item || "").toLowerCase().trim();
        if (!entry) continue;

        if (entry.includes("@")) {
            if (cleanEmail === entry) return entry;
        } else {
            if (domain === entry || domain.endsWith("." + entry)) {
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

    let updated;
    if (matched) {
        // Remove matching entry
        updated = cachedSafeList.filter(item => item.toLowerCase().trim() !== matched);
    } else {
        // Add new entry
        updated = [clean, ...cachedSafeList];
    }

    cachedSafeList = updated;
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.set({ safeSenders: updated });
    }

    // Refresh popup analysis
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
//              EXTRACT SENDER INFO (HANDLING REPLIES)
// ============================================================

function updateSenderInfo() {
    if (!isEmailViewActive()) {
        removePopup();
        return;
    }

    // Debounce slightly to allow Gmail DOM rendering
    setTimeout(extractData, 150);
}

function extractData() {
    if (!isEmailViewActive()) {
        removePopup();
        return;
    }

    const myEmail = getCurrentUserEmail();

    // Collect all message blocks in the opened conversation
    let msgNodes = [...document.querySelectorAll("div[role='main'] .adn")];
    if (msgNodes.length === 0) {
        msgNodes = [...document.querySelectorAll("div[role='main'] div[role='listitem']")];
    }

    let targetMsgNode = null;
    let senderName = "";
    let senderEmail = "";
    let contextType = "incoming"; // "incoming", "reply", "outgoing", "self"
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

        // Filter out the user's own email to find external sender(s)
        const externalMsgs = parsedMsgs.filter(m => !m.isSelf && m.email);

        if (externalMsgs.length > 0) {
            // Reply email thread or incoming message
            contextType = isMultiMessage ? "reply" : "incoming";

            // If an external message is currently expanded, target that one; otherwise target the latest external message
            const expandedExternal = externalMsgs.filter(m => m.isExpanded);
            const chosen = expandedExternal.length > 0
                ? expandedExternal[expandedExternal.length - 1]
                : externalMsgs[externalMsgs.length - 1];

            targetMsgNode = chosen.node;
            senderEmail = chosen.email;
            senderName = chosen.name;
        } else if (parsedMsgs.length > 0) {
            // Thread contains only messages from the user (e.g. Outgoing sent mail)
            const lastSent = parsedMsgs[parsedMsgs.length - 1];
            targetMsgNode = lastSent.node;

            // Check if there is an external recipient
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

    // Fallback for non-standard Gmail layouts
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

    // Expand header details for target message if not already open (to reveal reply-to)
    if (targetMsgNode) {
        const hasDetails = !!targetMsgNode.querySelector("tr.ajv");
        if (!hasDetails) {
            const arrow = targetMsgNode.querySelector("img.ajz, div.ajy");
            if (arrow && arrow.getAttribute("aria-expanded") !== "true") {
                arrow.click();
            }
        }
    }

    // Extract Reply-To specifically from the target message container
    let replyTo = "";
    if (targetMsgNode) {
        const replyRow = [...targetMsgNode.querySelectorAll("tr.ajv")]
            .find(r => r.querySelector(".gG .gI")?.textContent.trim().toLowerCase().startsWith("reply-to"));
        replyTo = replyRow?.querySelector(".gL [email]")?.getAttribute("email") || "";
    }

    const uniqueKey = `${senderName}_${senderEmail}_${contextType}`;
    if (uniqueKey === currentEmailKey) return;

    currentEmailKey = uniqueKey;
    popupClosed = false;

    analyzeEmail(senderName, senderEmail, replyTo, targetMsgNode, { contextType, myEmail });
}


// ============================================================
//                       MAIN ANALYSIS
// ============================================================

async function analyzeEmail(name, email, replyTo, targetMsgNode, contextMeta = {}) {
    lastAnalysisParams = { name, email, replyTo, targetMsgNode, contextMeta };

    const domain = email.includes("@") ? email.split("@")[1] : "";
    const warnings = [];
    const mxLogs = [];
    const attachLogs = [];

    // Check Safe Senders Database
    const safeMatch = matchSafeSender(email, cachedSafeList);
    const isSafe = !!safeMatch;

    if (contextMeta.contextType === "self") {
        createOrUpdatePopup(name, email, replyTo, warnings, mxLogs, attachLogs, {
            ...contextMeta,
            isSelf: true,
            isSafe: true,
            safeMatch: "Your own account"
        });
        return;
    }

    // Only flag typo/phishing if not marked safe
    if (!isSafe) {
        if (domain && isTypo(domain)) {
            warnings.push("❗ Possible Typo-squatting Domain");
        }

        if (domain && hasPhishingPattern(domain)) {
            warnings.push("❗ Suspicious Subdomain / Phishing Pattern");
        }
    }

    if (domain) {
        const mxResult = await checkMX(domain);
        if (!mxResult.hasMX) {
            mxLogs.push("❗ No MX Records Found; Domain cannot receive emails.");
        } else {
            mxLogs.push(`✔ MX Record Found: ${mxResult.mxRecords[0]}`);
        }
    }

    const attachments = detectAttachments(targetMsgNode);
    if (attachments.length > 0) {
        const risks = analyzeAttachmentRisks(attachments);
        attachLogs.push(...risks);
    }

    createOrUpdatePopup(name, email, replyTo, warnings, mxLogs, attachLogs, {
        ...contextMeta,
        isSafe,
        safeMatch,
        domain
    });
}


// ============================================================
//                   ATTACHMENT DETECTION
// ============================================================

function detectAttachments(targetMsgNode) {
    const scope = targetMsgNode || document.querySelector("div[role='main']") || document;
    const nodes = scope.querySelectorAll("div.aQH span.aZo, div.aQH .aV3");
    const files = [];

    nodes.forEach(node => {
        const filename = node.innerText.trim();
        if (filename) files.push(filename.toLowerCase());
    });

    return files;
}

function analyzeAttachmentRisks(files) {
    const highRisk = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".jar", ".msi", ".ps1", ".hta", ".html", ".htm", ".xlsm", ".docm"];
    const mediumRisk = [".zip", ".rar", ".7z", ".iso"];

    const logs = [];
    files.forEach(file => {
        const ext = file.substring(file.lastIndexOf("."));
        if (highRisk.includes(ext)) {
            logs.push(`❗ Dangerous attachment detected: <b>${file}</b>`);
        } else if (mediumRisk.includes(ext)) {
            logs.push(`⚠ Suspicious compressed file: <b>${file}</b>`);
        }
    });

    return logs;
}


// ============================================================
//                        MX CHECK
// ============================================================

async function checkMX(domain) {
    const url = `https://dns.google/resolve?name=${domain}&type=MX`;
    try {
        const res = await fetch(url);
        const data = await res.json();
        if (!data.Answer) return { hasMX: false };

        return {
            hasMX: true,
            mxRecords: data.Answer.map(r => r.data)
        };
    } catch {
        return { hasMX: false };
    }
}


// ============================================================
//                      TYPO & PHISHING CHECKS
// ============================================================

function isTypo(domain) {
    const checks = ["rn", "vv", "0", "1", "lll", "-", "–"];
    return checks.some(x => domain.toLowerCase().includes(x));
}

function hasPhishingPattern(domain) {
    return (
        domain.split(".").length > 4 ||
        domain.includes("secure") ||
        domain.includes("verify") ||
        domain.includes("auth") ||
        domain.length > 30
    );
}


// ============================================================
//                       POPUP RENDER
// ============================================================

function createOrUpdatePopup(name, email, replyTo, warnings, mxLogs, attachLogs, meta = {}) {
    if (popupClosed) return;
    if (!isEmailViewActive()) {
        removePopup();
        return;
    }

    let box = document.getElementById("sender-popup-box");
    if (!box) {
        box = document.createElement("div");
        box.id = "sender-popup-box";
        box.className = "sender-popup";
        document.body.appendChild(box);
        makeDraggable(box);
    }

    const { contextType = "incoming", isSafe = false, safeMatch = "", isSelf = false, domain = "" } = meta;

    // Header context tag
    let contextTagHtml = "";
    if (contextType === "reply") {
        contextTagHtml = `<div class="context-tag reply">💬 External Sender (Reply Thread)</div>`;
    } else if (contextType === "outgoing") {
        contextTagHtml = `<div class="context-tag outgoing">📤 Outgoing Email (Recipient Check)</div>`;
    } else if (contextType === "self") {
        contextTagHtml = `<div class="context-tag self">👤 Sent by you (Internal Email)</div>`;
    } else {
        contextTagHtml = `<div class="context-tag incoming">📩 Incoming Sender</div>`;
    }

    // Safe sender status banner
    let safeSectionHtml = "";
    let safeBtnHtml = "";

    if (isSelf) {
        safeSectionHtml = `
            <div class="safe-badge">
                <span class="safe-badge-icon">ℹ️</span>
                <div>
                    <div class="safe-badge-title">Internal / Self-Sent Message</div>
                    <div class="safe-badge-sub">This email was sent by your own logged-in account.</div>
                </div>
            </div>`;
    } else if (isSafe) {
        safeSectionHtml = `
            <div class="safe-badge">
                <span class="safe-badge-icon">🛡️</span>
                <div>
                    <div class="safe-badge-title">Trusted / Safe Sender</div>
                    <div class="safe-badge-sub">Matched: <b>${escapeHtml(safeMatch)}</b> in Safe Database</div>
                </div>
            </div>`;
        safeBtnHtml = `
            <button id="toggle-safe-btn" class="safe-toggle-btn remove" data-target="${escapeHtml(safeMatch)}">
                Remove "${escapeHtml(safeMatch)}" from Safe List
            </button>`;
    } else if (domain) {
        safeBtnHtml = `
            <button id="toggle-safe-btn" class="safe-toggle-btn add" data-target="${escapeHtml(domain)}">
                ➕ Trust "${escapeHtml(domain)}" (Add to Safe List)
            </button>`;
    }

    const redIssues = [...warnings, ...attachLogs];
    const redSection = redIssues.length
        ? `<div class="warning-section">${redIssues.join("<br>")}</div>`
        : "";

    const mxSection = mxLogs.length
        ? `<div class="mx-section"><b>MX Status:</b><br>${mxLogs.join("<br>")}</div>`
        : "";

    const noWarnings = redIssues.length === 0;
    const mxIsClean = mxLogs.every(l => !l.includes("❗"));

    const greenSection = (!isSafe && !isSelf && noWarnings && mxIsClean && mxLogs.length > 0)
        ? `<div class="safe-section">✔ No major warnings detected</div>`
        : "";

    const replyToHtml = replyTo ? `<b>Reply-To:</b> ${escapeHtml(replyTo)}<br>` : "";
    const roleLabel = (contextType === "outgoing") ? "Recipient:" : "Email:";

    box.innerHTML = `
        <div class="drag-header">
            <div class="drag-title">
                <span>🛡️</span>
                <span>Email Verifier</span>
            </div>
            <button id="close-popup" title="Close">✖</button>
        </div>

        <div class="content">
            ${contextTagHtml}

            <div class="info-section">
                <b>Name:</b> ${escapeHtml(name)}<br>
                <div class="email-row">
                    <b>${roleLabel}</b> <span class="email-text">${escapeHtml(email)}</span>
                </div>
                ${replyToHtml}
            </div>

            ${safeSectionHtml}
            ${safeBtnHtml}
            ${redSection}
            ${greenSection}
            ${mxSection}

            <button id="mismatch-btn" class="action-btn">Find Mismatch</button>

            <div id="mismatch-area" class="hidden">
                <input id="original-email" type="text" placeholder="Enter sender's original email">
                <button id="check-mismatch" class="action-btn small">Check</button>
                <div id="mismatch-result"></div>
            </div>
        </div>

        <div class="credit-box">
            <small>
                Developed by <b>Sabbir Ahmed</b><br>
                <a href="https://www.facebook.com/sabbir299" target="_blank">Facebook</a> &bull;
                <a href="https://github.com/sabbir-21" target="_blank">GitHub</a><br>
                <a href="#" id="open-options-link" class="options-link">⚙️ Safe Senders & Settings</a>
            </small>
        </div>
    `;

    // Event listeners
    document.getElementById("close-popup").onclick = () => {
        box.remove();
        popupClosed = true;
    };

    const toggleSafeBtn = document.getElementById("toggle-safe-btn");
    if (toggleSafeBtn) {
        toggleSafeBtn.onclick = () => {
            const targetVal = toggleSafeBtn.getAttribute("data-target");
            toggleSenderSafeStatus(targetVal);
        };
    }

    document.getElementById("mismatch-btn").onclick = () => {
        document.getElementById("mismatch-area").classList.toggle("hidden");
    };

    document.getElementById("check-mismatch").onclick = () => {
        const userInput = document.getElementById("original-email").value.trim().toLowerCase();
        const resultEl = document.getElementById("mismatch-result");

        if (!userInput.includes("@")) {
            resultEl.innerHTML = "⚠ Please enter a valid email.";
            return;
        }

        resultEl.innerHTML =
            userInput === email.toLowerCase()
                ? "✔ E-mail match. Sender is likely legitimate."
                : `❗ E-mail mismatch.<br>Sender: <b>${escapeHtml(email)}</b><br>Official: <b>${escapeHtml(userInput)}</b>`;
    };

    const optionsLink = document.getElementById("open-options-link");
    if (optionsLink) {
        optionsLink.onclick = (e) => {
            e.preventDefault();
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

    const header = element.querySelector(".drag-header");
    if (header) {
        header.onmousedown = dragMouseDown;
    }

    function dragMouseDown(e) {
        if (e.target.id === "close-popup") return;
        e.preventDefault();
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDrag;
        document.onmousemove = dragElement;
    }

    function dragElement(e) {
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        element.style.top = (element.offsetTop - pos2) + "px";
        element.style.left = (element.offsetLeft - pos1) + "px";
    }

    function closeDrag() {
        document.onmouseup = null;
        document.onmousemove = null;
    }
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
