// ============================================================
//              EMAIL VERIFIER - OPTIONS SCRIPT
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

let currentSenders = [];
let currentTrustedRecords = [];
let currentInstitutions = [];
let currentHistory = {};
let currentSettings = { lang: "en", dohEnabled: true, academicProtection: true };
let currentFilter = "all"; // "all" | "domain" | "email"

// DOM Elements
const newSenderInput = document.getElementById("new-sender-input");
const newSenderNote = document.getElementById("new-sender-note");
const addSenderBtn = document.getElementById("add-sender-btn");
const addFeedback = document.getElementById("add-feedback");
const searchInput = document.getElementById("search-input");
const sendersList = document.getElementById("senders-list");
const entriesCount = document.getElementById("entries-count");
const resetDefaultsBtn = document.getElementById("reset-defaults-btn");
const clearAllBtn = document.getElementById("clear-all-btn");

// Academic Protection Elements
const toggleAcademicProtection = document.getElementById("toggle-academic-protection");
const newInstDomain = document.getElementById("new-inst-domain");
const newInstName = document.getElementById("new-inst-name");
const addInstBtn = document.getElementById("add-inst-btn");
const instFeedback = document.getElementById("inst-feedback");
const instList = document.getElementById("inst-list");

// History & Settings Elements
const historyList = document.getElementById("history-list");
const clearHistoryBtn = document.getElementById("clear-history-btn");
const langSelect = document.getElementById("lang-select");
const toggleDoh = document.getElementById("toggle-doh");
const exportBtn = document.getElementById("export-btn");
const importFileInput = document.getElementById("import-file-input");
const backupFeedback = document.getElementById("backup-feedback");

// Initialization
document.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    loadAllData();
    setupEventListeners();
});

function setupTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
}

function setupEventListeners() {
    // Safe senders events
    addSenderBtn.addEventListener("click", handleAddSender);
    newSenderInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") handleAddSender();
    });
    newSenderNote.addEventListener("keydown", (e) => {
        if (e.key === "Enter") handleAddSender();
    });

    searchInput.addEventListener("input", renderList);
    resetDefaultsBtn.addEventListener("click", handleResetDefaults);
    clearAllBtn.addEventListener("click", handleClearAll);

    // Filter buttons
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.getAttribute("data-filter");
            renderList();
        });
    });

    // Academic protection events
    if (toggleAcademicProtection) {
        toggleAcademicProtection.addEventListener("change", () => {
            currentSettings.academicProtection = toggleAcademicProtection.checked;
            saveSettings();
        });
    }

    if (addInstBtn) {
        addInstBtn.addEventListener("click", handleAddInstitution);
        newInstDomain.addEventListener("keydown", (e) => {
            if (e.key === "Enter") handleAddInstitution();
        });
    }

    // Sender history
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener("click", handleClearHistory);
    }

    // Settings
    if (langSelect) {
        langSelect.addEventListener("change", () => {
            currentSettings.lang = langSelect.value;
            if (typeof EmailVerifierI18n !== "undefined") {
                EmailVerifierI18n.setLang(currentSettings.lang);
            }
            saveSettings();
        });
    }

    if (toggleDoh) {
        toggleDoh.addEventListener("change", () => {
            currentSettings.dohEnabled = toggleDoh.checked;
            saveSettings();
        });
    }

    // Backup & Restore
    if (exportBtn) {
        exportBtn.addEventListener("click", handleExportBackup);
    }

    if (importFileInput) {
        importFileInput.addEventListener("change", handleImportBackup);
    }

    // Storage change listener
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === "local") {
                if (changes.safeSenders) {
                    currentSenders = changes.safeSenders.newValue || [];
                    renderList();
                }
                if (changes.trustedInstitutions) {
                    currentInstitutions = changes.trustedInstitutions.newValue || [];
                    renderInstitutions();
                }
                if (changes.senderHistory) {
                    currentHistory = changes.senderHistory.newValue || {};
                    renderHistory();
                }
            }
        });
    }
}

function loadAllData() {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
        currentSenders = [...DEFAULT_SAFE_DOMAINS];
        renderList();
        return;
    }

    chrome.storage.local.get([
        "safeSenders",
        "trustedRecords",
        "trustedInstitutions",
        "senderHistory",
        "settings"
    ], (result) => {
        // Safe Senders
        if (result && Array.isArray(result.safeSenders) && result.safeSenders.length > 0) {
            currentSenders = result.safeSenders;
            currentTrustedRecords = Array.isArray(result.trustedRecords) ? result.trustedRecords : [];
        } else {
            currentSenders = [...DEFAULT_SAFE_DOMAINS];
            currentTrustedRecords = currentSenders.map(s => ({
                value: s,
                type: s.includes("@") ? "email" : "domain",
                category: "general",
                note: "Default safe sender",
                addedAt: new Date().toISOString()
            }));
            chrome.storage.local.set({
                safeSenders: currentSenders,
                trustedRecords: currentTrustedRecords
            });
        }
        renderList();

        // Academic Institutions
        currentInstitutions = Array.isArray(result.trustedInstitutions) ? result.trustedInstitutions : [];
        renderInstitutions();

        // Sender History
        currentHistory = (result.senderHistory && typeof result.senderHistory === "object") ? result.senderHistory : {};
        renderHistory();

        // Settings
        if (result.settings) {
            currentSettings = { ...currentSettings, ...result.settings };
            if (langSelect) langSelect.value = currentSettings.lang || "en";
            if (toggleDoh) toggleDoh.checked = currentSettings.dohEnabled !== false;
            if (toggleAcademicProtection) toggleAcademicProtection.checked = currentSettings.academicProtection !== false;
        }
    });
}

function saveSafeSenders(list, records = null) {
    currentSenders = list;
    if (records) currentTrustedRecords = records;

    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
            safeSenders: list,
            trustedRecords: currentTrustedRecords
        }, () => {
            renderList();
        });
    } else {
        renderList();
    }
}

function saveSettings() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ settings: currentSettings });
    }
}

// -------------------------------------------------------------
// SAFE SENDERS LOGIC
// -------------------------------------------------------------

function handleAddSender() {
    const rawVal = newSenderInput.value.trim().toLowerCase();
    const noteVal = newSenderNote.value.trim();
    showFeedback(addFeedback, "", "");

    if (!rawVal) {
        showFeedback(addFeedback, "Please enter a domain or email address.", "error");
        return;
    }

    let cleaned = rawVal.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^@/, "");

    const isEmail = cleaned.includes("@") && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleaned);
    const isDomain = !cleaned.includes("@") && /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleaned);

    if (!isEmail && !isDomain) {
        showFeedback(addFeedback, "Please enter a valid domain (e.g. example.com) or email (e.g. user@example.com).", "error");
        return;
    }

    if (currentSenders.includes(cleaned)) {
        showFeedback(addFeedback, `"${cleaned}" is already in the safe list!`, "error");
        return;
    }

    const updated = [cleaned, ...currentSenders];
    const newRecord = {
        value: cleaned,
        type: isEmail ? "email" : "domain",
        category: "general",
        note: noteVal || (isEmail ? "Trusted address" : "Trusted domain"),
        addedAt: new Date().toISOString()
    };
    const updatedRecords = [newRecord, ...currentTrustedRecords];

    saveSafeSenders(updated, updatedRecords);
    newSenderInput.value = "";
    newSenderNote.value = "";
    showFeedback(addFeedback, `Successfully added "${cleaned}" to safe senders!`, "success");
}

function handleRemoveSender(entry) {
    const updated = currentSenders.filter(item => item !== entry);
    const updatedRecords = currentTrustedRecords.filter(item => item.value !== entry);
    saveSafeSenders(updated, updatedRecords);
}

function handleResetDefaults() {
    if (confirm("Reset safe database to default common domains? Any custom additions will be replaced.")) {
        const defaultRecords = DEFAULT_SAFE_DOMAINS.map(s => ({
            value: s,
            type: "domain",
            category: "general",
            note: "Default safe domain",
            addedAt: new Date().toISOString()
        }));
        saveSafeSenders([...DEFAULT_SAFE_DOMAINS], defaultRecords);
        showFeedback(addFeedback, "Reset safe senders to defaults.", "success");
    }
}

function handleClearAll() {
    if (confirm("Are you sure you want to clear all safe senders?")) {
        saveSafeSenders([], []);
        showFeedback(addFeedback, "All safe senders removed.", "success");
    }
}

function renderList() {
    const query = searchInput.value.trim().toLowerCase();
    entriesCount.textContent = currentSenders.length;

    let filtered = currentSenders.filter(item => item.toLowerCase().includes(query));

    if (currentFilter === "domain") {
        filtered = filtered.filter(item => !item.includes("@"));
    } else if (currentFilter === "email") {
        filtered = filtered.filter(item => item.includes("@"));
    }

    if (filtered.length === 0) {
        sendersList.innerHTML = `
            <div class="empty-state">
                ${query ? "No matching entries found." : "Safe database is currently empty. Add trusted domains above!"}
            </div>
        `;
        return;
    }

    // Build map for notes
    const recordMap = new Map();
    for (const r of currentTrustedRecords) {
        if (r && r.value) recordMap.set(r.value.toLowerCase(), r);
    }

    sendersList.innerHTML = filtered.map(item => {
        const isEmail = item.includes("@");
        const typeTag = isEmail
            ? '<span class="sender-type-tag type-email">Email</span>'
            : '<span class="sender-type-tag type-domain">Domain</span>';
        const escaped = escapeHtml(item);
        const record = recordMap.get(item.toLowerCase());
        const noteHtml = record && record.note ? `<div class="sender-note">📝 ${escapeHtml(record.note)}</div>` : "";

        return `
            <div class="sender-item">
                <div class="sender-info">
                    <div class="sender-header-line">
                        ${typeTag}
                        <span class="sender-text">${escaped}</span>
                    </div>
                    ${noteHtml}
                </div>
                <button class="remove-btn" data-entry="${escaped}" title="Remove entry">✖</button>
            </div>
        `;
    }).join("");

    sendersList.querySelectorAll(".remove-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const entry = btn.getAttribute("data-entry");
            handleRemoveSender(entry);
        });
    });
}

// -------------------------------------------------------------
// ACADEMIC INSTITUTIONS LOGIC
// -------------------------------------------------------------

function handleAddInstitution() {
    const domainRaw = newInstDomain.value.trim().toLowerCase();
    const nameRaw = newInstName.value.trim();
    showFeedback(instFeedback, "", "");

    if (!domainRaw) {
        showFeedback(instFeedback, "Please enter an official institutional domain.", "error");
        return;
    }

    let cleaned = domainRaw.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^@/, "");
    if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleaned)) {
        showFeedback(instFeedback, "Please enter a valid domain (e.g. harvard.edu).", "error");
        return;
    }

    if (currentInstitutions.some(i => i.domain === cleaned)) {
        showFeedback(instFeedback, `"${cleaned}" is already added!`, "error");
        return;
    }

    const updated = [
        { domain: cleaned, name: nameRaw || cleaned, addedAt: new Date().toISOString() },
        ...currentInstitutions
    ];

    currentInstitutions = updated;
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ trustedInstitutions: updated }, () => {
            renderInstitutions();
        });
    } else {
        renderInstitutions();
    }

    newInstDomain.value = "";
    newInstName.value = "";
    showFeedback(instFeedback, `Added "${cleaned}" to trusted institutions!`, "success");
}

function handleRemoveInstitution(domain) {
    const updated = currentInstitutions.filter(i => i.domain !== domain);
    currentInstitutions = updated;
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ trustedInstitutions: updated }, () => {
            renderInstitutions();
        });
    } else {
        renderInstitutions();
    }
}

function renderInstitutions() {
    if (!instList) return;

    if (currentInstitutions.length === 0) {
        instList.innerHTML = `<div class="empty-state">No official academic institutions configured yet. Add your university domain above!</div>`;
        return;
    }

    instList.innerHTML = currentInstitutions.map(inst => `
        <div class="sender-item">
            <div class="sender-info">
                <div class="sender-header-line">
                    <span class="sender-type-tag type-academic">University</span>
                    <span class="sender-text">${escapeHtml(inst.domain)}</span>
                </div>
                ${inst.name ? `<div class="sender-note">🏛️ ${escapeHtml(inst.name)}</div>` : ""}
            </div>
            <button class="remove-btn" data-inst="${escapeHtml(inst.domain)}" title="Remove institution">✖</button>
        </div>
    `).join("");

    instList.querySelectorAll(".remove-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const dom = btn.getAttribute("data-inst");
            handleRemoveInstitution(dom);
        });
    });
}

// -------------------------------------------------------------
// SENDER HISTORY LOGIC
// -------------------------------------------------------------

function renderHistory() {
    if (!historyList) return;

    const entries = Object.values(currentHistory);
    if (entries.length === 0) {
        historyList.innerHTML = `<div class="empty-state">No sender history recorded yet. Senders observed in Gmail will appear here.</div>`;
        return;
    }

    // Sort by last seen descending
    entries.sort((a, b) => (b.lastSeen || "").localeCompare(a.lastSeen || ""));

    historyList.innerHTML = entries.map(item => {
        const lastSeenDate = item.lastSeen ? new Date(item.lastSeen).toLocaleDateString() : "N/A";
        const names = (item.observedNames || []).join(", ") || "Unknown";
        return `
            <div class="sender-item">
                <div class="sender-info">
                    <div class="sender-header-line">
                        <span class="sender-text">${escapeHtml(item.email)}</span>
                        <span class="badge-count">${item.count || 1} emails</span>
                    </div>
                    <div class="sender-note">👤 ${escapeHtml(names)} &bull; Last seen: ${lastSeenDate}</div>
                </div>
            </div>
        `;
    }).join("");
}

function handleClearHistory() {
    if (confirm("Clear all recorded sender history?")) {
        currentHistory = {};
        if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({ senderHistory: {} }, () => {
                renderHistory();
            });
        } else {
            renderHistory();
        }
    }
}

// -------------------------------------------------------------
// BACKUP & RESTORE
// -------------------------------------------------------------

function handleExportBackup() {
    if (typeof SenderHistory === "undefined") return;

    const payload = SenderHistory.createExportPayload(currentTrustedRecords, currentInstitutions);
    const jsonStr = JSON.stringify(payload, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `email-verifier-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    showFeedback(backupFeedback, "Backup file generated and downloaded successfully!", "success");
}

function handleImportBackup(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
        const text = event.target.result;
        if (typeof SenderHistory === "undefined") return;

        const validation = SenderHistory.validateImportData(text);
        if (!validation.valid) {
            showFeedback(backupFeedback, `Import failed: ${validation.error}`, "error");
            return;
        }

        // Merge imported data safely
        const existingValues = new Set(currentSenders.map(s => s.toLowerCase()));
        const newRecords = [...currentTrustedRecords];
        const newSenders = [...currentSenders];

        for (const r of validation.trustedRecords) {
            if (!existingValues.has(r.value.toLowerCase())) {
                existingValues.add(r.value.toLowerCase());
                newSenders.push(r.value);
                newRecords.push(r);
            }
        }

        saveSafeSenders(newSenders, newRecords);

        // Merge institutions
        if (validation.trustedInstitutions && validation.trustedInstitutions.length > 0) {
            const instMap = new Map();
            for (const i of currentInstitutions) instMap.set(i.domain, i);
            for (const i of validation.trustedInstitutions) instMap.set(i.domain, i);
            currentInstitutions = Array.from(instMap.values());
            if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
                chrome.storage.local.set({ trustedInstitutions: currentInstitutions });
            }
            renderInstitutions();
        }

        showFeedback(backupFeedback, `Successfully imported ${validation.trustedRecords.length} records!`, "success");
        importFileInput.value = "";
    };

    reader.readAsText(file);
}

function showFeedback(el, text, type) {
    if (!el) return;
    el.textContent = text;
    el.className = "feedback-msg " + (type || "");
    if (text) {
        setTimeout(() => {
            if (el.textContent === text) {
                el.textContent = "";
                el.className = "feedback-msg";
            }
        }, 3500);
    }
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
