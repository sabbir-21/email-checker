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

// DOM Elements
const newSenderInput = document.getElementById("new-sender-input");
const addSenderBtn = document.getElementById("add-sender-btn");
const addFeedback = document.getElementById("add-feedback");
const searchInput = document.getElementById("search-input");
const sendersList = document.getElementById("senders-list");
const entriesCount = document.getElementById("entries-count");
const resetDefaultsBtn = document.getElementById("reset-defaults-btn");
const clearAllBtn = document.getElementById("clear-all-btn");

// Initialization
document.addEventListener("DOMContentLoaded", () => {
    loadSafeSenders();
    setupEventListeners();
});

function setupEventListeners() {
    addSenderBtn.addEventListener("click", handleAddSender);
    newSenderInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") handleAddSender();
    });

    searchInput.addEventListener("input", renderList);
    resetDefaultsBtn.addEventListener("click", handleResetDefaults);
    clearAllBtn.addEventListener("click", handleClearAll);

    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === "local" && changes.safeSenders) {
                currentSenders = changes.safeSenders.newValue || [];
                renderList();
            }
        });
    }
}

function loadSafeSenders() {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
        currentSenders = [...DEFAULT_SAFE_DOMAINS];
        renderList();
        return;
    }

    chrome.storage.local.get(["safeSenders"], (result) => {
        if (result && Array.isArray(result.safeSenders) && result.safeSenders.length > 0) {
            currentSenders = result.safeSenders;
        } else {
            currentSenders = [...DEFAULT_SAFE_DOMAINS];
            chrome.storage.local.set({ safeSenders: currentSenders });
        }
        renderList();
    });
}

function saveSafeSenders(list) {
    currentSenders = list;
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ safeSenders: list }, () => {
            renderList();
        });
    } else {
        renderList();
    }
}

function handleAddSender() {
    const rawVal = newSenderInput.value.trim().toLowerCase();
    showFeedback("", "");

    if (!rawVal) {
        showFeedback("Please enter a domain or email address.", "error");
        return;
    }

    // Clean value (strip http://, https://, @ prefix if accidentally pasted)
    let cleaned = rawVal.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^@/, "");

    // Basic format validation
    const isEmail = cleaned.includes("@") && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleaned);
    const isDomain = !cleaned.includes("@") && /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleaned);

    if (!isEmail && !isDomain) {
        showFeedback("Please enter a valid domain (e.g. example.com) or email (e.g. user@example.com).", "error");
        return;
    }

    if (currentSenders.includes(cleaned)) {
        showFeedback(`"${cleaned}" is already in the safe list!`, "error");
        return;
    }

    const updated = [cleaned, ...currentSenders];
    saveSafeSenders(updated);
    newSenderInput.value = "";
    showFeedback(`Successfully added "${cleaned}" to safe senders!`, "success");
}

function handleRemoveSender(entry) {
    const updated = currentSenders.filter(item => item !== entry);
    saveSafeSenders(updated);
}

function handleResetDefaults() {
    if (confirm("Reset safe database to default common domains? Any custom additions will be replaced.")) {
        saveSafeSenders([...DEFAULT_SAFE_DOMAINS]);
        showFeedback("Reset safe senders to defaults.", "success");
    }
}

function handleClearAll() {
    if (confirm("Are you sure you want to clear all safe senders?")) {
        saveSafeSenders([]);
        showFeedback("All safe senders removed.", "success");
    }
}

function showFeedback(text, type) {
    addFeedback.textContent = text;
    addFeedback.className = "feedback-msg " + (type || "");
    if (text) {
        setTimeout(() => {
            if (addFeedback.textContent === text) {
                addFeedback.textContent = "";
                addFeedback.className = "feedback-msg";
            }
        }, 3500);
    }
}

function renderList() {
    const query = searchInput.value.trim().toLowerCase();
    entriesCount.textContent = currentSenders.length;

    const filtered = currentSenders.filter(item => item.toLowerCase().includes(query));

    if (filtered.length === 0) {
        sendersList.innerHTML = `
            <div class="empty-state">
                ${query ? "No matching entries found." : "Safe database is currently empty. Add trusted domains above!"}
            </div>
        `;
        return;
    }

    sendersList.innerHTML = filtered.map(item => {
        const isEmail = item.includes("@");
        const typeTag = isEmail ? '<span class="sender-type-tag type-email">Email</span>' : '<span class="sender-type-tag type-domain">Domain</span>';
        const escaped = escapeHtml(item);

        return `
            <div class="sender-item">
                <div class="sender-info">
                    ${typeTag}
                    <span class="sender-text">${escaped}</span>
                </div>
                <button class="remove-btn" data-entry="${escaped}" title="Remove entry">✖</button>
            </div>
        `;
    }).join("");

    // Attach click listeners to remove buttons
    sendersList.querySelectorAll(".remove-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const entry = btn.getAttribute("data-entry");
            handleRemoveSender(entry);
        });
    });
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
