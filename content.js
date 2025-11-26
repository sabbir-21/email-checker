let currentEmail = "";
let popupClosed = false;

// Reset-on-new-email
let lastURL = location.href;
let headersExpanded = false;

// Watch for URL changes (Gmail navigation)
setInterval(() => {
    if (location.href !== lastURL) {
        lastURL = location.href;

        // Gmail opened a new email → reset
        headersExpanded = false;
        currentEmail = "";
        popupClosed = false;
    }
}, 500);

// Mutation Observer for DOM changes
const observer = new MutationObserver(updateSenderInfo);
observer.observe(document.body, { childList: true, subtree: true });


// ============================================================
//                EMAIL OPENED → RUN CHECKS
// ============================================================
function updateSenderInfo() {

    // STEP 1: Try to expand "header details" once per email
    if (!headersExpanded) {
        const arrow = document.querySelector("img.ajz");
        if (arrow) {
            arrow.click();
            headersExpanded = true;
        } else {
            // Gmail loads arrow slightly late → retry briefly
            return;
        }
    }

    // STEP 2: Wait for Gmail to inject hidden rows (reply-to)
    setTimeout(extractData, 200);
}


// ============================================================
//               EXTRACT NAME / EMAIL / REPLY-TO
// ============================================================
function extractData() {

    const nameEl = document.querySelector(".gD");
    let email = nameEl?.getAttribute("email");

    if (!email) {
        const alt = document.querySelector(".go");
        email = alt?.getAttribute("email");
    }
    if (!nameEl || !email) return;

    // One-liner reply-to extraction
    const replyTo = [...document.querySelectorAll("tr.ajv")]
        .find(r => r.querySelector(".gG .gI")?.textContent.trim() === "reply-to:")
        ?.querySelector(".gL [email]")
        ?.getAttribute("email") || "";

    const name = nameEl.innerText;
    const emailID = email;
    const replytoEmailID = replyTo;
    const uniqueKey = name + emailID;

    if (uniqueKey === currentEmail) return;

    currentEmail = uniqueKey;
    popupClosed = false;

    analyzeEmail(name, emailID, replytoEmailID);
}



// ============================================================
//                       MAIN ANALYSIS
// ============================================================
async function analyzeEmail(name, email, replyTo) {
    const domain = email.split("@")[1];

    const warnings = [];
    const mxLogs = [];
    const attachLogs = [];

    if (isTypo(domain)) warnings.push("❗ Possible Typo-squatting Domain");

    if (hasPhishingPattern(domain)) warnings.push("❗ Suspicious Subdomain / Phishing Pattern");

    const mxResult = await checkMX(domain);
    if (!mxResult.hasMX) mxLogs.push("❗ No MX Records Found; Domain cannot receive emails.");
    else mxLogs.push(`✔ MX Record Found: ${mxResult.mxRecords[0]}`);

    const attachments = detectAttachments();
    if (attachments.length > 0) {
        const risks = analyzeAttachmentRisks(attachments);
        attachLogs.push(...risks);
    }

    createOrUpdatePopup(name, email, replyTo, warnings, mxLogs, attachLogs);
}



// ============================================================
//                   ATTACHMENT DETECTION
// ============================================================
function detectAttachments() {
    const nodes = document.querySelectorAll("div.aQH span.aZo, div.aQH .aV3");

    const files = [];

    nodes.forEach(node => {
        const filename = node.innerText.trim();
        if (filename) files.push(filename.toLowerCase());
    });

    return files;
}



// ============================================================
//                 ATTACHMENT RISK ANALYSIS
// ============================================================
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
//                      TYPO CHECK
// ============================================================
function isTypo(domain) {
    const checks = ["rn", "vv", "0", "1", "lll", "-", "–"];
    return checks.some(x => domain.toLowerCase().includes(x));
}



// ============================================================
//                PHISHING PATTERN CHECK
// ============================================================
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
function createOrUpdatePopup(name, email, replyTo, warnings, mxLogs, attachLogs) {
    let box = document.getElementById("sender-popup-box");
    if (popupClosed) return;

    if (!box) {
        box = document.createElement("div");
        box.id = "sender-popup-box";
        box.className = "sender-popup";
        document.body.appendChild(box);
        makeDraggable(box);
    }

    const redIssues = [...warnings, ...attachLogs];

    const redSection = redIssues.length
        ? `<div class="warning-section">${redIssues.join("<br>")}</div>`
        : "";

    const mxSection = `
        <div class="mx-section">
            <b>MX Status:</b><br>
            ${mxLogs.join("<br>")}
        </div>`;

    const noWarnings = redIssues.length === 0;
    const mxIsClean = mxLogs.every(l => !l.includes("❗"));

    const greenSection = (noWarnings && mxIsClean)
        ? `<div class="safe-section">✔ No major warnings detected</div>`
        : "";

    box.innerHTML = `
        <div class="drag-header">
            <strong>Email Verifier</strong>
            <button id="close-popup">✖</button>
        </div>

        <div class="content">
            <div class="info-section">
                <b>Name:</b> ${name}<br>

                <div class="email-row">
                    <b>Email:</b> <span class="email-text">${email}</span>
                </div>

                <b>Reply-To:</b> ${replyTo}<br><br>
            </div>

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
                <a href="https://www.facebook.com/sabbir299" target="_blank">Facebook</a> |
                <a href="https://github.com/sabbir-21" target="_blank">GitHub</a>
            </small>
        </div>
    `;

    document.getElementById("close-popup").onclick = () => {
        box.remove();
        popupClosed = true;
    };

    document.getElementById("mismatch-btn").onclick = () => {
        document.getElementById("mismatch-area").classList.toggle("hidden");
    };

    document.getElementById("check-mismatch").onclick = () => {
        const userInput = document.getElementById("original-email").value.trim();
        const resultEl = document.getElementById("mismatch-result");

        if (!userInput.includes("@")) {
            resultEl.innerHTML = "⚠ Please enter a valid email.";
            return;
        }

        resultEl.innerHTML =
            userInput === email
                ? "✔ E-mail match. Sender is likely legitimate."
                : `❗ E-mail mismatch.<br>Sender: <b>${email}</b><br>Official: <b>${userInput}</b>`;
    };
}



// ============================================================
//                   DRAGGABLE POPUP
// ============================================================
function makeDraggable(element) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

    const headerObserver = new MutationObserver(() => {
        const header = element.querySelector(".drag-header");
        if (!header) return;
        header.onmousedown = dragMouseDown;
    });

    headerObserver.observe(element, { childList: true, subtree: true });

    function dragMouseDown(e) {
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
