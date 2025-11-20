let currentEmail = "";
let popupClosed = false;

const observer = new MutationObserver(() => {
    updateSenderInfo();
});

observer.observe(document.body, { childList: true, subtree: true });

function updateSenderInfo() {
    const nameEl = document.querySelector(".gD");
    let email = nameEl?.getAttribute("email");

    if (!email) {
        const alt = document.querySelector(".go");
        email = alt?.getAttribute("email");
    }

    if (!nameEl || !email) return;

    // Get Reply-To
    const replyToEl = document.querySelector(".gI");
    let replyTo = replyToEl ? replyToEl.getAttribute("email") : "N/A";

    const name = nameEl.innerText;
    const emailID = email;
    const uniqueKey = name + emailID;

    if (uniqueKey === currentEmail) return;

    currentEmail = uniqueKey;
    popupClosed = false;

    analyzeEmail(name, emailID, replyTo);
}


// ===============================
//        MAIN ANALYSIS
// ===============================
async function analyzeEmail(name, email, replyTo) {
    const domain = email.split("@")[1];

    const warnings = []; // RED
    const mxLogs = [];   // YELLOW

    // 1. Typo Check
    if (isTypo(domain)) {
        warnings.push("❗ Possible Typo-squatting Domain");
    }

    // 2. Suspicious Pattern
    if (hasPhishingPattern(domain)) {
        warnings.push("❗ Suspicious Subdomain / Phishing Pattern");
    }

    // 3. MX Check
    const mxResult = await checkMX(domain);

    if (!mxResult.hasMX) {
        mxLogs.push("❗ No MX Records Found; Domain cannot receive emails.");
    } else {
        mxLogs.push(`✔ MX Record Found: ${mxResult.mxRecords[0]}`);
    }

    createOrUpdatePopup(name, email, replyTo, warnings, mxLogs);
}



// ===============================
//          MX CHECK
// ===============================
async function checkMX(domain) {
    const url = `https://dns.google/resolve?name=${domain}&type=MX`;

    try {
        const res = await fetch(url);
        const data = await res.json();

        if (!data.Answer) {
            return { hasMX: false };
        }

        return {
            hasMX: true,
            mxRecords: data.Answer.map(r => r.data)
        };

    } catch (e) {
        return { hasMX: false };
    }
}



// ===============================
//       TYPO DETECTION
// ===============================
function isTypo(domain) {
    const checks = ["rn", "vv", "0", "1", "lll", "-", "–"];
    const lower = domain.toLowerCase();

    for (const c of checks) {
        if (lower.includes(c)) return true;
    }
    return false;
}



// ===============================
//     HEURISTIC PHISHING CHECK
// ===============================
function hasPhishingPattern(domain) {
    return (
        domain.split(".").length > 4 ||
        domain.includes("secure") ||
        domain.includes("verify") ||
        domain.includes("auth") ||
        domain.length > 30
    );
}



// ===============================
//       POPUP GENERATION
// ===============================
function createOrUpdatePopup(name, email, replyTo, warnings, mxLogs) {
    let box = document.getElementById("sender-popup-box");

    if (popupClosed) return;

    if (!box) {
        box = document.createElement("div");
        box.id = "sender-popup-box";
        box.className = "sender-popup";
        document.body.appendChild(box);
        makeDraggable(box);
    }

    // Red warnings
    const redSection = warnings.length
        ? `<div class="warning-section">${warnings.join("<br>")}</div>`
        : "";

    // SHOW SAFE ONLY IF NOTHING BAD
    const noWarnings = warnings.length === 0;
    const mxIsClean = mxLogs.every(log => !log.includes("❗"));

    const greenSection = (noWarnings && mxIsClean)
        ? `<div class="safe-section">✔ No major warnings detected</div>`
        : "";
    
    // Yellow MX logs
    const mxSection = `
        <div class="mx-section">
            <b>MX Status:</b><br>
            ${mxLogs.join("<br>")}
        </div>
    `;


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
                <input id="original-email" type="text" placeholder="Enter professor's official email">
                <button id="check-mismatch" class="action-btn small">Check</button>
                <div id="mismatch-result"></div>
            </div>
        </div>
    `;

    // Close button
    document.getElementById("close-popup").onclick = () => {
        box.remove();
        popupClosed = true;
    };

    // Expand mismatch section
    document.getElementById("mismatch-btn").onclick = () => {
        document.getElementById("mismatch-area").classList.toggle("hidden");
    };

    // Mismatch check
    document.getElementById("check-mismatch").onclick = () => {
        const userInput = document.getElementById("original-email").value.trim();
        const resultEl = document.getElementById("mismatch-result");

        if (!userInput || !userInput.includes("@")) {
            resultEl.innerHTML = "⚠ Please enter a valid email.";
            return;
        }

        if (email === userInput) {
            resultEl.innerHTML = "✔ E-mail match. Sender is likely legitimate.";
        } else {
            resultEl.innerHTML = `❗ E-mail mismatch detected.<br>
                Sender E-mail: <b>${email}</b><br>
                Official E-mail: <b>${userInput}</b>`;
        }
    };
}



// ===============================
//       DRAGGABLE POPUP
// ===============================
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
        document.onmouseup = closeDragElement;
        document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        element.style.top = (element.offsetTop - pos2) + "px";
        element.style.left = (element.offsetLeft - pos1) + "px";
    }

    function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
    }
}
