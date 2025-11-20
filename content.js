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

    // NEW: Get Reply-To
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

function analyzeEmail(name, email, replyTo) {
    const domain = email.split("@")[1];
    const warnings = [];

    if (isTypo(domain)) {
        warnings.push("❗ Possible Typo-squatting Domain");
    }

    if (hasPhishingPattern(domain)) {
        warnings.push("❗ Suspicious Subdomain / Phishing Pattern");
    }

    createOrUpdatePopup(name, email, replyTo, warnings);
}

function isTypo(domain) {
    const checks = ["rn", "vv", "0", "1", "lll", "-", "–"];
    const lower = domain.toLowerCase();

    for (const c of checks) {
        if (lower.includes(c)) return true;
    }
    return false;
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

function createOrUpdatePopup(name, email, replyTo, warnings) {
    let box = document.getElementById("sender-popup-box");

    if (popupClosed) return;

    if (!box) {
        box = document.createElement("div");
        box.id = "sender-popup-box";
        box.className = "sender-popup";
        document.body.appendChild(box);
        makeDraggable(box);
    }

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
                <b>Reply-To:</b> ${replyTo}<br>
            </div>

            ${
                warnings.length
                ? `<div class="warning-section">${warnings.join("<br>")}</div>`
                : `<div class="safe-section">✔ No major warnings detected</div>`
            }

            <button id="mismatch-btn" class="action-btn">Find Mismatch</button>

            <div id="mismatch-area" class="hidden">
                <input id="original-email" type="text" placeholder="Enter professor's official email">
                <button id="check-mismatch" class="action-btn small">Check</button>
                <div id="mismatch-result"></div>
            </div>
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

        if (!userInput || !userInput.includes("@")) {
            resultEl.innerHTML = "⚠ Please enter a valid email.";
            return;
        }

        //const senderDomain = email.split("@")[1];
        //const officialDomain = userInput.split("@")[1];

        if (email === userInput) {
            resultEl.innerHTML = "✔ E-mail match. Sender is likely legitimate.";
        } else {
            resultEl.innerHTML = `❗ E-mail mismatch detected.<br>
                Sender E-mail: <b>${email}</b><br>
                Official E-mail: <b>${userInput}</b>`;
        }
    };
}


// DRAGGABLE WINDOW
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
