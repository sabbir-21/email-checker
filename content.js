let currentEmail = "";   // Track which email is open
let popupClosed = false; // Track if user closed popup manually

// Observe Gmail UI changes
const observer = new MutationObserver(() => {
    updateSenderInfo();
});

observer.observe(document.body, { childList: true, subtree: true });

function updateSenderInfo() {
    const nameEl = document.querySelector(".gD"); // sender name
    let email = nameEl?.getAttribute("email");

    // Gmail sometimes stores email in .go
    if (!email) {
        const alt = document.querySelector(".go");
        email = alt?.getAttribute("email");
    }

    if (!nameEl || !email) return;

    const name = nameEl.innerText;
    const emailID = email;

    // detect a new email opened
    const uniqueKey = name + emailID;
    if (uniqueKey === currentEmail) return; // no change

    currentEmail = uniqueKey;   // update email reference
    popupClosed = false;        // allow popup to show for new email

    createOrUpdatePopup(name, emailID);
}

function createOrUpdatePopup(name, email) {
    let box = document.getElementById("sender-popup-box");

    // If user closed the popup manually, do not recreate until new email opens
    if (popupClosed) return;

    if (!box) {
        box = document.createElement("div");
        box.id = "sender-popup-box";
        box.className = "sender-popup";
        document.body.appendChild(box);
        makeDraggable(box); // enable dragging
    }

    box.innerHTML = `
        <div class="drag-header">
            <strong>Sender Info</strong>
            <button id="close-popup">✖</button>
        </div>
        <div class="content">
            <b>Name:</b> ${name}<br>
            <b>Email:</b> ${email}
        </div>
    `;

    // Close button action
    document.getElementById("close-popup").onclick = () => {
        box.remove();
        popupClosed = true; // keep popup closed for this email
    };
}


// ------------------ DRAGGABLE FUNCTION ------------------ //
function makeDraggable(element) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

    // This observer ensures drag-header exists (because we re-render HTML)
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
