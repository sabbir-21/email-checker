// ============================================================
//              EMAIL VERIFIER - ATTACHMENT ANALYZER
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.AttachmentAnalyzer = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    // Direct Executables and Script Formats (High Risk)
    const EXECUTABLE_EXTENSIONS = new Set([
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".cpl",
        ".msi", ".jar", ".ps1", ".psm1", ".vbs", ".vbe", ".js",
        ".jse", ".wsf", ".wsh", ".hta", ".reg", ".lnk", ".gadget"
    ]);

    // Macro-Enabled Office Documents (High Risk)
    const MACRO_EXTENSIONS = new Set([
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
        ".xlam", ".ppam", ".docb"
    ]);

    // HTML & Web Page Attachments that often imitate login portals (Medium/High Risk)
    const HTML_EXTENSIONS = new Set([
        ".html", ".htm", ".xhtml", ".svg", ".mhtml", ".mht"
    ]);

    // Compressed Archive Formats (Medium Risk - may conceal dangerous payloads)
    const ARCHIVE_EXTENSIONS = new Set([
        ".zip", ".rar", ".7z", ".iso", ".tar", ".gz", ".cab",
        ".img", ".dmg", ".bz2", ".xz", ".ace", ".arj"
    ]);

    // Harmless, standard media/document extensions
    const COMMON_SAFE_EXTENSIONS = new Set([
        ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4"
    ]);

    /**
     * Extracts all file extension parts (e.g. "invoice.pdf.exe" -> [".pdf", ".exe"])
     */
    function getExtensionParts(filename) {
        if (!filename) return [];
        const clean = filename.trim().toLowerCase();
        const base = clean.split(/[/\\]/).pop(); // basename
        const parts = base.split(".");
        if (parts.length <= 1) return [];

        // Return parts with leading dot
        return parts.slice(1).map(p => "." + p);
    }

    /**
     * Inspects a single attachment filename for security risks.
     */
    function inspectAttachment(filename) {
        if (!filename) return null;

        const clean = filename.trim();
        const lower = clean.toLowerCase();
        const extParts = getExtensionParts(lower);
        const finalExt = extParts.length > 0 ? extParts[extParts.length - 1] : "";
        const issues = [];

        // 1. Double extension check (e.g. filename.pdf.exe, report.docx.vbs)
        if (extParts.length >= 2) {
            const penultimateExt = extParts[extParts.length - 2];
            if (COMMON_SAFE_EXTENSIONS.has(penultimateExt) && (EXECUTABLE_EXTENSIONS.has(finalExt) || MACRO_EXTENSIONS.has(finalExt) || ARCHIVE_EXTENSIONS.has(finalExt) || HTML_EXTENSIONS.has(finalExt))) {
                issues.push({
                    type: "DOUBLE_EXTENSION",
                    severity: "high",
                    filename: clean,
                    message: `Misleading double file extension detected: "${clean}". It appears as a document (${penultimateExt}) but executes as ${finalExt}.`,
                    recommendation: "Do not open this file. Attackers use double extensions to trick recipients into executing code."
                });
            }
        }

        // 2. High Risk Executables / Scripts
        if (EXECUTABLE_EXTENSIONS.has(finalExt)) {
            issues.push({
                type: "EXECUTABLE_FILE",
                severity: "high",
                filename: clean,
                message: `Executable or script attachment: "${clean}" (${finalExt}).`,
                recommendation: "Never open executable email attachments. Verify sender before interacting."
            });
        }

        // 3. Macro-Enabled Office Documents
        if (MACRO_EXTENSIONS.has(finalExt)) {
            issues.push({
                type: "MACRO_DOCUMENT",
                severity: "high",
                filename: clean,
                message: `Macro-enabled Office document: "${clean}" (${finalExt}). Embedded macros can execute malicious scripts upon opening.`,
                recommendation: "Do not enable macros or content if opening this file. Consult your organization's IT department."
            });
        }

        // 4. HTML / Web Page Attachments (Cred phishing / form injection)
        if (HTML_EXTENSIONS.has(finalExt)) {
            issues.push({
                type: "HTML_ATTACHMENT",
                severity: "medium",
                filename: clean,
                message: `HTML web file attached: "${clean}". Phishing emails commonly attach HTML files to present offline fake login forms.`,
                recommendation: "Do not enter passwords or credentials into pages opened from email attachments."
            });
        }

        // 5. Compressed Archives
        if (ARCHIVE_EXTENSIONS.has(finalExt)) {
            const isEncryptedHint = lower.includes("pass") || lower.includes("encrypted") || lower.includes("secure") || lower.includes("protected");
            issues.push({
                type: "ARCHIVE_ATTACHMENT",
                severity: isEncryptedHint ? "high" : "medium",
                filename: clean,
                message: isEncryptedHint
                    ? `Encrypted/password-hinted archive detected: "${clean}". Attackers often password-protect archives to bypass automated email scanner inspection.`
                    : `Compressed archive attached: "${clean}" (${finalExt}). May contain hidden scripts or executables.`,
                recommendation: "Carefully inspect the extracted file types before opening them."
            });
        }

        return {
            filename: clean,
            finalExt,
            hasRisk: issues.length > 0,
            issues
        };
    }

    /**
     * Inspects a list of attachment filenames.
     */
    function analyzeAttachments(fileList = []) {
        const results = [];
        for (const file of fileList) {
            const name = typeof file === "string" ? file : file.name;
            const res = inspectAttachment(name);
            if (res && res.hasRisk) {
                results.push(res);
            }
        }
        return results;
    }

    return {
        EXECUTABLE_EXTENSIONS,
        MACRO_EXTENSIONS,
        HTML_EXTENSIONS,
        ARCHIVE_EXTENSIONS,
        COMMON_SAFE_EXTENSIONS,
        inspectAttachment,
        analyzeAttachments
    };
});
