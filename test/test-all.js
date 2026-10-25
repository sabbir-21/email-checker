// ============================================================
//              EMAIL VERIFIER - COMPREHENSIVE TEST SUITE
// ============================================================

const assert = require("assert");

// Import modules
const I18n = require("../utils/i18n");
const DomainUtils = require("../utils/domain-utils");
const UrlAnalyzer = require("../utils/url-analyzer");
const AttachmentAnalyzer = require("../utils/attachment-analyzer");
const PhishingDetector = require("../utils/phishing-detector");
const AcademicProtection = require("../utils/academic-protection");
const SenderHistory = require("../utils/sender-history");
const RiskEngine = require("../utils/risk-engine");

let testsPassed = 0;
let testsFailed = 0;

function runTest(name, fn) {
    try {
        fn();
        console.log(`  ✓ ${name}`);
        testsPassed++;
    } catch (err) {
        console.error(`  ✗ ${name}`);
        console.error(`    Error: ${err.message}`);
        testsFailed++;
    }
}

console.log("Starting Email Verifier Test Suite...\n");

// -------------------------------------------------------------
// 1. I18N MODULE TESTS
// -------------------------------------------------------------
console.log("Testing i18n module:");

runTest("i18n returns English strings by default", () => {
    I18n.setLang("en");
    assert.strictEqual(I18n.getLang(), "en");
    assert.strictEqual(I18n.t("riskHigh"), "HIGH RISK");
});

runTest("i18n switches to Bangla successfully", () => {
    I18n.setLang("bn");
    assert.strictEqual(I18n.getLang(), "bn");
    assert.ok(I18n.t("riskHigh").includes("উচ্চ"));
    I18n.setLang("en"); // Reset to English
});

runTest("i18n handles parameter substitution", () => {
    const res = I18n.t("badgeTrustedSub", { match: "google.com" });
    assert.ok(typeof res === "string");
});

// -------------------------------------------------------------
// 2. DOMAIN UTILITIES TESTS
// -------------------------------------------------------------
console.log("\nTesting domain-utils module:");

runTest("extractEmailAddress handles angle brackets and clean strings", () => {
    assert.strictEqual(DomainUtils.extractEmailAddress("John Doe <john@example.com>"), "john@example.com");
    assert.strictEqual(DomainUtils.extractEmailAddress("SUPPORT@SERVICE.COM"), "support@service.com");
    assert.strictEqual(DomainUtils.extractEmailAddress("<alert@bank.org>"), "alert@bank.org");
});

runTest("getRootDomain extracts registrable domain including multi-part SLDs", () => {
    assert.strictEqual(DomainUtils.getRootDomain("mail.google.com"), "google.com");
    assert.strictEqual(DomainUtils.getRootDomain("sub.department.ox.ac.uk"), "ox.ac.uk");
    assert.strictEqual(DomainUtils.getRootDomain("cse.buet.ac.bd"), "buet.ac.bd");
    assert.strictEqual(DomainUtils.getRootDomain("api.store.co.uk"), "store.co.uk");
});

runTest("detectHomoglyphs flags Cyrillic confusables in domain names", () => {
    // 'а' is Cyrillic U+0430, 'р' is Cyrillic U+0440 -> "раураl.com"
    const homoglyphDomain = "\u0440\u0430\u0443\u0440\u0430l.com";
    const res = DomainUtils.detectHomoglyphs(homoglyphDomain);
    assert.strictEqual(res.hasHomoglyphs, true);
    assert.strictEqual(res.normalized, "paypal.com");

    const cleanRes = DomainUtils.detectHomoglyphs("paypal.com");
    assert.strictEqual(cleanRes.hasHomoglyphs, false);
});

runTest("isPunycode flags internationalized domains", () => {
    assert.strictEqual(DomainUtils.isPunycode("xn--pple-43d.com"), true);
    assert.strictEqual(DomainUtils.isPunycode("apple.com"), false);
});

runTest("checkTyposquatting catches edit distance and character substitutions", () => {
    // "paypa1.com" -> visual substitution
    const typo1 = DomainUtils.checkTyposquatting("paypa1.com");
    assert.strictEqual(typo1.isTypo, true);

    // "arnazon.com" -> rn for m
    const typo2 = DomainUtils.checkTyposquatting("arnazon.com");
    assert.strictEqual(typo2.isTypo, true);

    // "googgle.com" -> repeated character
    const typo3 = DomainUtils.checkTyposquatting("googgle.com");
    assert.strictEqual(typo3.isTypo, true);

    // "google.com" itself is not a typo of itself
    const clean = DomainUtils.checkTyposquatting("google.com");
    assert.strictEqual(clean.isTypo, false);
});

runTest("checkDeceptiveSubdomain flags brand in subdomain of unrelated root", () => {
    const deceptive = DomainUtils.checkDeceptiveSubdomain("paypal.com.account-update.xyz");
    assert.strictEqual(deceptive.isDeceptive, true);
    assert.strictEqual(deceptive.rootDomain, "account-update.xyz");

    const normal = DomainUtils.checkDeceptiveSubdomain("mail.google.com");
    assert.strictEqual(normal.isDeceptive, false);
});

runTest("checkFreeEmailImpersonation detects organizational role in display name with free email", () => {
    const imp = DomainUtils.checkFreeEmailImpersonation("Bank of America Support", "support12938@gmail.com");
    assert.strictEqual(imp.isImpersonation, true);

    // Regular personal display name with free email is NOT flagged
    const normal = DomainUtils.checkFreeEmailImpersonation("John Doe", "john.doe@gmail.com");
    assert.strictEqual(normal.isImpersonation, false);
});

runTest("checkReplyToMismatch detects mismatch and flags corporate -> free email drift", () => {
    const mismatch = DomainUtils.checkReplyToMismatch("support@company.com", "hacker123@yahoo.com");
    assert.strictEqual(mismatch.hasMismatch, true);
    assert.strictEqual(mismatch.severity, "high");

    const matched = DomainUtils.checkReplyToMismatch("contact@company.com", "reply@company.com");
    assert.strictEqual(mismatch.hasMismatch, true); // same root is checked:
    const matchedRoot = DomainUtils.checkReplyToMismatch("support@mail.company.com", "billing@company.com");
    assert.strictEqual(matchedRoot.hasMismatch, false);
});

// -------------------------------------------------------------
// 3. URL ANALYZER TESTS
// -------------------------------------------------------------
console.log("\nTesting url-analyzer module:");

runTest("UrlAnalyzer detects IP address URLs", () => {
    const res = UrlAnalyzer.analyzeLink("http://192.168.1.1/login");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "IP_ADDRESS_URL"));
});

runTest("UrlAnalyzer detects dangerous URL schemes", () => {
    const res = UrlAnalyzer.analyzeLink("javascript:alert(1)");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "DANGEROUS_SCHEME"));
});

runTest("UrlAnalyzer detects URL shorteners", () => {
    const res = UrlAnalyzer.analyzeLink("https://bit.ly/secure-account");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "URL_SHORTENER"));
});

runTest("UrlAnalyzer detects displayed text vs destination mismatch", () => {
    const res = UrlAnalyzer.analyzeLink("https://evil-phishing.com/page", "https://paypal.com/verify");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "TEXT_MISMATCH"));
});

runTest("UrlAnalyzer detects redirect parameter safely", () => {
    const res = UrlAnalyzer.analyzeLink("https://legit-site.com/redirect?dest=https://evil.com");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "REDIRECT_PARAMETER"));
});

// -------------------------------------------------------------
// 4. ATTACHMENT ANALYZER TESTS
// -------------------------------------------------------------
console.log("\nTesting attachment-analyzer module:");

runTest("AttachmentAnalyzer detects direct executables", () => {
    const res = AttachmentAnalyzer.inspectAttachment("malware.exe");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "EXECUTABLE_FILE"));
});

runTest("AttachmentAnalyzer detects misleading double extensions", () => {
    const res = AttachmentAnalyzer.inspectAttachment("invoice.pdf.exe");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "DOUBLE_EXTENSION"));
});

runTest("AttachmentAnalyzer detects macro-enabled Office files", () => {
    const res = AttachmentAnalyzer.inspectAttachment("payroll.xlsm");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "MACRO_DOCUMENT"));
});

runTest("AttachmentAnalyzer detects HTML login imitators", () => {
    const res = AttachmentAnalyzer.inspectAttachment("account_verification.html");
    assert.strictEqual(res.hasRisk, true);
    assert.ok(res.issues.some(i => i.type === "HTML_ATTACHMENT"));
});

runTest("AttachmentAnalyzer treats regular PDF as harmless", () => {
    const res = AttachmentAnalyzer.inspectAttachment("annual_report.pdf");
    assert.strictEqual(res.hasRisk, false);
});

// -------------------------------------------------------------
// 5. PHISHING DETECTOR TESTS
// -------------------------------------------------------------
console.log("\nTesting phishing-detector module:");

runTest("PhishingDetector identifies urgent payment demand in English", () => {
    const text = "Please send wire transfer immediately to our account within 24 hours.";
    const matches = PhishingDetector.detectPhishingPatterns(text);
    assert.ok(matches.length > 0);
    assert.strictEqual(matches[0].id, "URGENT_PAYMENT");
});

runTest("PhishingDetector identifies urgent payment demand in Bangla", () => {
    const text = "জরুরি টাকা পাঠান এই নাম্বারে বিকাশ করুন এখনই।";
    const matches = PhishingDetector.detectPhishingPatterns(text);
    assert.ok(matches.length > 0);
    assert.strictEqual(matches[0].id, "URGENT_PAYMENT");
});

runTest("PhishingDetector identifies credential harvesting in English and Bangla", () => {
    const en = "Verify your account and reset your password immediately to avoid disruption.";
    const enMatches = PhishingDetector.detectPhishingPatterns(en);
    assert.ok(enMatches.some(m => m.id === "CREDENTIAL_HARVESTING"));

    const bn = "আপনার একাউন্ট যাচাই করতে এখানে লগইন করুন এবং পাসওয়ার্ড পরিবর্তন করুন।";
    const bnMatches = PhishingDetector.detectPhishingPatterns(bn);
    assert.ok(bnMatches.some(m => m.id === "CREDENTIAL_HARVESTING"));
});

runTest("PhishingDetector ignores benign conversations", () => {
    const text = "Hi Alex, please find the meeting notes attached for our weekly project sync. Thanks!";
    const matches = PhishingDetector.detectPhishingPatterns(text);
    assert.strictEqual(matches.length, 0);
});

// -------------------------------------------------------------
// 6. ACADEMIC PROTECTION TESTS
// -------------------------------------------------------------
console.log("\nTesting academic-protection module:");

runTest("isAcademicDomain recognizes valid academic TLDs", () => {
    assert.strictEqual(AcademicProtection.isAcademicDomain("harvard.edu"), true);
    assert.strictEqual(AcademicProtection.isAcademicDomain("ox.ac.uk"), true);
    assert.strictEqual(AcademicProtection.isAcademicDomain("buet.ac.bd"), true);
    assert.strictEqual(AcademicProtection.isAcademicDomain("randomcompany.com"), false);
});

runTest("analyzeAcademicContext flags professor impersonation from free email", () => {
    const res = AcademicProtection.analyzeAcademicContext({
        senderName: "Prof. Alan Turing - Head of Department",
        senderEmail: "alan.turing.cambridge@gmail.com",
        bodyText: "Please find the research proposal."
    });
    assert.strictEqual(res.hasIssues, true);
    assert.ok(res.issues.some(i => i.type === "ACADEMIC_IMPERSONATION"));
});

runTest("analyzeAcademicContext detects predatory publishing invitations", () => {
    const res = AcademicProtection.analyzeAcademicContext({
        senderName: "Journal Editor",
        senderEmail: "editor@research-international.org",
        bodyText: "Call for papers! Submit your manuscript within 24 hours with guaranteed fast peer review."
    });
    assert.strictEqual(res.hasIssues, true);
    assert.ok(res.issues.some(i => i.type === "PREDATORY_PUBLISHING"));
});

runTest("analyzeAcademicContext detects academic fee scam", () => {
    const res = AcademicProtection.analyzeAcademicContext({
        senderName: "Admissions Team",
        senderEmail: "admissions@gmail.com",
        bodyText: "Congratulations! Wire the application fee and tuition deposit to secure your PhD scholarship."
    });
    assert.strictEqual(res.hasIssues, true);
    assert.ok(res.issues.some(i => i.type === "ACADEMIC_FEE_SCAM"));
});

// -------------------------------------------------------------
// 7. SENDER HISTORY TESTS
// -------------------------------------------------------------
console.log("\nTesting sender-history module:");

runTest("migrateStorageData migrates legacy safeSenders string array cleanly", () => {
    const raw = {
        safeSenders: ["google.com", "admin@trusted.org"]
    };
    const migrated = SenderHistory.migrateStorageData(raw);
    assert.strictEqual(migrated.safeSenders.length, 2);
    assert.strictEqual(migrated.trustedRecords.length, 2);
    assert.strictEqual(migrated.trustedRecords[0].type, "domain");
    assert.strictEqual(migrated.trustedRecords[1].type, "email");
});

runTest("recordSenderObservation and detectSenderDrift detect unexpected Reply-To change", () => {
    let history = {};
    history = SenderHistory.recordSenderObservation(history, "colleague@company.com", "Colleague", "colleague@company.com");
    history = SenderHistory.recordSenderObservation(history, "colleague@company.com", "Colleague", "colleague@company.com");

    // Unexpected new Reply-To from familiar contact
    const drift = SenderHistory.detectSenderDrift(history, "colleague@company.com", "Colleague", "suspicious-relay@scam.net");
    assert.strictEqual(drift.hasDrift, true);
    assert.strictEqual(drift.warnings[0].type, "UNEXPECTED_REPLYTO_CHANGE");
});

runTest("validateImportData validates correct payload and rejects malformed data", () => {
    const validPayload = {
        trustedRecords: [
            { value: "harvard.edu", type: "domain", note: "My University" },
            { value: "advisor@harvard.edu", type: "email", note: "PhD Advisor" }
        ],
        trustedInstitutions: [
            { domain: "harvard.edu", name: "Harvard University" }
        ]
    };
    const res = SenderHistory.validateImportData(validPayload);
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.trustedRecords.length, 2);
    assert.strictEqual(res.safeSenders.length, 2);

    const invalid = SenderHistory.validateImportData("malformed-not-json{");
    assert.strictEqual(invalid.valid, false);
});

// -------------------------------------------------------------
// 8. RISK ENGINE TESTS
// -------------------------------------------------------------
console.log("\nTesting risk-engine module:");

runTest("RiskEngine calculates HIGH RISK when critical indicators are present", () => {
    const assessment = RiskEngine.evaluateRisk({
        senderName: "PayPal Security",
        senderEmail: "support@paypa1.com",
        domainAnalysis: {
            domain: "paypa1.com",
            typosquatting: { isTypo: true, reason: "Typo of paypal.com" }
        },
        attachmentFindings: [
            { issues: [{ type: "EXECUTABLE_FILE", severity: "high", message: "Malware attached." }] }
        ]
    });

    assert.strictEqual(assessment.category, "HIGH_RISK");
    assert.strictEqual(assessment.categoryLabel, "HIGH RISK");
    assert.ok(assessment.highCount >= 2);
});

runTest("RiskEngine does NOT classify trusted sender as HIGH RISK", () => {
    const assessment = RiskEngine.evaluateRisk({
        senderName: "Google Support",
        senderEmail: "support@google.com",
        isSafe: true,
        safeMatch: "google.com",
        domainAnalysis: { domain: "google.com" },
        attachmentFindings: [
            { issues: [{ type: "EXECUTABLE_FILE", severity: "high", message: "Attachment test." }] }
        ]
    });

    assert.strictEqual(assessment.category, "TRUSTED");
    assert.strictEqual(assessment.categoryLabel, "TRUSTED SENDER");
});

runTest("RiskEngine calculates CAUTION when only medium warnings are present", () => {
    const assessment = RiskEngine.evaluateRisk({
        senderName: "Newsletter",
        senderEmail: "news@dailyupdate.com",
        domainAnalysis: {
            domain: "dailyupdate.com"
        },
        linkFindings: [
            { issues: [{ type: "URL_SHORTENER", severity: "medium", message: "Shortener used." }] }
        ]
    });

    assert.strictEqual(assessment.category, "CAUTION");
    assert.strictEqual(assessment.categoryLabel, "CAUTION");
});

runTest("RiskEngine calculates NO MAJOR INDICATORS DETECTED when clean", () => {
    const assessment = RiskEngine.evaluateRisk({
        senderName: "Jane Doe",
        senderEmail: "jane.doe@standard-domain.com",
        domainAnalysis: {
            domain: "standard-domain.com"
        }
    });

    assert.strictEqual(assessment.category, "SAFE");
    assert.strictEqual(assessment.categoryLabel, "NO MAJOR INDICATORS DETECTED");
});

runTest("RiskEngine generates privacy-preserving text and JSON reports without sensitive bodies", () => {
    const assessment = RiskEngine.evaluateRisk({
        senderName: "Test Sender",
        senderEmail: "test@example.com",
        domainAnalysis: { domain: "example.com" }
    });

    const textReport = RiskEngine.generateReport(assessment, { senderEmail: "test@example.com", senderName: "Test" }, "text");
    assert.ok(textReport.includes("EMAIL SECURITY ASSESSMENT REPORT"));
    assert.ok(textReport.includes("PRIVACY DISCLAIMER"));

    const jsonReport = RiskEngine.generateReport(assessment, { senderEmail: "test@example.com", senderName: "Test" }, "json");
    const parsed = JSON.parse(jsonReport);
    assert.strictEqual(parsed.reportTitle, "Email Security Assessment Report");
    assert.strictEqual(parsed.sender.email, "test@example.com");
});

// -------------------------------------------------------------
// SUMMARY
// -------------------------------------------------------------
console.log(`\nTest Run Completed: ${testsPassed} passed, ${testsFailed} failed.`);
if (testsFailed > 0) {
    process.exit(1);
} else {
    console.log("All unit tests passed successfully!\n");
}
