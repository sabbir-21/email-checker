// ============================================================
//              EMAIL VERIFIER - I18N MODULE
// ============================================================

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.EmailVerifierI18n = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    let currentLang = "en";

    const translations = {
        en: {
            // General & Header
            extName: "Email Verifier",
            tagIncoming: "📩 Incoming Sender",
            tagReply: "💬 External Sender (Reply Thread)",
            tagOutgoing: "📤 Outgoing Email (Recipient Check)",
            tagSelf: "👤 Sent by you (Internal Email)",

            // Risk Categories
            riskHigh: "HIGH RISK",
            riskCaution: "CAUTION",
            riskSafe: "NO MAJOR INDICATORS DETECTED",
            riskUnknown: "UNKNOWN / NOT CHECKED",

            // Badges
            badgeInternalTitle: "Internal / Self-Sent Message",
            badgeInternalSub: "This email was sent by your own logged-in account.",
            badgeTrustedTitle: "Trusted / Safe Sender",
            badgeTrustedSub: "Matched in Safe Senders Database",
            badgeAcademicVerifiedTitle: "Verified Academic Institution",
            badgeAcademicVerifiedSub: "Sender domain belongs to a verified institutional record.",

            // Warnings - Domain & Identity
            warnTypoDomain: "Possible typo-squatting or lookalike domain.",
            warnHomoglyphDomain: "Unicode confusable / homoglyph characters detected in domain name.",
            warnPunycodeDomain: "Internationalized domain name (Punycode) detected.",
            warnDeceptiveSubdomain: "Deceptive subdomain: trusted brand appears inside an unrelated domain.",
            warnFreeEmailImpersonation: "Free public email address used while claiming an official or corporate identity.",
            warnReplyToMismatch: "Reply-To address differs significantly from the sender domain.",
            warnSenderHistoryDrift: "Known contact is using an unfamiliar domain or Reply-To address.",

            // Warnings - Authentication
            authSpfPass: "SPF: Validated by mail provider (mailed-by domain matches).",
            authSpfFail: "SPF: Alignment failure or unverified envelope domain.",
            authDkimPass: "DKIM: Digitally signed by sender domain (signed-by matches).",
            authDkimFail: "DKIM: Signature domain does not align with sender domain.",
            authDmarcPass: "DMARC: Authentication policy satisfied.",
            authDmarcFails: "DMARC: Alignment issue detected.",
            authNotAvailable: "Raw RFC headers not directly available in standard Gmail reading pane.",
            authNote: "Reported by mail infrastructure; not independently cryptographically computed.",

            // Warnings - Links
            warnLinkTextMismatch: "Deceptive link: displayed text shows a different domain than actual destination.",
            warnLinkIpAddress: "Link points directly to an IP address instead of a domain name.",
            warnLinkShortener: "Link uses a URL shortener service which hides the true destination.",
            warnLinkDangerousScheme: "Unusual or dangerous link protocol detected.",
            warnLinkSuspiciousPath: "Link targets a sensitive authentication or credential-related path.",
            warnLinkRedirect: "Link contains a redirect parameter; final destination is unverified.",

            // Warnings - Attachments
            warnAttachExecutable: "High-risk executable or script attachment detected.",
            warnAttachDoubleExt: "Misleading double file extension detected (e.g. filename.pdf.exe).",
            warnAttachMacro: "Macro-enabled Office document detected; can execute embedded code.",
            warnAttachArchive: "Compressed archive attachment detected; may contain hidden executables.",
            warnAttachHtml: "HTML attachment detected; may imitate a login or credential portal.",

            // Warnings - Phishing & Social Engineering
            warnUrgentPayment: "Urgent payment, wire transfer, or cryptocurrency request detected.",
            warnCredentialTheft: "Urgent credential, password reset, or account verification demand.",
            warnAccountSuspension: "Threat of account suspension or urgent legal/security action.",
            warnDocumentRequest: "Request to submit sensitive identity documents (passport, ID, SSN).",
            warnSecrecyDemand: "Suspicious secrecy or request to bypass normal organizational procedures.",
            warnPrizeLottery: "Unexpected prize, lottery award, or grant notification.",
            warnSuspiciousJob: "Unsolicited work-from-home job offer with unrealistic guarantees.",

            // Warnings - Academic Protection
            warnAcademicImpersonation: "Academic impersonation: claimed faculty/university title sent from a non-institutional address.",
            warnPredatoryPublishing: "Predatory journal or conference solicitation detected.",
            warnAcademicFeeScam: "Suspicious application, publication, or processing fee request in academic context.",
            warnAcademicUnverifiedDomain: "Sender claims university affiliation but does not use the official institutional domain.",

            // DNS & Infrastructure
            dnsMxFound: "MX records verified: domain can receive emails.",
            dnsMxMissing: "No MX records found: domain cannot receive emails.",
            dnsQueryFailed: "DNS query could not be completed (network error or offline).",
            dnsSpfRecordFound: "Published SPF policy found in DNS.",
            dnsDmarcRecordFound: "Published DMARC policy found in DNS.",

            // UI Actions & Buttons
            btnTrustSender: "Trust Sender",
            btnRemoveTrust: "Remove from Safe List",
            btnFindMismatch: "Find Mismatch",
            btnCheckMismatch: "Check",
            btnCopyReport: "Copy Security Report",
            btnCopied: "Copied to Clipboard!",
            btnShowDetails: "Show Technical Evidence",
            btnHideDetails: "Hide Technical Evidence",
            btnOptions: "Safe Senders & Settings",
            placeholderMismatch: "Enter sender's original email",

            // Recommendations
            recVerifyIndependently: "Do not click links or open attachments. Verify this request using official published contact details.",
            recCautionLinks: "Inspect links carefully. Navigate to the official website manually rather than clicking email links.",
            recSafeProceed: "No active threat indicators detected. Continue applying standard vigilance."
        },
        bn: {
            // General & Header
            extName: "ইমেইল ভেরিফায়ার",
            tagIncoming: "📩 আগত ইমেইল প্রেরক",
            tagReply: "💬 রিপ্লাই থ্রেড প্রেরক",
            tagOutgoing: "📤 বহির্গামী ইমেইল (প্রাপক যাচাই)",
            tagSelf: "👤 আপনার নিজের একাউন্ট (অভ্যন্তরীণ ইমেইল)",

            // Risk Categories
            riskHigh: "উচ্চ ঝুঁকি (HIGH RISK)",
            riskCaution: "সতর্কতা (CAUTION)",
            riskSafe: "কোনো বড় ঝুঁকি পাওয়া যায়নি",
            riskUnknown: "অজানা / যাচাই করা হয়নি",

            // Badges
            badgeInternalTitle: "অভ্যন্তরীণ / নিজের পাঠানো বার্তা",
            badgeInternalSub: "এই ইমেইলটি আপনার নিজের লগইন করা একাউন্ট থেকে পাঠানো হয়েছে।",
            badgeTrustedTitle: "বিশ্বস্ত / নিরাপদ প্রেরক",
            badgeTrustedSub: "নিরাপদ প্রেরকের তালিকায় অন্তর্ভুক্ত রয়েছে",
            badgeAcademicVerifiedTitle: "যাচাইকৃত শিক্ষা প্রতিষ্ঠান",
            badgeAcademicVerifiedSub: "প্রেরকের ডোমেইনটি অফিসিয়াল শিক্ষা প্রতিষ্ঠানের রেকর্ডের সাথে মিলেছে।",

            // Warnings - Domain & Identity
            warnTypoDomain: "টাইপো-স্কোয়াটিং বা দেখতে একই রকম নকল ডোমেইন হতে পারে।",
            warnHomoglyphDomain: "ডোমেইনে বিভ্রান্তিকর ইউনিকোড বা হোমোগ্লিফ অক্ষর সনাক্ত হয়েছে।",
            warnPunycodeDomain: "ইন্টারন্যাশনালাইজড ডোমেইন নেম (Punycode) সনাক্ত হয়েছে।",
            warnDeceptiveSubdomain: "প্রতারণামূলক সাব-ডোমেইন: বিশ্বস্ত ব্র্যান্ড নাম অন্য ডোমেইনের মাঝে ব্যবহার করা হয়েছে।",
            warnFreeEmailImpersonation: "অফিসিয়াল বা প্রাতিষ্ঠানিক পরিচয় দিয়ে ফ্রি পাবলিক ইমেইল ব্যবহার করা হয়েছে।",
            warnReplyToMismatch: "রিপ্লাই-টু (Reply-To) ঠিকানা মূল প্রেরকের ডোমেইনের চেয়ে সম্পূর্ণ ভিন্ন।",
            warnSenderHistoryDrift: "পূর্বের পরিচিত প্রেরক এবার অচেনা ডোমেইন বা রিপ্লাই-টু ঠিকানা ব্যবহার করছে।",

            // Warnings - Authentication
            authSpfPass: "SPF: জিমেইল অবকাঠামো দ্বারা যাচাইকৃত (mailed-by মিলেছে)।",
            authSpfFail: "SPF: ডোমেইন অ্যালাইনমেন্ট ব্যর্থ অথবা যাচাই করা যায়নি।",
            authDkimPass: "DKIM: প্রেরক ডোমেইন দ্বারা ডিজিটালি সাইন করা (signed-by মিলেছে)।",
            authDkimFail: "DKIM: সাইন ডোমেইন প্রেরক ডোমেইনের সাথে মিলছে না।",
            authDmarcPass: "DMARC: ডোমেইন অথেনটিকেশন নীতি সন্তোষজনক।",
            authDmarcFails: "DMARC: অ্যালাইনমেন্ট সংক্রান্ত সমস্যা সনাক্ত হয়েছে।",
            authNotAvailable: "জিমেইলের সাধারণ রিডিং ভিউতে সম্পূর্ণ র RFC হেডার উপস্থিত নেই।",
            authNote: "এটি মেইল অবকাঠামো কর্তৃক প্রদর্শিত; এক্সটেনশন স্বাধীন ক্রিপ্টোগ্রাফিক যাচাই করেনি।",

            // Warnings - Links
            warnLinkTextMismatch: "প্রতারণামূলক লিংক: লেখার টেক্সট এবং আসল লিংকের ঠিকানা ভিন্ন।",
            warnLinkIpAddress: "লিংকটি ডোমেইনের বদলে সরাসরি আইপি (IP) অ্যাড্রেস নির্দেশ করছে।",
            warnLinkShortener: "লিংক শর্টেনার ব্যবহার করা হয়েছে, যা আসল গন্তব্য লুকিয়ে রাখে।",
            warnLinkDangerousScheme: "অস্বাভাবিক বা বিপজ্জনক লিংক প্রটোকল সনাক্ত হয়েছে।",
            warnLinkSuspiciousPath: "লিংকটি পাসওয়ার্ড বা লগইন পাতার মতো সংবেদনশীল পেজ নির্দেশ করছে।",
            warnLinkRedirect: "লিংকে রিডাইরেক্ট প্যারামিটার রয়েছে; চূড়ান্ত গন্তব্য নিশ্চিত নয়।",

            // Warnings - Attachments
            warnAttachExecutable: "বিপজ্জনক এক্সিকিউটেবল বা স্ক্রিপ্ট ফাইল সনাক্ত হয়েছে।",
            warnAttachDoubleExt: "বিভ্রান্তিকর ডাবল ফাইল এক্সটেনশন সনাক্ত হয়েছে (যেমন filename.pdf.exe)।",
            warnAttachMacro: "ম্যাক্রো-যুক্ত অফিস ফাইল সনাক্ত হয়েছে; এটি স্বয়ংক্রিয় কোড চালাতে পারে।",
            warnAttachArchive: "সংকুচিত আর্কাইভ ফাইল সনাক্ত হয়েছে; ভেতরে ক্ষতিকারক ফাইল থাকতে পারে।",
            warnAttachHtml: "এইচটিএমএল (HTML) অ্যাটাচমেন্ট সনাক্ত হয়েছে; এটি ভুয়া লগইন পেজ হতে পারে।",

            // Warnings - Phishing & Social Engineering
            warnUrgentPayment: "জরুরি টাকা পাঠানো, ব্যাংক ট্রান্সফার বা ক্রিপ্টোকারেন্সির দাবি সনাক্ত হয়েছে।",
            warnCredentialTheft: "জরুরি পাসওয়ার্ড রিসেট বা একাউন্ট ভেরিফিকেশনের দাবি সনাক্ত হয়েছে।",
            warnAccountSuspension: "একাউন্ট বন্ধ বা আইনি পদক্ষেপ নেওয়ার হুমকি সনাক্ত হয়েছে।",
            warnDocumentRequest: "সংবেদনশীল জাতীয় পরিচয়পত্র, পাসপোর্ট বা ব্যাংক বিবরণ জমা দেওয়ার অনুরোধ।",
            warnSecrecyDemand: "অস্বাভাবিক গোপনীয়তার অনুরোধ বা স্বাভাবিক নিয়ম উপেক্ষা করার চাপ।",
            warnPrizeLottery: "অপ্রত্যাশিত লটারি, আর্থিক অনুদান বা পুরস্কারের লোভ দেখানো হয়েছে।",
            warnSuspiciousJob: "বাস্তবতাবিবর্জিত ঘরে বসে আয়ের লোভনীয় চাকরির প্রস্তাব।",

            // Warnings - Academic Protection
            warnAcademicImpersonation: "শিক্ষা সংক্রান্ত প্রতারণা: শিক্ষক বা বিশ্ববিদ্যালয়ের নাম দিয়ে ব্যক্তিগত ফ্রি ইমেইল থেকে পাঠানো হয়েছে।",
            warnPredatoryPublishing: "শিকারি (Predatory) জার্নাল বা ভুয়া কনফারেন্সের আমন্ত্রণ সনাক্ত হয়েছে।",
            warnAcademicFeeScam: "ভর্তি, প্রকাশনা বা প্রসেসিং ফি বাবদ অনাকাঙ্ক্ষিত অর্থ চাওয়ার লক্ষণ।",
            warnAcademicUnverifiedDomain: "বিশ্ববিদ্যালয়ের প্রতিনিধি দাবি করলেও প্রাতিষ্ঠানিক ডোমেইন ব্যবহার করা হয়নি।",

            // DNS & Infrastructure
            dnsMxFound: "MX রেকর্ড যাচাইকৃত: ডোমেইনটি ইমেইল গ্রহণ করতে সক্ষম।",
            dnsMxMissing: "কোনো MX রেকর্ড পাওয়া যায়নি: ডোমেইনটি ইমেইল গ্রহণ করতে সক্ষম নয়।",
            dnsQueryFailed: "ডিএনএস কোয়েরি সম্পন্ন করা যায়নি (নেটওয়ার্ক সমস্যা বা অফলাইন)।",
            dnsSpfRecordFound: "ডিএনএসে প্রকাশিত SPF নীতিমালা পাওয়া গেছে।",
            dnsDmarcRecordFound: "ডিএনএসে প্রকাশিত DMARC নীতিমালা পাওয়া গেছে।",

            // UI Actions & Buttons
            btnTrustSender: "প্রেরককে বিশ্বাস করুন",
            btnRemoveTrust: "নিরাপদ তালিকা থেকে মুছুন",
            btnFindMismatch: "অমিল পরীক্ষা করুন",
            btnCheckMismatch: "যাচাই করুন",
            btnCopyReport: "নিরাপত্তা রিপোর্ট কপি করুন",
            btnCopied: "ক্লিপবোর্ডে কপি হয়েছে!",
            btnShowDetails: "প্রযুক্তিগত প্রমাণাদি দেখুন",
            btnHideDetails: "প্রমাণাদি লুকিয়ে রাখুন",
            btnOptions: "সেটিংস ও নিরাপদ তালিকা",
            placeholderMismatch: "প্রেরকের সঠিক ইমেইল লিখুন",

            // Recommendations
            recVerifyIndependently: "লিংকে ক্লিক করবেন না এবং ফাইল খুলবেন না। অফিসিয়াল সূত্র থেকে তথ্য যাচাই করুন।",
            recCautionLinks: "লিংক সতর্কতার সাথে পরীক্ষা করুন। ব্রাউজারে নিজে টাইপ করে অফিসিয়াল সাইটে প্রবেশ করুন।",
            recSafeProceed: "কোনো পরিচিত ঝুঁকি পাওয়া যায়নি। তবুও স্বাভাবিক সতর্কতা বজায় রাখুন।"
        }
    };

    function getLang() {
        return currentLang;
    }

    function setLang(lang) {
        if (lang === "bn" || lang === "en") {
            currentLang = lang;
        }
    }

    function t(key, params = {}) {
        const langDict = translations[currentLang] || translations.en;
        let str = langDict[key] || translations.en[key] || key;

        if (params && typeof params === "object") {
            for (const [k, v] of Object.entries(params)) {
                str = str.replace(new RegExp(`\\{${k}\\}`, "g"), v);
            }
        }
        return str;
    }

    return {
        getLang,
        setLang,
        t,
        translations
    };
});
