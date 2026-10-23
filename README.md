# Email Verifier Chrome Extension

A Google Chrome Extension that checks sender authenticity, detects phishing patterns, analyzes attachment risks, and validates MX records directly within Gmail.

## Features

- **Automatic Verification & Clean Lifecycle**: Verifies senders when an email conversation is opened and automatically closes/removes the popup when returning to the inbox or folder list.
- **Smart Reply & Thread Sender Detection**: In reply threads and conversations, filters out your own email address to analyze the actual external sender.
- **Safe Senders Database**:
  - Persistent storage in Chrome (`chrome.storage.local`).
  - Preloaded with major trusted domains (e.g., `google.com`, `microsoft.com`, `apple.com`, `amazon.com`, `github.com`, etc.).
  - Quick 1-click **Add / Remove** safe sender directly from the Gmail popup.
  - Full management dashboard in the **Options** page to search, add, delete, or reset safe entries.
- **Security Checks**:
  - MX Record lookup via Google Public DNS.
  - Phishing pattern and typo-squatting detection.
  - High-risk attachment detection (`.exe`, `.scr`, `.js`, `.bat`, etc.).
  - Email mismatch finder.

## Author

Developed by **Sabbir Ahmed**  
- [GitHub](https://github.com/sabbir-21)
- [Facebook](https://www.facebook.com/sabbir299)
