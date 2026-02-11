# 🔧 Remaining Professional Styling Tasks - Code Reference

**Quick Action Plan for Completing All 9 Pages**

---

## Summary of Remaining Work

| Page | Status | Action | Time |
|------|--------|--------|------|
| Terms & Conditions | ✅ DONE | None needed | — |
| Privacy Policy | 🟡 50% | Add icons to content sections | 10 min |
| Refund Policy | 🟡 40% | Apply red theme styling | 15 min |
| Payment Terms | 🟡 0% | Copy from template | 3 min |
| Contact & Support | 🟡 0% | Copy from template | 3 min |
| Disclaimer | 🟡 0% | Apply red theme + icons | 15 min |
| Acceptable Use | 🟡 0% | Apply orange theme + icons | 15 min |
| IP Policy | 🟡 0% | Apply blue theme + icons | 15 min |
| Return/Cancel | 🟡 0% | Apply purple theme + icons | 15 min |

**Total Time to Complete: 91 minutes (if done sequentially)**

---

## Task 1: Privacy Policy - Add Content Icons ⏳

**File:** `views/privacy-policy.ejs`

**What to do:** Add Font Awesome icons to h2 section headers

**Current state:**
```html
<!-- Looking for section headers that look like: -->
<h2>Introduction</h2>
<h2>Information We Collect</h2>
<!-- etc -->
```

**Change to:**
```html
<h2><i class="fas fa-info-circle"></i> Introduction</h2>
<h2><i class="fas fa-database"></i> Information We Collect</h2>
<h2><i class="fas fa-lock"></i> Security Measures</h2>
<h2><i class="fas fa-users"></i> Your Rights</h2>
<h2><i class="fas fa-exchange-alt"></i> Data Sharing</h2>
<h2><i class="fas fa-chart-line"></i> Cookie & Tracking</h2>
<h2><i class="fas fa-globe"></i> International Data</h2>
<h2><i class="fas fa-phone"></i> Contact Us</h2>
<h2><i class="fas fa-gavel"></i> Legal Basis</h2>
<!-- etc - add appropriate icon to each section -->
```

**Icon suggestions by section:**
- Introduction: `fas fa-info-circle`
- Collect: `fas fa-database` or `fas fa-download`
- Use: `fas fa-cogs`
- Share: `fas fa-users`
- Store: `fas fa-archive`
- Retention: `fas fa-calendar`
- Security: `fas fa-shield-alt` or `fas fa-lock`
- Rights: `fas fa-user-shield`
- Tracking: `fas fa-map-marker`
- Contact: `fas fa-envelope`

---

## Task 2: Refund Policy - Apply Styling ⏳

**File:** `views/refundpolicy.ejs`

**What to do:** Replace the entire file with professional styling

**Template structure:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Understand Vidyari's flexible refund policy and how we protect users.">
  <title>Refund Policy - Vidyari</title>
  <link rel="icon" type="image/png" href="./images/logo.svg">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/legal-pages.css">
  <style>
    header {
      border-left-color: #d9534f;
    }
    .notice-box {
      border-left-color: #d9534f;
      background-color: rgba(217, 83, 79, 0.05);
    }
    .section h2 i {
      color: #d9534f;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <a href="/"><i class="fas fa-arrow-left"></i> Back to Home</a>
      <h1>Refund Policy</h1>
      <div class="meta-info">
        <div class="meta-item">
          <i class="fas fa-calendar-alt"></i>
          <span>Updated: February 2026</span>
        </div>
        <div class="meta-item">
          <i class="fas fa-file-alt"></i>
          <span>Legal Document</span>
        </div>
      </div>
    </header>

    <div class="main-content">
      <div class="notice-box">
        <div class="notice-icon">
          <i class="fas fa-undo"></i>
        </div>
        <div class="notice-content">
          <strong>7-Day Refund Guarantee:</strong> We want you to be satisfied. If you're not happy with your purchase, we offer a full refund within 7 days.
        </div>
      </div>

      <!-- Then add all existing sections with h2 icons -->
      <div class="section">
        <h2><i class="fas fa-check-circle"></i> Eligibility Criteria</h2>
        <!-- existing content -->
      </div>
      
      <div class="section">
        <h2><i class="fas fa-clock"></i> Refund Timeline</h2>
        <!-- existing content -->
      </div>

      <!-- More sections with icons:
        - fas fa-undo (refunds)
        - fas fa-exchange-alt (exchanges)
        - fas fa-credit-card (payment methods)
        - fas fa-question-circle (FAQs)
        - fas fa-envelope (contact)
      -->
    </div>

    <footer>
      <p>&copy; 2025-2026 Vidyari. All rights reserved.</p>
      <p style="margin-top: 10px; font-size: 12px;">Last updated: February 2026</p>
      <div class="footer-links">
        <a href="/terms&conditions">Terms & Conditions</a>
        <a href="/privacy-policy">Privacy Policy</a>
        <a href="/payment-terms">Payment Terms</a>
        <a href="/contact">Contact Us</a>
      </div>
    </footer>
  </div>
</body>
</html>
```

---

## Task 3: Payment Terms - Copy Template ⚡ EASIEST

**File:** `views/payment-terms.ejs`

**What to do:** Copy the professional version that already exists

**Command (or manually copy):**
```bash
# Windows PowerShell:
Copy-Item "views/payment-terms-pro.ejs" -Destination "views/payment-terms.ejs" -Force

# Or manually:
# 1. Open payment-terms-pro.ejs
# 2. Copy ALL content
# 3. Select ALL in payment-terms.ejs
# 4. Delete and paste
```

**Result:** Professional payment page with purple theme, payment method cards, security details ready

---

## Task 4: Contact & Support - Copy Template ⚡ EASIEST

**File:** `views/contact.ejs`

**What to do:** Copy the professional version that already exists

**Command (or manually copy):**
```bash
# Windows PowerShell:
Copy-Item "views/contact-pro.ejs" -Destination "views/contact.ejs" -Force

# Or manually:
# 1. Open contact-pro.ejs
# 2. Copy ALL content
# 3. Select ALL in contact.ejs
# 4. Delete and paste
```

**Result:** Professional contact page with green theme, 6-email grid, SLA table, FAQ ready

---

## Task 5: Disclaimer - Apply Red Theme ⏳

**File:** `views/disclaimer.ejs`

**Color theme:** Red (#d9534f)

**Header structure to use:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Important disclaimer about Vidyari's liability and legal protections.">
  <title>Disclaimer & Liability - Vidyari</title>
  <link rel="icon" type="image/png" href="./images/logo.svg">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/legal-pages.css">
  <style>
    header {
      border-left-color: #d9534f;
    }
    .notice-box {
      border-left-color: #d9534f;
      background-color: rgba(217, 83, 79, 0.05);
    }
    .section h2 i {
      color: #d9534f;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <a href="/"><i class="fas fa-arrow-left"></i> Back to Home</a>
      <h1>Disclaimer & Liability</h1>
      <div class="meta-info">
        <div class="meta-item">
          <i class="fas fa-calendar-alt"></i>
          <span>Updated: February 2026</span>
        </div>
        <div class="meta-item">
          <i class="fas fa-file-alt"></i>
          <span>Legal Document</span>
        </div>
      </div>
    </header>

    <div class="main-content">
      <div class="notice-box">
        <div class="notice-icon">
          <i class="fas fa-exclamation-circle"></i>
        </div>
        <div class="notice-content">
          <strong>Important Legal Notice:</strong> Please read this disclaimer carefully. It contains important information about limitations on our liability and your rights.
        </div>
      </div>

      <!-- Add existing content with h2 icons:
        - fas fa-exclamation-triangle (disclaimers)
        - fas fa-shield-alt (limitations)
        - fas fa-balance-scale (liability)
        - fas fa-gavel (legal)
      -->
    </div>
  </div>
</body>
</html>
```

---

## Task 6: Acceptable Use Policy - Apply Orange Theme ⏳

**File:** `views/acceptable-use.ejs`

**Color theme:** Orange (#f57c00)

**Header template:**
```html
<head>
  <!-- ... standard meta tags ... -->
  <title>Acceptable Use Policy - Vidyari</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/legal-pages.css">
  <style>
    header {
      border-left-color: #f57c00;
    }
    .notice-box {
      border-left-color: #f57c00;
      background-color: rgba(245, 124, 0, 0.05);
    }
    .section h2 i {
      color: #f57c00;
    }
  </style>
</head>

<div class="notice-box">
  <div class="notice-icon">
    <i class="fas fa-info-circle"></i>
  </div>
  <div class="notice-content">
    <strong>Community Standards:</strong> We're committed to maintaining a safe, respectful community. These guidelines help us achieve that.
  </div>
</div>
```

**Section icons to add:**
- `fas fa-shield-alt` - Conduct Standards
- `fas fa-ban` - Prohibited Activities
- `fas fa-warning` - Violation Consequences
- `fas fa-gavel` - Enforcement
- `fas fa-question-circle` - Help/Support

---

## Task 7: IP Policy - Apply Blue Theme ⏳

**File:** `views/intellectual-property.ejs`

**Color theme:** Blue (#1e88e5)

**Header template:**
```html
<head>
  <!-- ... standard meta tags ... -->
  <title>Intellectual Property Policy - Vidyari</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/legal-pages.css">
  <style>
    header {
      border-left-color: #1e88e5;
    }
    .notice-box {
      border-left-color: #1e88e5;
      background-color: rgba(30, 136, 229, 0.05);
    }
    .section h2 i {
      color: #1e88e5;
    }
  </style>
</head>

<div class="notice-box">
  <div class="notice-icon">
    <i class="fas fa-lock"></i>
  </div>
  <div class="notice-content">
    <strong>Creator Protection:</strong> We respect intellectual property. Both our IP and creator IP are fully protected.
  </div>
</div>
```

**Section icons to add:**
- `fas fa-copyright` - Copyright
- `fas fa-bookmark` - Creator Rights
- `fas fa-gavel` - DMCA
- `fas fa-shield-alt` - Protection

---

## Task 8: Return & Cancellation - Apply Purple Theme ⏳

**File:** `views/return-cancellation.ejs`

**Color theme:** Purple (#ab47bc)

**Header template:**
```html
<head>
  <!-- ... standard meta tags ... -->
  <title>Return & Cancellation Policy - Vidyari</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/legal-pages.css">
  <style>
    header {
      border-left-color: #ab47bc;
    }
    .notice-box {
      border-left-color: #ab47bc;
      background-color: rgba(171, 71, 188, 0.05);
    }
    .section h2 i {
      color: #ab47bc;
    }
  </style>
</head>

<div class="notice-box">
  <div class="notice-icon">
    <i class="fas fa-undo"></i>
  </div>
  <div class="notice-content">
    <strong>Flexible Returns:</strong> Change your mind? Cancel your order before download and get a full refund.
  </div>
</div>
```

**Section icons to add:**
- `fas fa-times-circle` - Pre-Download Cancellation
- `fas fa-calendar` - Timelines
- `fas fa-money-bill-wave` - Refund Processing
- `fas fa-download` - Post-Download

---

## Quick Copy-Paste Header Template

Use this for ANY page (just change the color code and icons):

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="[YOUR DESCRIPTION]">
  <title>[PAGE TITLE] - Vidyari</title>
  <link rel="icon" type="image/png" href="./images/logo.svg">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/legal-pages.css">
  <style>
    header {
      border-left-color: #[COLOR_CODE];
    }
    .notice-box {
      border-left-color: #[COLOR_CODE];
      background-color: rgba([R], [G], [B], 0.05);
    }
    .section h2 i {
      color: #[COLOR_CODE];
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <a href="/"><i class="fas fa-arrow-left"></i> Back to Home</a>
      <h1>[PAGE TITLE]</h1>
      <div class="meta-info">
        <div class="meta-item">
          <i class="fas fa-calendar-alt"></i>
          <span>Updated: February 2026</span>
        </div>
        <div class="meta-item">
          <i class="fas fa-file-alt"></i>
          <span>Legal Document</span>
        </div>
      </div>
    </header>

    <div class="main-content">
      <div class="notice-box">
        <div class="notice-icon">
          <i class="fas fa-[ICON]"></i>
        </div>
        <div class="notice-content">
          [YOUR NOTICE TEXT]
        </div>
      </div>

      <!-- Sections with h2 icons -->

    </div>

    <footer>
      <p>&copy; 2025-2026 Vidyari. All rights reserved.</p>
      <p style="margin-top: 10px; font-size: 12px;">Last updated: February 2026</p>
      <div class="footer-links">
        <a href="/terms&conditions">Terms & Conditions</a>
        <a href="/privacy-policy">Privacy Policy</a>
        <a href="/payment-terms">Payment Terms</a>
        <a href="/contact">Contact Us</a>
      </div>
    </footer>
  </div>
</body>
</html>
```

### Color Codes for Hex-to-RGB conversion:
- `#d9534f` (Red) = rgb(217, 83, 79)
- `#f57c00` (Orange) = rgb(245, 124, 0)
- `#1e88e5` (Blue) = rgb(30, 136, 229)
- `#ab47bc` (Purple) = rgb(171, 71, 188)
- `#10a37f` (Teal) = rgb(16, 163, 127)
- `#6c63ff` (Indigo) = rgb(108, 99, 255)

---

## All Section Icons Reference

### General Icons
| Icon | Code |
|------|------|
| Back button | `fas fa-arrow-left` |
| Calendar/Date | `fas fa-calendar-alt` |
| Document | `fas fa-file-alt` |
| Info | `fas fa-info-circle` |
| Warning | `fas fa-exclamation-triangle` |
| Alert | `fas fa-exclamation-circle` |

### Financial Icons
| Icon | Code |
|------|------|
| Credit Card | `fas fa-credit-card` |
| Money | `fas fa-money-bill-wave` |
| Exchange | `fas fa-exchange-alt` |
| Payment | `fas fa-wallet` |
| Refund/Return | `fas fa-undo` |

### Security Icons
| Icon | Code |
|------|------|
| Lock | `fas fa-lock` |
| Shield | `fas fa-shield-alt` |
| User Shield | `fas fa-user-shield` |

### User/Account Icons
| Icon | Code |
|------|------|
| User | `fas fa-user` |
| Users | `fas fa-users` |
| User Circle | `fas fa-user-circle` |

### Legal/Process Icons
| Icon | Code |
|------|------|
| Gavel | `fas fa-gavel` |
| Balance Scale | `fas fa-balance-scale` |
| Copyright | `fas fa-copyright` |
| Ban | `fas fa-ban` |

### Contact Icons
| Icon | Code |
|------|------|
| Envelope | `fas fa-envelope` |
| Phone | `fas fa-phone` |
| Headset | `fas fa-headset` |
| Comments | `fas fa-comments` |

### Data Icons
| Icon | Code |
|------|------|
| Database | `fas fa-database` |
| Chart | `fas fa-chart-line` |
| Archive | `fas fa-archive` |

### Time Icons
| Icon | Code |
|------|------|
| Clock | `fas fa-clock` |
| Calendar | `fas fa-calendar` |
| History | `fas fa-history` |

### Help Icons
| Icon | Code |
|------|------|
| Question Circle | `fas fa-question-circle` |
| Lightbulb | `fas fa-lightbulb` |
| Bookmark | `fas fa-bookmark` |

---

## Estimated Completion Timeline

**If working 1:1 with these instructions:**

- Task 1 (Privacy icons): 10 minutes  
- Task 2 (Refund styling): 15 minutes  
- Task 3 (Payment Terms copy): 3 minutes  
- Task 4 (Contact copy): 3 minutes  
- Task 5 (Disclaimer): 15 minutes  
- Task 6 (Acceptable Use): 15 minutes  
- Task 7 (IP Policy): 15 minutes  
- Task 8 (Return/Cancel): 15 minutes  
- **Testing all pages**: 10 minutes  

**Total: 101 minutes (~ 1.5 hours for all 9 pages professionally styled)**

---

**All the tools & references you need are in this document. Copy-paste the templates, add content sections with icons, and you're done!** 🚀

