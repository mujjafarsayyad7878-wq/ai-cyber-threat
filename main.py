import os
import re
import ipaddress
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

app = FastAPI(
    title="AI Cyber Threat & Phishing Detection Engine",
    description="Full-spectrum phishing and cyber threat analyzer using ML and URL heuristics",
    version="1.0.0"
)

# CORS Middleware configured for deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# ==============================================================================
# 1. DATASET & MACHINE LEARNING MODEL PIPELINE
# ==============================================================================

TRAINING_DATA = [
    # Phishing Samples (label = 1)
    ("URGENT: Your bank account has been suspended due to suspicious activity. Verify immediately: http://192.168.1.1/verify", 1),
    ("Dear customer, your PayPal security update is pending. Please log in to prevent permanent restriction: http://paypal-security-update.com/login", 1),
    ("Action Required: Unauthorized sign-in attempt detected on your Microsoft 365 account. Click here to confirm identity: http://msft-verify365.top", 1),
    ("Immediate attention needed! Your Netflix subscription is on hold due to payment failure. Update card details now to avoid cancellation: http://netflix-billing-renew.xyz", 1),
    ("Congratulations! You won the Walmart $1000 gift card lottery. Claim your reward immediately by submitting your SSN and shipping details: http://claim-giftcard-now.club", 1),
    ("IRS Tax Refund Notification: You are eligible for a $1,420.50 tax refund. Click here to claim your direct deposit now: http://irs-refund-portal-secure.info", 1),
    ("Security Alert: Your Apple ID has been locked for security reasons. Confirm your password and security questions to restore access.", 1),
    ("Your package delivery from DHL has failed. Re-schedule delivery and pay custom fee $1.99 now: http://dhl-express-redelivery.buzz", 1),
    ("HR Payroll Update: Please verify your direct deposit banking information before Friday to avoid delay in salary disbursement.", 1),
    ("Cryptocurrency Giveaway: Send 0.1 ETH to verify your wallet and receive 1.0 ETH back instantly from the Ethereum Foundation.", 1),
    ("Your DocuSign document 'Urgent Invoice #98421' is ready for signature. Review and enter your email credentials to access: http://docusign-view-doc.tk", 1),
    ("Bank of America Alert: Unusual login from Russia detected. If this was not you, lock your debit card immediately: http://bofa-fraud-lock.com", 1),
    ("Urgent: Your Amazon account has been suspended for violating terms. Click link to submit your government ID and credit card details.", 1),
    ("Final Notice: Your email mailbox quota has exceeded 99%. All incoming emails will be deleted within 24 hours unless you upgrade.", 1),
    ("CEO Request: I am in a conference meeting and need you to purchase 5 Apple Gift Cards ($100 each) for client gifts immediately.", 1),
    ("Chase Online Banking: A wire transfer of $2,450.00 is pending approval. Disavow transaction here: http://chase-wire-cancel.xyz/auth", 1),
    ("Wells Fargo: Account Alert - Security questions have been reset. If you did not make this change, click to secure your profile.", 1),
    ("Dropbox Security: Someone shared a confidential document with you. Log in with your email provider to view encrypted contents.", 1),
    ("Warning: Virus detected on your computer! Windows Defender has blocked Trojan:Win32. Call Microsoft tech support at +1-800-FAKE.", 1),
    ("Your Facebook account will be permanently deactivated within 24 hours due to copyright infringement. Submit appeal here: http://fb-appeal-case.top", 1),
    ("Verify your Instagram blue badge verification badge now. Enter your username and current password to qualify.", 1),
    ("Urgent notice from IT department: Mandatory system upgrade tonight. Verify your Active Directory credentials to retain email access.", 1),
    ("Binance Security Notification: Withdrawal request for 0.85 BTC initiated from unknown IP. Cancel withdrawal: http://binance-safety-check.icu", 1),
    ("Google Account Recovery: Unusual login attempt blocked. Verify your phone number and backup email immediately to secure account.", 1),
    ("Overdue Invoice Reminder: Please find attached past-due invoice #INV-49210. Download the zip archive and enable macros to view.", 1),
    ("Claim your Covid-19 Relief Grant $2,500 approved by Federal Government. Provide bank credentials for instant wire deposit.", 1),
    ("LinkedIn Notification: You appeared in 14 searches today! View who looked at your private profile: http://linkedin-search-peek.tk", 1),
    ("Coinbase Support: Two-Factor Authentication has been disabled on your account. Re-enable immediately to prevent unauthorized asset transfer.", 1),
    ("Notice of Subpoena: You are summoned to appear in federal court. Download your official legal documents here: http://court-summons-fed.xyz", 1),
    ("Attention: Your car warranty is about to expire! Extend full coverage for $29/mo today to avoid heavy out-of-pocket repair bills.", 1),
    ("Urgent Security Alert: We detected an unrecognized device accessing your Gmail. Click to confirm your identity or account will be locked.", 1),
    ("Your AT&T bill payment failed. Pay today to prevent service shutoff: http://att-online-billpay-portal.xyz", 1),
    ("Dear Customer, suspicious transaction of $849.00 at Apple Store. Press 1 or verify online to dispute: http://apple-dispute-alert.cam", 1),
    ("You have 1 new voicemail message (0:48s). Click here to play audio file and log in with your corporate credentials.", 1),
    ("Emergency: Family member is stranded at airport without funds. Please wire money via Western Union immediately to help.", 1),
    ("Meta Business Support: Your Facebook ad account has violated advertising standards. Enter business credentials to contest restriction.", 1),
    ("Your Twitter / X Premium subscription has expired. Re-enter payment information to maintain your verified badge.", 1),
    ("Exclusive Offer: Zero-risk automated cryptocurrency trading bot generated $12,400 this week! Register free account today.", 1),
    ("Security Notice: SSL certificate expired for your domain. Click to renew certificate before DNS suspension.", 1),
    ("Immediate action required: Suspicious wire transfer initiated from your checking account. Cancel transfer immediately: http://192.168.0.22/cancel", 1),

    # Legitimate Samples (label = 0)
    ("Hi team, please find attached the quarterly engineering sprint retrospective notes and agenda for tomorrow morning's standup.", 0),
    ("Your Amazon order #112-8492019-382910 has shipped and is estimated to arrive on Thursday. Track your package in your Amazon account.", 0),
    ("Weekly Engineering Newsletter: Exploring Python 3.12 performance improvements, asyncio patterns, and modern FastAPI architectures.", 0),
    ("Reminder: Project status review meeting is scheduled for Wednesday at 2:00 PM EST via Google Meet. See calendar invite for link.", 0),
    ("Hey Sarah, could you review my pull request on the user authentication branch when you get a chance? Thanks!", 0),
    ("Your GitHub security alert: Dependabot detected 1 moderate severity vulnerability in package lodash. Review the automated fix PR.", 0),
    ("Your monthly electricity bill from ConEdison is ready. Total amount due: $68.40 on October 25th. View details in your account portal.", 0),
    ("Hi Alex, here is the updated PDF design mockups for the landing page dashboard from our UX team brainstorming session.", 0),
    ("Thank you for your reservation at Bistro Bella. Your table for 2 is confirmed for Friday, October 20th at 7:30 PM.", 0),
    ("University Registrar: Fall semester grades have been finalized and are now viewable in the official student portal.", 0),
    ("Flight Confirmation: Your flight UA 412 from San Francisco (SFO) to New York (JFK) is confirmed for November 12th.", 0),
    ("Release Notes: Version 2.4.0 of our analytics library is now live with enhanced charting options and bug fixes.", 0),
    ("Hey team, don't forget to submit your timesheets by 5 PM today for bi-weekly payroll processing. Have a great weekend!", 0),
    ("Your subscription receipt from Spotify: Premium Individual ($10.99/mo). Thank you for being a subscriber since 2019.", 0),
    ("Customer support ticket #48192 has been resolved. Please take a 1-minute survey to let us know how we did.", 0),
    ("Notice: Scheduled building maintenance and elevator inspection this Saturday between 9:00 AM and 1:00 PM.", 0),
    ("Hi David, thanks for following up on the client proposal. I will make the requested edits and send the revised draft by 3 PM.", 0),
    ("Your library books 'Introduction to Machine Learning' and 'Designing Data-Intensive Applications' are due in 3 days.", 0),
    ("Invitation: Tech Talk on Kubernetes Cluster Architecture & Zero-Trust Networking this Thursday at 4 PM in the main auditorium.", 0),
    ("Your Uber trip receipt: $24.50 from 4th Street to Airport Terminal 2. Payment charged to card ending in 4109.", 0),
    ("Daily Digest: New articles in Cybersecurity, Python Development, and Cloud Computing curated for your reading list.", 0),
    ("Good morning everyone, the shared kitchen on floor 3 has been cleaned and restocked with fresh coffee beans and fruit.", 0),
    ("GitLab CI/CD Pipeline #9420 passed successfully for branch main on commit 8f9b1c2. Deploying to staging environment.", 0),
    ("Hi team, please remember to complete your annual workplace compliance training module before the end of next month.", 0),
    ("Slack Notification: You were mentioned by Marcus in #dev-ops: 'The database migration completed with zero downtime.'", 0),
    ("Your Google Cloud Platform billing report for last month is available. Total spend was within your budget alert threshold.", 0),
    ("Welcome to our community meetup! Check out our GitHub repository and join our Discord channel to connect with fellow builders.", 0),
    ("Doctor appointment confirmation: Your annual physical checkup is scheduled with Dr. Robinson for next Tuesday at 10:15 AM.", 0),
    ("Hi team, the quarterly all-hands meeting recording and slide presentation have been uploaded to our internal company drive.", 0),
    ("Your package was delivered to your front door at 2:14 PM. Signature was received by resident.", 0),
    ("Hey all, let's grab lunch at the food trucks outside building 4 around 12:30 PM if anyone wants to join.", 0),
    ("Thanks for attending our webinar on Microservices Security! You can view the full recording and code repository here.", 0),
    ("Your gym membership monthly renewal has processed successfully. See you at your next training session!", 0),
    ("Software update available: macOS Sonoma 14.2 includes important bug fixes and security improvements for all Mac users.", 0),
    ("Hi team, please find the minutes from today's architecture committee meeting summarized in the engineering wiki.", 0),
    ("Your annual credit report is available for your regular annual review at the official government website annualcreditreport.com.", 0),
    ("Hello! Here are the slides from the machine learning workshop on naive bayes and NLP text classification.", 0),
    ("Your coffee subscription has shipped! Fresh roasted whole beans are on their way to your door via standard ground delivery.", 0),
    ("Team reminder: Please ensure all test cases pass and coverage remains above 85% before requesting merge reviews.", 0),
    ("Hi team, the office will be closed next Monday in observance of the federal holiday. Have a restful long weekend!", 0),
]

class PhishingModelEngine:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=2000,
            sublinear_tf=True,
            stop_words="english"
        )
        self.model = MultinomialNB(alpha=0.1)
        self.metrics: Dict[str, Any] = {}
        self.top_features: Dict[str, List[Dict[str, Any]]] = {"phishing": [], "legitimate": []}
        self.train()

    def train(self):
        texts, labels = zip(*TRAINING_DATA)
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.25, random_state=42, stratify=labels
        )
        
        X_train_vec = self.vectorizer.fit_transform(X_train)
        self.model.fit(X_train_vec, y_train)
        
        X_test_vec = self.vectorizer.transform(X_test)
        y_pred = self.model.predict(X_test_vec)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        self.metrics = {
            "accuracy": round(float(acc) * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2),
            "confusion_matrix": cm, # [[TN, FP], [FN, TP]]
            "training_samples": len(texts),
            "vocabulary_size": len(self.vectorizer.vocabulary_)
        }
        
        # Extract top feature words for Phishing and Legitimate
        feature_names = np.array(self.vectorizer.get_feature_names_out())
        # MultinomialNB feature_log_prob_ has shape (2, n_features)
        # Class 0: Legitimate, Class 1: Phishing
        legit_log_prob = self.model.feature_log_prob_[0]
        phish_log_prob = self.model.feature_log_prob_[1]
        
        # Ratio of phishing vs legit probability
        phish_ratio = phish_log_prob - legit_log_prob
        top_phish_idx = np.argsort(phish_ratio)[-15:][::-1]
        top_legit_idx = np.argsort(phish_ratio)[:15]
        
        self.top_features["phishing"] = [
            {"word": feature_names[i], "weight": round(float(np.exp(phish_log_prob[i])) * 100, 3)}
            for i in top_phish_idx
        ]
        self.top_features["legitimate"] = [
            {"word": feature_names[i], "weight": round(float(np.exp(legit_log_prob[i])) * 100, 3)}
            for i in top_legit_idx
        ]

    def predict(self, text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            return {"probability": 0.0, "label": "Legitimate", "confidence": 0.0, "matched_tokens": []}
            
        vec = self.vectorizer.transform([text])
        proba = self.model.predict_proba(vec)[0]
        phish_prob = float(proba[1])
        
        # Find which model vocabulary terms appear in this text
        tokens = text.lower().split()
        matched_tokens = []
        for word in self.top_features["phishing"]:
            if word["word"] in text.lower():
                matched_tokens.append(word["word"])
                
        return {
            "probability": round(phish_prob * 100, 2),
            "label": "Phishing" if phish_prob >= 0.50 else "Legitimate",
            "confidence": round(max(proba) * 100, 2),
            "matched_tokens": matched_tokens[:8]
        }

ml_engine = PhishingModelEngine()

# ==============================================================================
# 2. URL ANALYSIS ENGINE (Urllib Parsing & Threat Heuristics)
# ==============================================================================

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work", 
    "cn", "icu", "cam", "monster", "fit", "surf", "click", "download", 
    "racing", "rest", "kim", "country", "stream", "bid", "men", "date"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", 
    "is.gd", "cutt.ly", "trib.al", "shorte.st", "rebrandly.com", "rb.gy", 
    "tiny.cc", "v.gd", "clck.ru", "bc.vc"
}

LEGIT_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "accounts.google.com", "drive.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com"],
    "coinbase": ["coinbase.com"],
    "dhl": ["dhl.com"]
}

def analyze_url(raw_url: str) -> Dict[str, Any]:
    if not raw_url or not raw_url.strip():
        return {
            "has_url": False,
            "url": "",
            "risk_score": 0,
            "flags": [],
            "breakdown": {}
        }

    clean_url = raw_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    parsed = urlparse(clean_url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()
    
    flags = []
    risk_points = 0
    
    # 1. IP Address as Hostname Detection
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        risk_points += 40
        flags.append({
            "type": "IP_HOSTNAME",
            "severity": "CRITICAL",
            "message": f"Raw IP address host detected ({hostname}). Attackers frequently use naked IPs to bypass domain reputation filters."
        })
    except ValueError:
        is_ip = False

    # 2. URL Shortener Detection
    is_shortener = hostname.lower() in KNOWN_SHORTENERS
    if is_shortener:
        risk_points += 25
        flags.append({
            "type": "SHORTENED_URL",
            "severity": "HIGH",
            "message": f"Known URL shortener detected ({hostname}). Shortened links mask the true destination URL."
        })

    # 3. Missing HTTPS / Insecure Scheme
    is_https = scheme == "https"
    if not is_https:
        risk_points += 20
        flags.append({
            "type": "INSECURE_PROTOCOL",
            "severity": "MEDIUM",
            "message": "Unencrypted HTTP protocol used. Sensitive credentials transmitted over HTTP can be intercepted in transit."
        })

    # 4. Suspicious TLD Detection
    tld = hostname.split(".")[-1].lower() if "." in hostname else ""
    has_suspicious_tld = tld in SUSPICIOUS_TLDS
    if has_suspicious_tld:
        risk_points += 30
        flags.append({
            "type": "SUSPICIOUS_TLD",
            "severity": "HIGH",
            "message": f"High-risk Top-Level Domain (.{tld}) identified, frequently utilized in disposable malware and phishing campaigns."
        })

    # 5. Brand Keyword Spoofing / Impersonation Check
    brand_spoofed = False
    spoofed_brand_name = ""
    for brand, legit_domains in LEGIT_BRAND_DOMAINS.items():
        if brand in hostname.lower() or brand in path.lower():
            # Check if actual domain is one of legitimate domains
            is_legit = any(hostname.lower() == ld or hostname.lower().endswith("." + ld) for ld in legit_domains)
            if not is_legit:
                brand_spoofed = True
                spoofed_brand_name = brand
                risk_points += 45
                flags.append({
                    "type": "BRAND_IMPERSONATION",
                    "severity": "CRITICAL",
                    "message": f"Deceptive brand spoofing: Contains '{brand}' trademark in URL, but does not originate from official authorized domains ({', '.join(legit_domains)})."
                })
                break

    # 6. Excessive Subdomain Depth
    subdomain_parts = hostname.split(".")
    excessive_subdomains = len(subdomain_parts) > 3
    if excessive_subdomains:
        risk_points += 20
        flags.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "message": f"Deep subdomain hierarchy detected ({len(subdomain_parts)} domain levels). Phishers stack subdomains to disguise the root apex domain."
        })

    # 7. Multiple Hyphens in Hostname
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        risk_points += 15
        flags.append({
            "type": "DOMAIN_HYPHENATION",
            "severity": "MEDIUM",
            "message": f"Multiple hyphens ({hyphen_count}) detected in domain name, commonly seen in typosquatted domains (e.g. 'paypal-update-login')."
        })

    # 8. Userinfo '@' symbol trickery
    has_at_symbol = "@" in raw_url
    if has_at_symbol:
        risk_points += 35
        flags.append({
            "type": "USERINFO_OBFUSCATION",
            "severity": "HIGH",
            "message": "URL contains '@' symbol. Browsers ignore everything before '@' and route directly to the host behind it."
        })

    # 9. Non-Standard Port Specification
    non_standard_port = False
    if parsed.port and parsed.port not in (80, 443):
        non_standard_port = True
        risk_points += 20
        flags.append({
            "type": "NON_STANDARD_PORT",
            "severity": "MEDIUM",
            "message": f"Unusual network port :{parsed.port} specified. Common phishing servers operate on non-standard ports to evade web gateways."
        })

    # 10. URL Length Heuristic (> 80 characters)
    is_long_url = len(raw_url) > 80
    if is_long_url:
        risk_points += 10
        flags.append({
            "type": "ABNORMAL_LENGTH",
            "severity": "LOW",
            "message": f"Abnormally long URL length ({len(raw_url)} chars), typically containing encoded payload tokens."
        })

    url_risk_score = min(100, risk_points)

    return {
        "has_url": True,
        "url": clean_url,
        "hostname": hostname,
        "scheme": scheme,
        "path": path,
        "is_https": is_https,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "tld": tld,
        "brand_spoofed": brand_spoofed,
        "spoofed_brand": spoofed_brand_name,
        "excessive_subdomains": excessive_subdomains,
        "has_at_symbol": has_at_symbol,
        "risk_score": url_risk_score,
        "flags": flags
    }

# ==============================================================================
# 3. RED-FLAG KEYWORD & URGENCY SCORING
# ==============================================================================

RED_FLAG_PATTERNS = [
    # Critical Urgency & Threat of Restriction
    (r"\b(account.*(?:suspended|locked|terminated|restricted|disabled))\b", 30, "Account Suspension Threat"),
    (r"\b(urgent|immediate(?:ly)?|action required|within 24 hours|final notice)\b", 25, "High Urgency / Pressure Tactic"),
    (r"\b(verify.*(?:identity|account|credentials|profile|security))\b", 25, "Credential Verification Lure"),
    (r"\b(unauthorized.*(?:access|attempt|login|transaction))\b", 25, "False Intrusion Scare"),
    
    # Financial / Credential Exfiltration
    (r"\b(password.*(?:reset|expire|confirm|enter))\b", 20, "Password Harvest Request"),
    (r"\b(credit card|cvv|expiry date|banking details|ssn|social security)\b", 35, "Sensitive Financial Data Request"),
    (r"\b(wire transfer|direct deposit|payroll|crypto(?:currency)?|wallet|bitcoin|ethereum)\b", 25, "Cryptocurrency / Wire Transfer Hook"),
    
    # Bait & Lures
    (r"\b(tax refund|irs|covid grant|claim prize|lottery winner|free gift card)\b", 30, "Lure / Reward Bait"),
    (r"\b(enable macros|download attachment|invoice.*(?:pdf|zip))\b", 25, "Malicious Attachment Prompt"),
    (r"\b(click here|log in to prevent|restore access|dispute charge)\b", 15, "Coercive Call to Action"),
]

def analyze_keywords(text: str) -> Dict[str, Any]:
    if not text or not text.strip():
        return {"score": 0, "detected": [], "count": 0}

    detected = []
    total_score = 0
    lower_text = text.lower()

    for pattern, weight, label in RED_FLAG_PATTERNS:
        matches = re.findall(pattern, lower_text)
        if matches:
            total_score += weight
            detected.append({
                "label": label,
                "weight": weight,
                "occurrences": len(matches)
            })

    score = min(100, total_score)
    return {
        "score": score,
        "detected": detected,
        "count": len(detected)
    }

# ==============================================================================
# 4. COMPOSITE RISK CALCULATION & MITIGATION ENGINE
# ==============================================================================

def generate_recommendations(overall_score: int, url_data: Dict[str, Any], kw_data: Dict[str, Any], ml_data: Dict[str, Any]) -> List[Dict[str, str]]:
    recs = []
    
    if overall_score >= 71:
        recs.append({
            "action": "DO NOT CLICK OR PROCEED",
            "priority": "HIGH",
            "desc": "This item has strong indicators of malicious cyber threat. Do not follow links, open attachments, or input passwords."
        })
    elif overall_score >= 36:
        recs.append({
            "action": "EXERCISE EXTREME CAUTION",
            "priority": "MEDIUM",
            "desc": "Suspicious characteristics detected. Verify the authenticity of this message through an independent verified channel."
        })
    else:
        recs.append({
            "action": "STANDARD SAFE PRACTICES",
            "priority": "LOW",
            "desc": "Low risk indicators detected. Always remain vigilant with personal information and sensitive credentials."
        })

    if url_data.get("has_url"):
        if url_data.get("is_ip"):
            recs.append({
                "action": "BLOCK RAW IP DESTINATIONS",
                "priority": "HIGH",
                "desc": "Legitimate enterprise services rarely link to bare IP addresses. Add IP host to local DNS firewall blocklist."
            })
        if url_data.get("brand_spoofed"):
            recs.append({
                "action": "INSPECT APEX DOMAIN",
                "priority": "HIGH",
                "desc": f"Brand impersonation detected for '{url_data.get('spoofed_brand')}'. Navigate manually to the authentic website rather than clicking provided link."
            })
        if url_data.get("is_shortener"):
            recs.append({
                "action": "UNSHORTEN LINK BEFORE ACCESSING",
                "priority": "MEDIUM",
                "desc": "Use a link expansion previewer (e.g. checkshorturl) to inspect the final redirected landing destination safely."
            })
        if not url_data.get("is_https"):
            recs.append({
                "action": "AVOID UNENCRYPTED CONNECTIONS",
                "priority": "MEDIUM",
                "desc": "Insecure HTTP connection transmits plain-text data susceptible to Man-In-The-Middle (MITM) snooping."
            })

    if kw_data.get("count", 0) > 0:
        recs.append({
            "action": "VERIFY SENDER OUT-OF-BAND",
            "priority": "MEDIUM",
            "desc": "Urgent psychological pressure and account restriction tactics are standard social engineering vectors. Call the sender directly to confirm."
        })

    recs.append({
        "action": "REPORT TO IT SECURITY (SOC)",
        "priority": "LOW",
        "desc": "Forward suspicious email headers (.eml) to your organization's security operations center or abuse@ mailbox."
    })

    return recs

def calculate_composite_risk(text: str, url: str) -> Dict[str, Any]:
    has_text = bool(text and text.strip())
    has_url_input = bool(url and url.strip())

    # Extract URL from text if URL field is empty
    extracted_url = url
    if not has_url_input and has_text:
        found_urls = re.findall(r'(https?://[^\s]+)', text)
        if found_urls:
            extracted_url = found_urls[0]
            has_url_input = True

    ml_result = ml_engine.predict(text) if has_text else {"probability": 0.0, "label": "Legitimate", "confidence": 0.0, "matched_tokens": []}
    kw_result = analyze_keywords(text) if has_text else {"score": 0, "detected": [], "count": 0}
    url_result = analyze_url(extracted_url) if has_url_input else analyze_url("")

    # Adaptive Weighting
    if has_text and url_result.get("has_url"):
        # Blended: 40% ML Probability, 25% Keyword Urgency, 35% URL Heuristics
        composite = (ml_result["probability"] * 0.40) + (kw_result["score"] * 0.25) + (url_result["risk_score"] * 0.35)
    elif url_result.get("has_url") and not has_text:
        # URL only
        composite = url_result["risk_score"]
    elif has_text and not url_result.get("has_url"):
        # Text only: 65% ML Probability, 35% Keyword Urgency
        composite = (ml_result["probability"] * 0.65) + (kw_result["score"] * 0.35)
    else:
        composite = 0.0

    score = int(round(min(100.0, max(0.0, composite))))

    if score >= 71:
        verdict = "Malicious"
        verdict_color = "red"
        threat_level = "High Risk"
    elif score >= 36:
        verdict = "Suspicious"
        verdict_color = "amber"
        threat_level = "Moderate Risk"
    else:
        verdict = "Safe"
        verdict_color = "emerald"
        threat_level = "Low Risk"

    recommendations = generate_recommendations(score, url_result, kw_result, ml_result)

    return {
        "overall_score": score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "threat_level": threat_level,
        "text_analysis": {
            "ml_probability": ml_result["probability"],
            "ml_verdict": ml_result["label"],
            "ml_confidence": ml_result["confidence"],
            "matched_tokens": ml_result["matched_tokens"],
            "keyword_score": kw_result["score"],
            "red_flags": kw_result["detected"]
        },
        "url_analysis": url_result,
        "recommendations": recommendations,
        "timestamp": datetime.now().isoformat()
    }

# ==============================================================================
# 5. RECENT SCAN STORAGE & THREAT STATS
# ==============================================================================

RECENT_SCANS: List[Dict[str, Any]] = []

# ==============================================================================
# 6. API & TEMPLATE ROUTES
# ==============================================================================

class AnalyzeRequest(BaseModel):
    text: Optional[str] = ""
    url: Optional[str] = ""

@app.get("/", response_class=HTMLResponse)
async def page_index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html", 
        context={"active_page": "detector"}
    )

@app.get("/analytics", response_class=HTMLResponse)
async def page_analytics(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="analytics.html", 
        context={"active_page": "analytics", "metrics": ml_engine.metrics}
    )

@app.get("/download-report")
async def download_word_report():
    from fastapi.responses import FileResponse
    doc_path = os.path.join(BASE_DIR, "Mujjafar_Sayyad_AI_Cyber_Threat_Project_Report.docx")
    if os.path.exists(doc_path):
        return FileResponse(
            path=doc_path,
            filename="Mujjafar_Sayyad_AI_Cyber_Threat_Project_Report.docx",
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
    return JSONResponse(status_code=404, content={"error": "Report file not found"})

@app.get("/about", response_class=HTMLResponse)
async def page_about(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="about.html", 
        context={"active_page": "about"}
    )

@app.post("/api/analyze")
async def api_analyze(payload: AnalyzeRequest):
    result = calculate_composite_risk(payload.text or "", payload.url or "")
    
    # Record to recent scans
    summary = (payload.url or payload.text or "Empty Scan")[:45]
    if len(payload.url or payload.text or "") > 45:
        summary += "..."
    scan_record = {
        "id": f"SCAN-{len(RECENT_SCANS) + 1}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "Text & URL" if (payload.text and payload.url) else ("URL Only" if payload.url else "Text Only"),
        "summary": summary,
        "score": result["overall_score"],
        "verdict": result["verdict"]
    }
    RECENT_SCANS.insert(0, scan_record)
    if len(RECENT_SCANS) > 30:
        RECENT_SCANS.pop()
        
    return JSONResponse(content=result)

@app.get("/api/analytics")
@app.get("/api/model-stats")
async def api_analytics_data():
    total_scans = len(RECENT_SCANS)
    malicious_count = sum(1 for s in RECENT_SCANS if s["verdict"] == "Malicious")
    suspicious_count = sum(1 for s in RECENT_SCANS if s["verdict"] == "Suspicious")
    safe_count = sum(1 for s in RECENT_SCANS if s["verdict"] == "Safe")
    avg_score = round(sum(s["score"] for s in RECENT_SCANS) / max(1, total_scans), 1)

    return JSONResponse(content={
        "metrics": ml_engine.metrics,
        "top_features": ml_engine.top_features,
        "scan_stats": {
            "total_scans": total_scans,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
            "avg_score": avg_score
        },
        "recent_scans": RECENT_SCANS[:10]
    })

@app.get("/api/sample-data")
@app.get("/api/quick-samples")
async def api_sample_data():
    samples = {
        "phishing_email": {
            "title": "Malicious Account Suspension Phishing",
            "text": "URGENT: Your PayPal account has been permanently restricted due to unauthorized login attempts. To restore access and verify your identity, please confirm your password immediately within 24 hours.",
            "url": "http://paypal-security-update.com/login"
        },
        "spoofed_ip_url": {
            "title": "Naked IP Credential Harvester",
            "text": "Your Bank of America checking account was suspended. Log in here to review security alert details.",
            "url": "http://185.220.101.45:8080/bofa-verification/auth"
        },
        "shortened_url_bait": {
            "title": "Suspicious Shortened Link Lottery Lure",
            "text": "Congratulations! You have been selected as the winner of a $500 Amazon gift card. Claim prize before midnight!",
            "url": "https://bit.ly/amz-free-giftcard-claim"
        },
        "safe_corporate_message": {
            "title": "Safe Corporate Sprint Update",
            "text": "Hi team, please find attached the quarterly engineering sprint retrospective notes and agenda for tomorrow morning's standup meeting.",
            "url": "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit"
        }
    }
    return JSONResponse(content=samples)

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AI Cyber Threat & Phishing Detection Engine",
        "timestamp": datetime.now().isoformat(),
        "model_trained": bool(ml_engine.metrics)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
