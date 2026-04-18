# 🛡️ Satya Ai: The Digital Trust Hub

**A multilingual AI forensics engine to detect fake news and AI-generated media in real-time.** 

**Note on Repository Status:** *This repository serves as a technical showcase and architectural overview. The core proprietary AI scoring engine and backend logic remain closed-source.*

---

## 🚀 Overview

The internet has changed. Misinformation is no longer just text on a screen; it is a highly industrialized, AI-driven weapon.      **Satya Ai** is a real-time, multilingual Digital Trust Hub designed to move everyday internet users from being passive victims to having an active defense. 

Built on a highly scalable, decoupled architecture, Satya Ai intercepts threats across three distinct vectors: Text, Media, and Applications.

---

## ✨ Core Features (The 3-Pillar Defense)

***📰 Fake News Text Detector:** Analyzes pasted text or scraped live URLs natively across 100+ languages to classify the content as real, fake, or uncertain. [cite: 940]
***📸 AI Image Detector (Deepfake Scanner):** Evaluates uploaded images for synthesized noise, unnatural lighting, and background artifacts to return a granular probability score of AI generation. [cite: 941]
***📱 Malicious App Scanner:** A dual-threat module that analyzes Google Play Store URLs for developer metadata red flags and scans uploaded APK file hashes for malware. [cite: 942]

---

## 🧠 The Innovation: Explainable AI (XAI)

Most cybersecurity tools are "black boxes" that output a confusing percentage score. Satya Ai breaks this barrier using **Explainable AI (XAI)**. 

Instead of just giving a number, our system acts as a digital forensic analyst. It dynamically generates an "Executive Summary" paragraph that explains to the user in plain English exactly why a specific decision was made.Furthermore, it instantly cross-references claims with live databases to provide real journalistic source links as proof.

---

## 🛠️ Technical Architecture

Satya Ai is engineered as a decoupled, modern web application prioritizing sub-second latency and smooth user experience.

### **Frontend (The Client)**
***Tech Stack:** Built with React 19, Vite, and Tailwind CSS.
***UX Strategy:** Utilizes Framer Motion for AnimatePresence, ensuring layout transitions simulate a high-tech intelligence tool without jarring DOM jumps.
***Semantic Visualization:** Translates complex AI probabilities into visual trust cues (Emerald = Safe, Amber = Warning, Rose = Fake).

### **Backend (The Brain)**
***Tech Stack:** Powered by FastAPI (Python), handling heavy AI calculations and asynchronous data routing.
***AI Models:** Integrates HuggingFace's `xlm-roberta-base` for native multilingual text classification, alongside `spaCy` for Named Entity Recognition (NER).
***Cross-Referencing Engines:** Leverages the Google Fact Check Tools API, NewsAPI, Hive Moderation API, and VirusTotal API for live threat verification.

---

## 📸 Interface Showcase

*(Add your screenshots here! Example formats below:)*

* **Results Dashboard:**
  `![Results Dashboard](./docs/dashboard-screenshot.png)`
* **Explainable AI Summary in Action:**
  `![XAI Summary](./docs/xai-screenshot.png)`
* **App Scanner Toggle:**
  `![App Scanner](./docs/app-scanner.png)`

---

## 🌍 Real-World Impact

A great algorithm means nothing if it doesn’t help real people. Satya Ai is designed to protect:
***Citizens & Voters:** Targeted by extreme-severity election deepfakes and mass panic. 
***Investors & Markets:** Retail investors manipulated by fabricated financial narratives. 
***Everyday Users:** Providing hyper-localized defense by outputting forensic summaries in the user's chosen regional language.

---

## 🤝 Contact & Team

This project was proudly developed for **CodeSrijan 2026**. 

* **Team:** The Intellectuals
* **Developers:** * swapnil - [https://www.linkedin.com/in/swapnil-arya-657589387?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app]
  * naman priya sharama - [https://www.linkedin.com/in/naman-priya-sharma-90b075349]
  * ashwin singh pramar - [https://www.linkedin.com/in/ashwin-singh-pramar-a297a336b]

*In a world of generative AI, we need generative defense. Satya Ai is that defense.* 