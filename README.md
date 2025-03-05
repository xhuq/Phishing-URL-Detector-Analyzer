# Phishing URL Detector & Analyzer

A Python-based tool to detect potential phishing URLs using heuristic analysis without external API dependencies.

---

## Features
- 10-point detection system
- Risk score calculation
- Detailed URL analysis
- No API keys required
- Fast local execution

---

## Installation

1. Clone the repository :
    ```bash
   git clone https://github.com/yourusername/phishing-detector.git

   cd phishing-detector

2. Install dependencies :
   ```bash
   pip install -r requirements.txt

3. Run the detector using python :
   ```bash
   python phishing_detector.py

4. Enter the URL when prompted

   Example:
   ```bash
   Enter URL to analyze: http://suspicious-site.com/login/verify?user=test

---

## Detection Features 

- URL Length Analysis

- Subdomain Count Check

- IP Address Detection

- Non-Standard Port Detection

- URL Shortener Check

- '@' Symbol Detection

- Double Slash Detection

- Suspicious Domain Keywords

- HTTPS in Domain Check

- HTTPS Implementation Verification

---

## Risk Scoring
- Score 0-4: Likely Safe

- Score 5-15: Potential Phishing

---

## Dependencies
- Python 3.6+

- requests library

---  

## Limitations
This tool uses heuristic analysis and may produce false positives/negatives. Always verify results manually.

---

## Contributing
Contributions are welcome! Please open an issue first to discuss proposed changes.

