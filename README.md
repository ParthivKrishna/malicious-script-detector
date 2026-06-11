# Malicious Script Detector

A cybersecurity-focused Python project that analyzes scripts for potentially malicious behavior using signature-based detection, regex pattern matching, weighted threat scoring, and severity classification.

This project is being developed as the foundation for an AI-powered malicious script detection and browser exploitation prevention system.

## Features

### Current Features

* Regex-based malicious pattern detection
* Weighted threat scoring
* Severity classification
* Detection categories
* Structured analysis results

### Detection Categories

* Command Execution
* Process Execution
* Code Execution
* Network Activity
* Data Encoding
* File Deletion

### Example Detected Patterns

* `os.system()`
* `subprocess`
* `eval()`
* `exec()`
* `socket`
* `requests`
* `powershell`
* `base64`
* `rm -rf`

## Example Output

```python
{
    "findings": [
        {
            "pattern": "eval",
            "category": "code_execution",
            "count": 2,
            "weight": 30
        }
    ],
    "risk_score": 60,
    "severity": "HIGH",
    "is_malicious": True
}
```

## Project Goal

The long-term goal of this project is to develop an AI-assisted malicious script analysis system capable of detecting:

* Obfuscated code
* Browser exploitation attempts
* Malicious JavaScript payloads
* Command execution techniques
* Network-based malware behavior
* Previously unseen attack patterns using machine learning

## Planned Features

### Version 3

* Occurrence counting
* Detailed finding reports
* Improved scoring engine

### Version 4

* Obfuscation detection
* Base64 analysis
* Dynamic execution detection

### Version 5

* Flask-based web dashboard
* Upload and analyze scripts

### Version 6

* Machine learning classification
* Benign vs malicious prediction
* Threat intelligence integration

## Technologies Used

* Python
* Regular Expressions (Regex)
* Cybersecurity Detection Rules

## Disclaimer

This project is intended for educational purposes, cybersecurity research, and defensive security analysis only.
