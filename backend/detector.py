import re

suspicious_patterns = {
  r"os\.system\s*\(": {
      "weight": 40,
      "category": "command_execution"
  },
  r"subprocess": {
      "weight": 40,
      "category": "process_execution"  
  },
  r"eval\s*\(": {
      "weight": 30,
      "category": "code_execution"
  },
  r"exec\s*\(": {
      "weight": 30,
      "category": "code_execution"
  },
  r"base64": {
      "weight": 20,
      "category": "data_encoding"
  },
  r"socket": {
      "weight": 25,
      "category": "network_activity"
  },
    r"requests": {
        "weight": 10,
        "category": "network_activity"
    },
    r"powershell": {
        "weight": 40,
        "category": "command_execution"
    },
    r"rm\s+-rf": {
        "weight": 50,
        "category": "file_deletion"
    }
}

def analyze_script(script_content):

    findings = []
    script_content=script_content.lower()
    severity = "NONE"
    risk_score = 0

    for pattern,info in suspicious_patterns.items():

        if re.search(pattern, script_content):

            findings.append(info["category"])

            risk_score += info["weight"]
            if risk_score >= 80:
                severity = "CRITICAL"

            elif risk_score >= 50:
                severity = "HIGH"

            elif risk_score >= 20:
                severity = "MEDIUM"

            else:
                severity = "LOW"
                
    if not findings:
        return {
            "findings": [],
            "risk_score": 0,
            "is_malicious": False,
            "severity": "NONE"
        }
    else:
        return {
            "findings": findings,
            "risk_score": risk_score,
            "is_malicious": risk_score > 20,
            "severity": severity
        }