import re

# ==========================================
# MALICIOUS BEHAVIOR PATTERNS
# ==========================================

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

# ==========================================
# OBFUSCATION PATTERNS
# ==========================================

obfuscation_patterns = {

    r"base64\.b64decode\s*\(": {
        "weight": 30,
        "category": "obfuscation"
    },

    r"getattr\s*\(": {
        "weight": 20,
        "category": "dynamic_execution"
    },

    r"compile\s*\(": {
        "weight": 25,
        "category": "dynamic_execution"
    },

    r"chr\s*\(": {
        "weight": 15,
        "category": "character_obfuscation"
    },

    r"(\\x[0-9a-fA-F]{2}){3,}": {
        "weight": 20,
        "category": "hex_obfuscation"
    }
}

# ==========================================
# ANALYSIS ENGINE
# ==========================================

def analyze_script(script_content):

    script_content = script_content.lower()

    findings = []
    risk_score = 0

    # Merge all rules
    all_patterns = {
        **suspicious_patterns,
        **obfuscation_patterns
    }

    # Scan script
    for pattern, info in all_patterns.items():

        matches = re.findall(pattern, script_content)
        count = len(matches)

        if count > 0:

            risk_score += info["weight"] * count

            findings.append({
                "category": info["category"],
                "count": count,
                "weight": info["weight"]
            })

    # Cap score
    risk_score = min(risk_score, 100)

    # No detections
    if not findings:

        return {
            "findings": [],
            "risk_score": 0,
            "severity": "NONE",
            "is_malicious": False,
            "message": "No suspicious patterns detected."
        }

    # Severity calculation
    if risk_score >= 80:
        severity = "CRITICAL"

    elif risk_score >= 50:
        severity = "HIGH"

    elif risk_score >= 20:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "findings": findings,
        "risk_score": risk_score,
        "severity": severity,
        "is_malicious": risk_score >= 20
    }


# ==========================================
# TESTING
# ==========================================

if __name__ == "__main__":

    test_script = """
    import base64
    import os

    payload = base64.b64decode("SGVsbG8=")

    eval("print('hello')")

    os.system("whoami")
    """

    result = analyze_script(test_script)

    print(result)