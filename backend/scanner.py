import json
import sys

from detector import analyze_script


def scan_file(filename):

    try:

        with open(filename, "r", encoding="utf-8") as file:
            script_content = file.read()

        result = analyze_script(script_content)

        return result

    except Exception as e:

        return {
            "error": str(e)
        }



def save_report(result, filename="reports/report.json"):

    with open(filename, "w") as file:

        json.dump(
            result,
            file,
            indent=4
        )
        
def print_report(result):

    print("\n======================")
    print("SCRIPT ANALYSIS REPORT")
    print("======================\n")

    print("Risk Score :", result["risk_score"])
    print("Severity   :", result["severity"])
    print("Malicious  :", result["is_malicious"])

    print("\nFindings:")

    for finding in result["findings"]:

        print(
            f"- {finding['category']} "
            f"(Count: {finding['count']})"
        )

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("Usage:")
        print("python scanner.py <filename.py>")
        sys.exit()

    target_file = sys.argv[1]

    result = scan_file(target_file)

    print("\n===== ANALYSIS REPORT =====\n")

    print_report(result)

    save_report(result)

    print("\nReport saved successfully.")