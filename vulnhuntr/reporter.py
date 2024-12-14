import html
import os
import sys
from vulnhuntr.models import Response

def initialize_report():
    file_name = "reporter.html"
    if os.path.exists(file_name):
        user_input = input("Report File Exists! Delete reporter.html? y/(n): ").strip().lower()
        if user_input == 'y':
            os.remove(file_name)
            print(f"{file_name} has been deleted, recreating")
        else:
            print(f"{file_name} was not deleted, please handle with it manually")
            sys.exit(0)

    with open(file_name, "w") as report_html:
        header = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Report</title>
<style>
    body {
        font-family: Arial, sans-serif;
        margin: 20px;
        background-color: #f4f4f9;
        color: #333;
    }
    .container {
        max-width: 800px;
        margin: auto;
        background: #fff;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
        border-radius: 8px;
        margin-bottom: 20px;
    }
    h2 {
        color: #e63946;
    }
    h3 {
        color: #457b9d;
    }
    pre {
        background: #f1faee;
        padding: 10px;
        border-radius: 5px;
        overflow-x: auto;
        white-space: pre-wrap;
        max-width: 1024px;
    }
</style>
</head>
<body>
"""
        report_html.write(header)

def finalize_report():
    with open("reporter.html", "a") as report_html:
        footer = """
</body>
</html>
"""
        report_html.write(footer)

def add_vuln_to_report(response: Response, filepath: str):
    with open("reporter.html", "a") as report_html:
        if "<" in response.poc or ">" in response.poc:
            poc = html.escape(response.poc)
        else:
            poc = response.poc
        if "<" in response.scratchpad or ">" in response.scratchpad:
            scratchpad = html.escape(response.scratchpad)
        else:
            scratchpad = response.scratchpad
        if "<" in response.analysis or ">" in response.analysis:
            analysis = html.escape(response.analysis)
        else:
            analysis = response.analysis

        info = f"""
    <div class="container">
        <h2>({html.escape(str(response.confidence_score))} Score) {html.escape(",".join(response.vulnerability_types))} in {html.escape(filepath)}</h2>
        <h3>分析结论</h3>
        <pre>{analysis}</pre>
        <h3>分析过程</h3>
        <pre>{scratchpad}</pre>
        <h3>PoC</h3>
        <pre>{poc}</pre>
    </div>
"""
        report_html.write(info)

def add_summary_to_report(summary: str):
    with open("reporter.html", "a") as report_html:
        info = f"""
    <div class="container">
        <h2>Summary</h2>
        <pre>{html.escape(summary)}</pre>
    </div>
"""
        report_html.write(info)