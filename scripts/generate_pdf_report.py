"""
scripts/generate_pdf_report.py — Generates a publication-grade PDF from docs/TECHNICAL_REPORT.md.
Uses Python Markdown + Chrome/Edge headless print-to-pdf.
"""

import os
import sys
import subprocess
import markdown

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MD_PATH = os.path.join(ROOT_DIR, "docs", "TECHNICAL_REPORT.md")
HTML_PATH = os.path.join(ROOT_DIR, "docs", "report.html")
PDF_PATH = os.path.join(ROOT_DIR, "docs", "NEXUS_NIDS_Technical_Report.pdf")

# Detect Chrome or Edge executable
CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]
browser_exe = None
for p in CHROME_PATHS:
    if os.path.exists(p):
        browser_exe = p
        break

if not browser_exe:
    print("[ERROR] Neither Chrome nor Edge executable was found.")
    sys.exit(1)

print(f"[+] Detected browser engine: {browser_exe}")

# Read markdown
with open(MD_PATH, "r", encoding="utf-8") as f:
    md_content = f.read()

# Replace raw LaTeX math markers with clean typographic Unicode
math_replacements = [
    (r"$$\text{Match} \iff (\text{duration} \le 1.0\text{ s}) \land (\text{src\_bytes} \le 100\text{ B}) \land (\text{dst\_bytes} \le 100\text{ B})$$",
     "<div class='math-block'>Match &hArr; (duration &le; 1.0s) &and; (src_bytes &le; 100B) &and; (dst_bytes &le; 100B)</div>"),
    (r"$$\text{Match} \iff (\text{duration} \ge 60.0\text{ s}) \land (\text{dst\_bytes} \ge 10{,}000{,}000\text{ B}\ [10\text{ MB}])$$",
     "<div class='math-block'>Match &hArr; (duration &ge; 60.0s) &and; (dst_bytes &ge; 10,000,000B [10 MB])</div>"),
    (r"$$\text{Match} \iff (\text{src\_bytes} \ge 1{,}000\text{ B}) \land \left(\frac{\text{src\_bytes}}{\text{dst\_bytes} + 1.0} \ge 10.0\right)$$",
     "<div class='math-block'>Match &hArr; (src_bytes &ge; 1,000B) &and; (src_bytes / (dst_bytes + 1.0) &ge; 10.0)</div>"),
    (r"$$\text{Match} \iff (\text{dst\_bytes} \ge 1{,}000\text{ B}) \land \left(\frac{\text{dst\_bytes}}{\text{src\_bytes} + 1.0} \ge 10.0\right)$$",
     "<div class='math-block'>Match &hArr; (dst_bytes &ge; 1,000B) &and; (dst_bytes / (src_bytes + 1.0) &ge; 10.0)</div>"),
    (r"$$\text{Accuracy} = \frac{2{,}105 + 1{,}824}{3{,}985} = \mathbf{98.59\%}$$",
     "<div class='math-block'>Accuracy = (2,105 + 1,824) / 3,985 = <strong>98.59%</strong></div>"),
    (r"$$\text{Precision} = \frac{1{,}824}{1{,}824 + 56} = \mathbf{97.02\%}$$",
     "<div class='math-block'>Precision = 1,824 / (1,824 + 56) = <strong>97.02%</strong></div>"),
    (r"$$\text{Recall} = \frac{1{,}824}{1{,}824 + 0} = \mathbf{100.00\%}$$",
     "<div class='math-block'>Recall = 1,824 / (1,824 + 0) = <strong>100.00%</strong></div>"),
    (r"$$\text{F1} = 2 \times \frac{0.9702 \times 1.0000}{0.9702 + 1.0000} = \mathbf{98.49\%}$$",
     "<div class='math-block'>F1-Score = 2 &times; (0.9702 &times; 1.0000) / (0.9702 + 1.0000) = <strong>98.49%</strong></div>"),
    (r"$$\text{FNR} = \mathbf{0.00\%}\quad (0\text{ out of }1{,}824\text{ intrusions missed})$$",
     "<div class='math-block'>False Negative Rate (FNR) = <strong>0.00%</strong> (0 out of 1,824 intrusions missed)</div>"),
    (r"$$\text{FPR} = \frac{56}{2{,}161} = \mathbf{2.59\%}$$",
     "<div class='math-block'>False Positive Rate (FPR) = 56 / 2,161 = <strong>2.59%</strong></div>"),
    (r"$$s(\mathbf{x}, n) = 2^{-\frac{\mathbb{E}(h(\mathbf{x}))}{c(n)}}$$",
     "<div class='math-block'>s(x, n) = 2<sup>-E(h(x)) / c(n)</sup></div>"),
    (r"$\approx 1.2\text{ ms}$", "<strong>~1.2 ms</strong>"),
    (r"$\approx 1.24\text{ ms}$", "<strong>~1.24 ms</strong>"),
    (r"$\mathbf{0.85\text{ ms}}$", "<strong>0.85 ms</strong>"),
    (r"$\mathbf{1.24\text{ ms}}$", "<strong>1.24 ms</strong>"),
    (r"$\mathbf{5.67\text{ ms}}$", "<strong>5.67 ms</strong>"),
    (r"$\mathbf{x} = [\text{duration}, \text{src\_bytes}, \text{dst\_bytes}] \in \mathbb{R}^3$", "<strong>x</strong> = [duration, src_bytes, dst_bytes] &isin; &reals;<sup>3</sup>"),
    (r"$(\text{src\_ip}, \text{src\_port}, \text{dst\_ip}, \text{dst\_port})$", "(src_ip, src_port, dst_ip, dst_port)"),
    (r"$\nu = 0.05$", "&nu; = 0.05"),
    (r"$h(\mathbf{x})$", "h(x)"),
    (r"$c(n) = 2\ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$", "c(n) = 2 ln(n - 1) + 0.5772156649 - 2(n - 1)/n"),
    (r"$\ge 0.50$", "&ge; 0.50"),
    (r"$< 0$", "&lt; 0"),
    (r"$< 0.05\text{ s}$", "&lt; 0.05s"),
    (r"$< 1\text{ ms}$", "&lt; 1 ms"),
    (r"($< 0.85\text{ ms}$ on standard x86-64 hardware)", "(&lt; 0.85 ms on standard x86-64 hardware)"),
    (r"880 Hz $\to$ 440 Hz", "880 Hz &rarr; 440 Hz"),
]

for old, new in math_replacements:
    md_content = md_content.replace(old, new)

# Convert markdown to HTML
html_body = markdown.markdown(
    md_content,
    extensions=["extra", "tables", "fenced_code", "toc", "nl2br"]
)

# HTML Template with Executive Styling
html_full = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NEXUS NIDS — Comprehensive Technical Architecture & Evaluation Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  @page {{
    size: A4;
    margin: 13mm 12mm 13mm 12mm;
    @bottom-right {{
      content: counter(page);
    }}
  }}

  * {{
    box-sizing: border-box;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }}

  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 9.5pt;
    line-height: 1.48;
    color: #1e293b;
    background: #ffffff;
    margin: 0;
    padding: 0;
  }}

  h1 {{
    font-size: 20pt;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.03em;
    margin-top: 0;
    margin-bottom: 3px;
    padding-bottom: 6px;
    border-bottom: 2px solid #0284c7;
  }}

  h2 {{
    font-size: 13pt;
    font-weight: 700;
    color: #0369a1;
    letter-spacing: -0.02em;
    margin-top: 15pt;
    margin-bottom: 6pt;
    padding-bottom: 3pt;
    border-bottom: 1px solid #e2e8f0;
    page-break-after: avoid;
    break-after: avoid;
  }}

  h3 {{
    font-size: 11pt;
    font-weight: 600;
    color: #0f172a;
    margin-top: 11pt;
    margin-bottom: 4pt;
    page-break-after: avoid;
    break-after: avoid;
  }}

  h4 {{
    font-size: 10pt;
    font-weight: 600;
    color: #334155;
    margin-top: 8pt;
    margin-bottom: 3pt;
    page-break-after: avoid;
    break-after: avoid;
  }}

  p, li {{
    color: #334155;
    margin-top: 0;
    margin-bottom: 5pt;
  }}

  ul, ol {{
    margin-top: 2pt;
    margin-bottom: 6pt;
    padding-left: 18px;
  }}

  li {{
    margin-bottom: 2.5pt;
  }}

  strong {{
    font-weight: 600;
    color: #0f172a;
  }}

  blockquote {{
    margin: 8pt 0 12pt 0;
    padding: 8pt 12pt;
    background: #f0fdf4;
    border-left: 4px solid #16a34a;
    border-radius: 4px;
    color: #166534;
    font-size: 9.5pt;
    font-style: italic;
  }}

  blockquote p {{
    margin: 0;
    color: #166534;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0 14pt 0;
    font-size: 8.5pt;
    page-break-inside: avoid;
    break-inside: avoid;
  }}

  th {{
    background: #f1f5f9;
    color: #0f172a;
    font-weight: 600;
    text-align: left;
    padding: 6pt 8pt;
    border: 1px solid #cbd5e1;
    font-size: 8.5pt;
  }}

  td {{
    padding: 5pt 8pt;
    border: 1px solid #e2e8f0;
    color: #334155;
    vertical-align: top;
  }}

  tr:nth-child(even) td {{
    background: #f8fafc;
  }}

  pre {{
    background: #0f172a !important;
    color: #f8fafc !important;
    padding: 10pt 12pt;
    border-radius: 6px;
    font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
    font-size: 8pt;
    line-height: 1.45;
    overflow-x: auto;
    margin: 8pt 0 12pt 0;
    border: 1px solid #1e293b;
    page-break-inside: avoid;
    break-inside: avoid;
  }}

  code {{
    font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
    font-size: 8.5pt;
    background: #f1f5f9;
    color: #0369a1;
    padding: 1pt 3pt;
    border-radius: 3px;
    border: 1px solid #e2e8f0;
  }}

  pre code {{
    background: transparent !important;
    color: #f8fafc !important;
    padding: 0;
    border: none;
    font-size: 8pt;
  }}

  hr {{
    border: none;
    border-top: 1px solid #e2e8f0;
    margin: 16pt 0;
  }}

  .math-block {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 3px solid #0284c7;
    padding: 5pt 10pt;
    margin: 5pt 0 8pt 0;
    font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
    font-size: 8.5pt;
    color: #0f172a;
    border-radius: 4px;
    page-break-inside: avoid;
    break-inside: avoid;
  }}

  .badge {{
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 7.5pt;
    font-weight: 600;
    text-transform: uppercase;
  }}
  .badge-success {{ background: #dcfce7; color: #15803d; }}
  .badge-critical {{ background: #fee2e2; color: #b91c1c; }}
  .badge-info {{ background: #e0f2fe; color: #0369a1; }}

  /* Cover Header decoration */
  .doc-header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #ffffff;
    padding: 18pt 20pt;
    border-radius: 8px;
    margin-bottom: 18pt;
  }}
  .doc-header h1 {{
    color: #38bdf8;
    border-bottom: none;
    margin-bottom: 2pt;
  }}
  .doc-header p {{
    color: #94a3b8;
    margin-bottom: 0;
  }}
</style>
</head>
<body>

{html_body}

</body>
</html>
"""

with open(HTML_PATH, "w", encoding="utf-8") as f:
    f.write(html_full)

print(f"[+] Wrote styled HTML to {HTML_PATH}")

# Launch browser to convert HTML to PDF
cmd = [
    browser_exe,
    "--headless",
    "--disable-gpu",
    "--no-pdf-header-footer",
    f"--print-to-pdf={PDF_PATH}",
    HTML_PATH
]

print(f"[+] Generating PDF via browser headless print...")
proc = subprocess.run(cmd, capture_output=True, text=True)
if proc.returncode != 0:
    print(f"[ERROR] Headless conversion failed: {proc.stderr}")
    sys.exit(proc.returncode)

if os.path.exists(PDF_PATH):
    size_kb = os.path.getsize(PDF_PATH) / 1024
    print(f"[SUCCESS] PDF generated successfully: {PDF_PATH} ({size_kb:.1f} KB)")
else:
    print("[ERROR] PDF was not created.")
    sys.exit(1)
