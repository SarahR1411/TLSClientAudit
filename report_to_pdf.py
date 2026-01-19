import json
import sys
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


def json_to_pdf(json_file, output_pdf):
    # Charger le JSON
    with open(json_file, "r") as f:
        report = json.load(f)

    # Charger le template HTML
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")

    # Rendu HTML
    html_content = template.render(report=report)

    # Génération PDF
    HTML(string=html_content).write_pdf(output_pdf)

    print(f"[+] PDF generated: {output_pdf}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python report_to_pdf.py <report.json> <output.pdf>")
        sys.exit(1)

    json_to_pdf(sys.argv[1], sys.argv[2])
