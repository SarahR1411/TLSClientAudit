from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

def generate_pdf(result, filename="tls_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("<b>TLS Cipher Suite Security Report</b>", styles["Title"]))
    story.append(Spacer(1, 20))

    for k, v in result.items():
        story.append(Paragraph(f"<b>{k}</b> : {v}", styles["Normal"]))
        story.append(Spacer(1, 8))

    doc.build(story)

