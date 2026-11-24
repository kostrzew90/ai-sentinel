"""Generate scenario PDFs: visible text in black, hidden text in white 1.5pt in the footer."""

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from sentinel.redteam.scenarios import load_scenarios


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def make_pdf(path, visible_text: str, hidden_text: str) -> None:
    c = canvas.Canvas(str(path), pagesize=A4)
    c.setCreator("ai-sentinel fixtures")
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 12)
    y = 780
    for line in visible_text.strip().splitlines():
        c.drawString(60, y, line)
        y -= 18
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica", 1.5)
    y = 40
    for line in _wrap(hidden_text, 150):
        c.drawString(60, y, line)
        y -= 2
    c.save()


def main() -> None:
    for scenario in load_scenarios():
        for v in scenario["variants"]:
            if "pdf" not in v:
                continue
            v["pdf_path"].parent.mkdir(parents=True, exist_ok=True)
            make_pdf(v["pdf_path"], v["pdf"]["visible_text"], v["pdf"]["hidden_text"])
            print("wrote", v["pdf_path"])


if __name__ == "__main__":
    main()
