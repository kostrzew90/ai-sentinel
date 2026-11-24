import pytest

from sentinel.agent.pdf import MAX_PAGES, MAX_PDF_BYTES, extract_text
from sentinel.redteam.scenarios import get_scenario

SCENARIO = get_scenario("indirect_injection")


@pytest.mark.parametrize("variant", SCENARIO["variants"], ids=lambda v: v["id"])
def test_hidden_text_extracted(variant):
    text = extract_text(variant["pdf_path"].read_bytes())
    assert variant["pdf"]["visible_text"].splitlines()[0] in text
    marker = " ".join(variant["pdf"]["hidden_text"].split()[:6])
    assert marker in " ".join(text.split())
    assert "Portside Logistics Park" in text


def test_oversized_pdf_rejected():
    with pytest.raises(ValueError):
        extract_text(b"%PDF-" + b"0" * MAX_PDF_BYTES)


def test_garbage_rejected():
    with pytest.raises(ValueError):
        extract_text(b"not a pdf")


def test_too_many_pages_rejected():
    from reportlab.pdfgen import canvas
    import io

    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    for _ in range(MAX_PAGES + 1):
        c.drawString(10, 10, "x")
        c.showPage()
    c.save()
    with pytest.raises(ValueError):
        extract_text(buf.getvalue())
