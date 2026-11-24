import io

from pypdf import PdfReader

MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PAGES = 20


def extract_text(pdf_bytes: bytes) -> str:
    """Extract all text, including hidden (white / tiny) text. Raises ValueError on limits or bad input."""
    if len(pdf_bytes) > MAX_PDF_BYTES:
        raise ValueError(f"PDF too large (max {MAX_PDF_BYTES} bytes)")
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        if len(reader.pages) > MAX_PAGES:
            raise ValueError(f"PDF has too many pages (max {MAX_PAGES})")
        return "\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"cannot read PDF: {exc}") from exc
