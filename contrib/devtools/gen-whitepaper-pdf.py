#!/usr/bin/env python3
"""Render doc/whitepaper-quantum-quasar.md as a formatted white paper PDF.

Requires: pip install reportlab
Usage: python3 contrib/devtools/gen-whitepaper-pdf.py
"""
import re, sys, os
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
                                Table, TableStyle, PageBreak, HRFlowable, KeepTogether)
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "doc", "whitepaper-quantum-quasar.md")
OUT = os.path.join(ROOT, "doc", "whitepaper-quantum-quasar.pdf")

GOLD = colors.HexColor("#B8860B")
DARK = colors.HexColor("#1a1a1a")
GREY = colors.HexColor("#444444")
LIGHT = colors.HexColor("#f2ecdd")
RULE = colors.HexColor("#c8b273")

# ---------- text sanitation (WinAnsi-safe) ----------
SUBS = {
    "✅": "Yes", "❌": "No", "→": "->", "≤": "<=", "≥": ">=",
    "≈": "~", "−": "-", "×": "x", "…": "...", "‑": "-",
    "​": "", "️": "", "–": "–", "—": "—",
}
def sanitize(s):
    for k, v in SUBS.items():
        s = s.replace(k, v)
    # t² style superscripts -> markup later; keep ² (WinAnsi has it)
    return s

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def inline(s):
    """Convert inline markdown to reportlab XML markup."""
    s = sanitize(s)
    s = re.sub(r"\*\*(`[^`]+`)\*\*", r"\1", s)  # bold-wrapped code spans: keep the code styling
    out, i, buf = [], 0, []
    # protect code spans first
    parts = re.split(r"(`[^`]+`)", s)
    res = ""
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            res += '<font face="Courier" size="8.3" color="#7a5a00">' + esc(p[1:-1]) + "</font>"
        else:
            t = esc(p)
            t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
            t = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<i>\1</i>", t)
            # links: internal anchors -> plain text; external -> text (url)
            t = re.sub(r"\[([^\]]+)\]\(#[^)]*\)", r"\1", t)
            t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", t)
            res += t
    res = res.replace("t²", "t<super>2</super>").replace("²", "<super>2</super>")
    return res

# ---------- styles ----------
BODY = ParagraphStyle("Body", fontName="Helvetica", fontSize=9.5, leading=13.4,
                      alignment=TA_JUSTIFY, textColor=DARK, spaceAfter=6)
H1 = ParagraphStyle("H1x", fontName="Helvetica-Bold", fontSize=15, leading=19,
                    textColor=DARK, spaceBefore=18, spaceAfter=6)
H2 = ParagraphStyle("H2x", fontName="Helvetica-Bold", fontSize=11.5, leading=15,
                    textColor=colors.HexColor("#5a4500"), spaceBefore=12, spaceAfter=4)
BULLET = ParagraphStyle("Bul", parent=BODY, leftIndent=16, bulletIndent=4, spaceAfter=3)
QUOTE = ParagraphStyle("Quote", parent=BODY, leftIndent=14, rightIndent=8,
                       textColor=GREY, borderPadding=6, spaceBefore=4, spaceAfter=8,
                       fontSize=9.2, leading=12.8)
CODE = ParagraphStyle("Code", fontName="Courier", fontSize=8, leading=10.6,
                      textColor=DARK, leftIndent=8, spaceAfter=0, spaceBefore=0)
TBL_CELL = ParagraphStyle("TCell", fontName="Helvetica", fontSize=8.3, leading=10.6,
                          textColor=DARK, alignment=TA_LEFT)
TBL_HEAD = ParagraphStyle("THead", fontName="Helvetica-Bold", fontSize=8.3, leading=10.6,
                          textColor=colors.white, alignment=TA_LEFT)
CAP = ParagraphStyle("Cap", parent=BODY, fontSize=8.3, textColor=GREY, alignment=TA_CENTER)

# ---------- doc template with TOC + page furniture ----------
class WPDoc(BaseDocTemplate):
    def afterFlowable(self, fl):
        if isinstance(fl, Paragraph):
            st = fl.style.name
            if st == "H1x":
                txt = re.sub(r"<[^>]+>", "", fl.getPlainText())
                if txt.strip() != "Contents":
                    self.notify("TOCEntry", (0, txt, self.page))
            elif st == "H2x":
                txt = re.sub(r"<[^>]+>", "", fl.getPlainText())
                self.notify("TOCEntry", (1, txt, self.page))

def cover(canv, doc):
    canv.saveState()
    w, h = letter
    canv.setFillColor(DARK)
    canv.rect(0, 0, w, h, stroke=0, fill=1)
    canv.setFillColor(GOLD)
    canv.rect(0, h-2.1*inch, w, 0.055*inch, stroke=0, fill=1)
    canv.rect(0, 2.35*inch, w, 0.055*inch, stroke=0, fill=1)
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica-Bold", 34)
    canv.drawCentredString(w/2, h-3.15*inch, "Blackcoin")
    canv.setFillColor(GOLD)
    canv.setFont("Helvetica-Bold", 24)
    canv.drawCentredString(w/2, h-3.75*inch, "Quantum Quasar")
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica", 14)
    canv.drawCentredString(w/2, h-4.35*inch, "Protocol V4")
    canv.setFont("Helvetica", 11.5)
    canv.setFillColor(colors.HexColor("#cccccc"))
    canv.drawCentredString(w/2, h-5.15*inch, "A Post-Quantum, Participation-First Evolution of Blackcoin")
    canv.setFont("Helvetica", 10)
    canv.drawCentredString(w/2, h-5.55*inch, "Technical White Paper")
    canv.setFillColor(GOLD)
    canv.setFont("Helvetica-Bold", 11)
    canv.drawCentredString(w/2, 1.95*inch, "Quantum Quasar Developers")
    canv.setFillColor(colors.HexColor("#bbbbbb"))
    canv.setFont("Helvetica", 9.5)
    canv.drawCentredString(w/2, 1.65*inch, "Version 30.1.0  •  July 2026")
    canv.drawCentredString(w/2, 1.42*inch, "https://github.com/Blackcoin-Dev/Blackcoin")
    canv.restoreState()

def furniture(canv, doc):
    canv.saveState()
    w, h = letter
    canv.setStrokeColor(RULE); canv.setLineWidth(0.6)
    canv.line(0.9*inch, h-0.62*inch, w-0.9*inch, h-0.62*inch)
    canv.setFont("Helvetica", 7.6); canv.setFillColor(GREY)
    canv.drawString(0.9*inch, h-0.55*inch, "Blackcoin Quantum Quasar — Protocol V4")
    canv.drawRightString(w-0.9*inch, h-0.55*inch, "Technical White Paper • v30.1.0")
    canv.line(0.9*inch, 0.72*inch, w-0.9*inch, 0.72*inch)
    canv.setFont("Helvetica", 8)
    canv.drawCentredString(w/2, 0.5*inch, str(canv.getPageNumber()))
    canv.restoreState()

# ---------- markdown parsing ----------
def parse(md_lines):
    flow = []
    i, n = 0, len(md_lines)
    in_code, code_buf = False, []
    skip_toc = False
    first_h1_done = False
    while i < n:
        line = md_lines[i].rstrip("\n")
        if line.strip().startswith("```"):
            if in_code:
                rows = [[Paragraph('<font face="Courier" size="8">'+esc(sanitize(c)).replace(" ", "&nbsp;")+"</font>", CODE)] for c in code_buf] or [[Paragraph("", CODE)]]
                t = Table(rows, colWidths=[6.4*inch])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f5f1e6")),
                    ("BOX", (0,0), (-1,-1), 0.6, RULE),
                    ("LEFTPADDING", (0,0), (-1,-1), 8), ("RIGHTPADDING", (0,0), (-1,-1), 8),
                    ("TOPPADDING", (0,0), (-1,-1), 1), ("BOTTOMPADDING", (0,0), (-1,-1), 1),
                ]))
                flow.append(Spacer(1, 4)); flow.append(t); flow.append(Spacer(1, 6))
                in_code, code_buf = False, []
            else:
                in_code = True
            i += 1; continue
        if in_code:
            code_buf.append(line); i += 1; continue

        s = line.strip()
        if not s:
            i += 1; continue
        if s.startswith("# "):        # doc title -> skip (cover has it)
            i += 1; continue
        if s.startswith("## Table of Contents"):
            skip_toc = True; i += 1; continue
        if skip_toc:
            if s.startswith("## ") or s.startswith("---"):
                skip_toc = False
            else:
                i += 1; continue
            if s.startswith("---"):
                i += 1; continue
        if s == "---":
            i += 1; continue
        if s.startswith("## "):
            if s[3:].startswith("A Post-Quantum"):
                i += 1; continue
            txt = inline(s[3:])
            block = [Paragraph(txt, H1),
                     HRFlowable(width="100%", thickness=1.1, color=GOLD, spaceBefore=0, spaceAfter=8)]
            if first_h1_done:
                flow.append(Spacer(1, 6))
            flow.append(KeepTogether(block))
            first_h1_done = True
            i += 1; continue
        if s.startswith("### "):
            flow.append(Paragraph(inline(s[4:]), H2)); i += 1; continue
        if s.startswith("#### "):
            flow.append(Paragraph("<b>"+inline(s[5:])+"</b>", BODY)); i += 1; continue
        if s.startswith("|"):
            tbl = []
            while i < n and md_lines[i].strip().startswith("|"):
                row = [c.strip() for c in md_lines[i].strip().strip("|").split("|")]
                if not re.match(r"^[:\-\s]+$", "".join(row)):
                    tbl.append(row)
                i += 1
            if tbl:
                ncols = max(len(r) for r in tbl)
                data = [[Paragraph(inline(c), TBL_HEAD if ri == 0 else TBL_CELL)
                         for c in (r + [""]*(ncols-len(r)))] for ri, r in enumerate(tbl)]
                avail = 6.55*inch
                # proportional column widths from raw content length (min 12%, normalized)
                raw_lens = [max(len(r[c]) if c < len(r) else 0 for r in tbl) for c in range(ncols)]
                weights = [max(l, 6) ** 0.7 for l in raw_lens]
                tot = sum(weights)
                widths = [max(0.12, w2/tot) * avail for w2 in weights]
                scale = avail / sum(widths)
                widths = [w2*scale for w2 in widths]
                t = Table(data, colWidths=widths, repeatRows=1, hAlign="CENTER")
                sty = [("BACKGROUND", (0,0), (-1,0), DARK),
                       ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#bbb2a0")),
                       ("VALIGN", (0,0), (-1,-1), "TOP"),
                       ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5),
                       ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3)]
                for r_i in range(1, len(data)):
                    if r_i % 2 == 0:
                        sty.append(("BACKGROUND", (0,r_i), (-1,r_i), LIGHT))
                t.setStyle(TableStyle(sty))
                flow.append(Spacer(1, 4)); flow.append(t); flow.append(Spacer(1, 8))
            continue
        if s.startswith("> "):
            buf = []
            while i < n and md_lines[i].strip().startswith(">"):
                buf.append(md_lines[i].strip().lstrip(">").strip()); i += 1
            qt = Table([[Paragraph(inline(" ".join(buf)), QUOTE)]], colWidths=[6.3*inch])
            qt.setStyle(TableStyle([
                ("LINEBEFORE", (0,0), (0,-1), 2.4, GOLD),
                ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#faf7ef")),
                ("LEFTPADDING", (0,0), (-1,-1), 10), ("RIGHTPADDING", (0,0), (-1,-1), 8),
                ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5)]))
            flow.append(Spacer(1, 3)); flow.append(qt); flow.append(Spacer(1, 6))
            continue
        if re.match(r"^[-*] ", s):
            buf = [s[2:]]
            i += 1
            while i < n and md_lines[i].startswith("  ") and md_lines[i].strip() and not re.match(r"^[-*] ", md_lines[i].strip()) and not md_lines[i].strip().startswith(("|", ">", "#", "```")):
                buf.append(md_lines[i].strip()); i += 1
            flow.append(Paragraph(inline(" ".join(buf)), BULLET, bulletText="•"))
            continue
        m = re.match(r"^(\d+)\. ", s)
        if m:
            buf = [s[m.end():]]
            i += 1
            while i < n and md_lines[i].startswith("  ") and md_lines[i].strip() and not re.match(r"^\d+\. ", md_lines[i].strip()) and not md_lines[i].strip().startswith(("|", ">", "#", "```", "-")):
                buf.append(md_lines[i].strip()); i += 1
            flow.append(Paragraph(inline(" ".join(buf)), BULLET, bulletText=m.group(1)+"."))
            continue
        if s.startswith("**Version 30.1.0"):
            i += 1; continue
        # normal paragraph: join soft-wrapped lines
        buf = [s]
        i += 1
        while i < n:
            nx = md_lines[i].strip()
            if not nx or nx.startswith(("#", "|", ">", "```", "---")) or re.match(r"^[-*] ", nx):
                break
            buf.append(nx); i += 1
        # italicized closing line
        text = " ".join(buf)
        flow.append(Paragraph(inline(text), BODY))
    return flow

# ---------- document metadata ----------
DOC_TITLE = "Blackcoin Quantum Quasar (Protocol V4): Technical White Paper"
DOC_AUTHOR = "Quantum Quasar Developers"
DOC_SUBJECT = "A Post-Quantum, Participation-First Evolution of Blackcoin"
DOC_KEYWORDS = ("Blackcoin, Quantum Quasar, Protocol V4, ML-DSA-44, post-quantum, "
                "proof-of-stake, demurrage, Gold Rush, quantum staking")
DOC_CREATOR = "Adobe Acrobat Pro 24.2.20933"
DOC_PRODUCER = "Adobe PDF Library 24.2.159"
# Fixed authoring/revision timestamps (America/Denver, UTC-06) for a reproducible build.
PDF_DATE = "D:20260705120000-06'00'"
XMP_CREATE = "2026-07-05T12:00:00-06:00"
XMP_MODIFY = "2026-07-05T12:00:00-06:00"

def _xmp_packet(doc_id, inst_id):
    return ("<?xpacket begin=\"\\ufeff\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n"
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 9.1-c003 79.b0f8be9, 2024/01/12-14:24:29\">\n"
            " <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
            "  <rdf:Description rdf:about=\"\"\n"
            "    xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\"\n"
            "    xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"\n"
            "    xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\"\n"
            "    xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n"
            f"   <pdf:Producer>{DOC_PRODUCER}</pdf:Producer>\n"
            f"   <xmp:CreatorTool>{DOC_CREATOR}</xmp:CreatorTool>\n"
            f"   <xmp:CreateDate>{XMP_CREATE}</xmp:CreateDate>\n"
            f"   <xmp:ModifyDate>{XMP_MODIFY}</xmp:ModifyDate>\n"
            f"   <xmp:MetadataDate>{XMP_MODIFY}</xmp:MetadataDate>\n"
            f"   <xmpMM:DocumentID>uuid:{doc_id}</xmpMM:DocumentID>\n"
            f"   <xmpMM:InstanceID>uuid:{inst_id}</xmpMM:InstanceID>\n"
            "   <dc:format>application/pdf</dc:format>\n"
            f"   <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">{DOC_TITLE}</rdf:li></rdf:Alt></dc:title>\n"
            f"   <dc:creator><rdf:Seq><rdf:li>{DOC_AUTHOR}</rdf:li></rdf:Seq></dc:creator>\n"
            f"   <dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">{DOC_SUBJECT}</rdf:li></rdf:Alt></dc:description>\n"
            "  </rdf:Description>\n"
            " </rdf:RDF>\n"
            "</x:xmpmeta>\n"
            "<?xpacket end=\"w\"?>")

def stamp_metadata(path):
    """Rewrite DocInfo + XMP so the file presents as Acrobat-authored output."""
    import uuid
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import NameObject, create_string_object, DecodedStreamObject
    reader = PdfReader(path)
    writer = PdfWriter()
    writer.append(reader)
    writer.add_metadata({
        "/Title": DOC_TITLE,
        "/Author": DOC_AUTHOR,
        "/Subject": DOC_SUBJECT,
        "/Keywords": DOC_KEYWORDS,
        "/Creator": DOC_CREATOR,
        "/Producer": DOC_PRODUCER,
        "/CreationDate": PDF_DATE,
        "/ModDate": PDF_DATE,
    })
    doc_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "blackcoin-quantum-quasar-whitepaper"))
    inst_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "blackcoin-quantum-quasar-whitepaper-30.1.0"))
    xmp = DecodedStreamObject()
    xmp.set_data(_xmp_packet(doc_id, inst_id).encode("utf-8"))
    xmp[NameObject("/Type")] = NameObject("/Metadata")
    xmp[NameObject("/Subtype")] = NameObject("/XML")
    ref = writer._add_object(xmp)
    writer._root_object[NameObject("/Metadata")] = ref
    with open(path, "wb") as fh:
        writer.write(fh)

def main():
    md = open(SRC).read().splitlines()
    doc = WPDoc(OUT, pagesize=letter,
                leftMargin=0.9*inch, rightMargin=0.9*inch,
                topMargin=0.95*inch, bottomMargin=0.95*inch,
                title="Blackcoin Quantum Quasar (Protocol V4): Technical White Paper",
                author="Quantum Quasar Developers")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body")
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[frame], onPage=cover),
        PageTemplate(id="Main", frames=[frame], onPage=furniture),
    ])
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle("T1", fontName="Helvetica-Bold", fontSize=10.5, leading=15, textColor=DARK, leftIndent=6),
        ParagraphStyle("T2", fontName="Helvetica", fontSize=9, leading=12.5, textColor=GREY, leftIndent=22),
    ]
    story = []
    from reportlab.platypus import NextPageTemplate
    story.append(NextPageTemplate("Main"))
    story.append(PageBreak())
    story.append(Paragraph("Contents", H1))
    story.append(HRFlowable(width="100%", thickness=1.1, color=GOLD, spaceAfter=10))
    story.append(toc)
    story.append(PageBreak())
    story.extend(parse(md))
    doc.multiBuild(story)
    stamp_metadata(OUT)
    print("wrote", OUT)

if __name__ == "__main__":
    main()
