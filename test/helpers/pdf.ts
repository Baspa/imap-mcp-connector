/** Builds a minimal valid one-page PDF containing `text` (ASCII only). */
export function tinyPdf(text: string): Buffer {
  return tinyPdfPages([text]);
}

/** Builds a minimal valid PDF with one page per entry (ASCII only). A newline in an entry starts a new line. */
export function tinyPdfPages(pages: string[]): Buffer {
  const pageCount = pages.length;
  // Object layout: 1 catalog, 2 page tree, 3 font, then a page and a content stream per entry.
  const fontId = 3;
  const pageId = (i: number) => fontId + 1 + i * 2;
  const contentId = (i: number) => pageId(i) + 1;

  const objects: string[] = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    `<< /Type /Pages /Kids [${pages.map((_, i) => `${pageId(i)} 0 R`).join(' ')}] /Count ${pageCount} >>`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  pages.forEach((text, i) => {
    const lines = text.split('\n');
    const stream = `BT /F1 18 Tf 20 100 Td 20 TL ${lines.map((l) => `(${l}) Tj T*`).join(' ')} ET`;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents ${contentId(i)} 0 R /Resources << /Font << /F1 ${fontId} 0 R >> >> >>`,
      `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    );
  });

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(Buffer.byteLength(pdf, 'latin1'));
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = Buffer.byteLength(pdf, 'latin1');
  pdf +=
    `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n` +
    offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('') +
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, 'latin1');
}
