package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.print.PageRange;
import android.print.PrintAttributes;
import android.print.PrintDocumentAdapter;
import android.print.PrintDocumentInfo;
import android.print.pdf.PrintedPdfDocument;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Text-only Android print/PDF output; no Internet access or additional storage permission. */
final class RootSessionPrintAdapter extends PrintDocumentAdapter {
    private final Context context;
    private final String report;
    private final String name;
    private final Paint ink = new Paint(Paint.ANTI_ALIAS_FLAG);
    private PrintAttributes attributes;
    private List<String> wrappedLines = new ArrayList<>();
    private int linesPerPage = 1;
    private int pageCount = 1;

    RootSessionPrintAdapter(Context context, String name, String report) {
        this.context = context.getApplicationContext();
        this.name = name;
        this.report = report;
        ink.setColor(0xff151515);
        ink.setTextSize(10f);
        ink.setTypeface(android.graphics.Typeface.MONOSPACE);
    }

    @Override public void onLayout(PrintAttributes oldAttributes, PrintAttributes newAttributes,
                                   CancellationSignal cancellation, LayoutResultCallback callback,
                                   Bundle extras) {
        if (cancellation.isCanceled()) { callback.onLayoutCancelled(); return; }
        attributes = newAttributes;
        try (PrintedPdfDocument preview = new PrintedPdfDocument(context, newAttributes)) {
            Rect bounds = preview.getPageContentRect();
            wrappedLines = wrapLines(report, Math.max(1, bounds.width()));
            linesPerPage = Math.max(1, (bounds.height() - 12) / 14);
            pageCount = Math.max(1, (wrappedLines.size() + linesPerPage - 1) / linesPerPage);
        } catch (RuntimeException error) {
            callback.onLayoutFailed("Could not prepare report pages.");
            return;
        }
        callback.onLayoutFinished(new PrintDocumentInfo.Builder(name + ".pdf")
                .setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT)
                .setPageCount(pageCount)
                .build(), true);
    }

    @Override public void onWrite(PageRange[] ranges, ParcelFileDescriptor destination,
                                  CancellationSignal cancellation, WriteResultCallback callback) {
        if (attributes == null) { callback.onWriteFailed("Print layout not available."); return; }
        if (cancellation.isCanceled()) { callback.onWriteCancelled(); return; }
        boolean[] selected = new boolean[pageCount];
        for (PageRange range : ranges) {
            int from = Math.max(0, range.getStart());
            int to = Math.min(pageCount - 1, range.getEnd());
            for (int i = from; i <= to; i++) selected[i] = true;
        }
        PrintedPdfDocument pdf = new PrintedPdfDocument(context, attributes);
        try {
            for (int i = 0; i < pageCount; i++) {
                if (!selected[i]) continue;
                if (cancellation.isCanceled()) { callback.onWriteCancelled(); return; }
                android.graphics.pdf.PdfDocument.Page page = pdf.startPage(i + 1);
                Canvas canvas = page.getCanvas();
                Rect content = page.getInfo().getContentRect();
                float baseline = content.top - ink.ascent() + 3f;
                int end = Math.min(wrappedLines.size(), (i + 1) * linesPerPage);
                for (int line = i * linesPerPage; line < end; line++) {
                    canvas.drawText(wrappedLines.get(line), content.left, baseline, ink);
                    baseline += 14f;
                }
                pdf.finishPage(page);
            }
            try (FileOutputStream stream = new FileOutputStream(destination.getFileDescriptor())) {
                pdf.writeTo(stream);
            }
        } catch (IOException | RuntimeException error) {
            callback.onWriteFailed("Could not write report to the print destination.");
            return;
        } finally {
            pdf.close();
        }
        if (cancellation.isCanceled()) callback.onWriteCancelled();
        else callback.onWriteFinished(ranges);
    }

    private List<String> wrapLines(String value, int width) {
        List<String> result = new ArrayList<>();
        for (String line : value.split("\\r?\\n", -1)) {
            if (line.isEmpty()) { result.add(""); continue; }
            int offset = 0;
            while (offset < line.length()) {
                int count = ink.breakText(line, offset, line.length(), true, width, null);
                count = Math.max(count, 1);
                int end = Math.min(line.length(), offset + count);
                if (end < line.length()) {
                    int whitespace = line.lastIndexOf(' ', end);
                    if (whitespace > offset + count / 2) end = whitespace + 1;
                }
                result.add(line.substring(offset, end));
                offset = end;
            }
        }
        return result;
    }
}
