package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

import java.util.ArrayList;
import java.util.List;

/**
 * Small, read-only live sample plot. It draws only local WireGuard counter
 * deltas. It does not capture packets or sample other apps' traffic.
 */
final class TunnelTrafficGraphView extends View {
    private static final int DOWNLOAD = 0xffb8d7ff;
    private static final int UPLOAD = 0xfff6a6d7;
    private static final int GRID = 0xff3c3448;

    private final Paint stroke = new Paint(Paint.ANTI_ALIAS_FLAG);
    private List<TunnelTrafficRates.Result> values = new ArrayList<>();

    TunnelTrafficGraphView(Context context) {
        super(context);
        setBackgroundColor(0xff1b1728);
    }

    void setValues(List<TunnelTrafficRates.Result> samples) {
        values = new ArrayList<>(samples);
        invalidate();
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float density = getResources().getDisplayMetrics().density;
        float left = 11 * density;
        float right = getWidth() - 11 * density;
        float top = 14 * density;
        float bottom = getHeight() - 14 * density;
        if (right <= left || bottom <= top) return;
        stroke.setStyle(Paint.Style.STROKE);
        stroke.setStrokeWidth(density);
        stroke.setColor(GRID);
        for (int line = 0; line <= 3; ++line) {
            float y = top + (bottom - top) * line / 3f;
            canvas.drawLine(left, y, right, y, stroke);
        }
        if (values.isEmpty()) return;
        double maximum = 0.2;
        for (TunnelTrafficRates.Result point : values)
            maximum = Math.max(maximum,
                    Math.max(point.downloadMbps, point.uploadMbps));
        drawSeries(canvas, values, true, DOWNLOAD, maximum,
                left, right, top, bottom, density);
        drawSeries(canvas, values, false, UPLOAD, maximum,
                left, right, top, bottom, density);
    }

    private void drawSeries(Canvas canvas, List<TunnelTrafficRates.Result> samples,
                            boolean download, int color, double maximum,
                            float left, float right, float top, float bottom,
                            float density) {
        Path path = new Path();
        float x = 0f;
        float y = 0f;
        int n = samples.size();
        for (int i = 0; i < n; ++i) {
            x = n == 1 ? (left + right) / 2f
                    : left + (right - left) * i / (n - 1f);
            double mbps = download ? samples.get(i).downloadMbps
                    : samples.get(i).uploadMbps;
            y = bottom - (float) (Math.max(0.0, mbps) / maximum)
                    * (bottom - top);
            if (i == 0) path.moveTo(x, y);
            else path.lineTo(x, y);
        }
        stroke.setStyle(Paint.Style.STROKE);
        stroke.setStrokeWidth(2.5f * density);
        stroke.setStrokeJoin(Paint.Join.ROUND);
        stroke.setStrokeCap(Paint.Cap.ROUND);
        stroke.setColor(color);
        if (n > 1) canvas.drawPath(path, stroke);
        stroke.setStyle(Paint.Style.FILL);
        canvas.drawCircle(x, y, 2.8f * density, stroke);
    }
}
