package com.mjjbencodedecode_system;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.webkit.JavascriptInterface;
import android.webkit.MimeTypeMap;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    static { System.loadLibrary("mjjbserver"); }

    // JNI declarations
    public native void nativeStartServer(int port);
    public native void nativeStopServer();

    private WebView webView;
    private ValueCallback<Uri[]> fileChooserCallback;
    private static final int FILE_CHOOSER_REQUEST = 1001;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Start the C++ server in a background thread
        executor.execute(() -> nativeStartServer(5006));

        // Build WebView
        webView = new WebView(this);
        setContentView(webView);

        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setAllowContentAccess(true);
        ws.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        ws.setCacheMode(WebSettings.LOAD_NO_CACHE);
        ws.setMediaPlaybackRequiresUserGesture(false);

        webView.addJavascriptInterface(new MJJBBridge(), "MJJBAndroid");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view,
                                                               WebResourceRequest request) {
                // Block any real network — serve localhost only
                String host = request.getUrl().getHost();
                if (host != null && !host.equals("localhost") && !host.equals("127.0.0.1")) {
                    return new WebResourceResponse("text/plain", "utf-8", null);
                }
                return super.shouldInterceptRequest(view, request);
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView wv,
                                              ValueCallback<Uri[]> filePathCallback,
                                              FileChooserParams params) {
                fileChooserCallback = filePathCallback;
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                startActivityForResult(Intent.createChooser(intent, "Select File"),
                        FILE_CHOOSER_REQUEST);
                return true;
            }
        });

        // Small delay to let the server start
        mainHandler.postDelayed(() ->
            webView.loadUrl("file:///android_asset/index.html"), 600);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == FILE_CHOOSER_REQUEST) {
            if (fileChooserCallback == null) return;
            Uri[] results = null;
            if (res == Activity.RESULT_OK && data != null && data.getData() != null) {
                results = new Uri[]{data.getData()};
            }
            fileChooserCallback.onReceiveValue(results);
            fileChooserCallback = null;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        nativeStopServer();
        executor.shutdown();
        webView.destroy();
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    // ── JavaScript Bridge ────────────────────────────────────────────
    class MJJBBridge {

        /** Read a content:// URI and return base64-encoded bytes to JS */
        @JavascriptInterface
        public String readFileAsBase64(String uriStr) {
            try {
                Uri uri = Uri.parse(uriStr);
                InputStream is = getContentResolver().openInputStream(uri);
                if (is == null) return "";
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[65536];
                int n;
                while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
                is.close();
                return android.util.Base64.encodeToString(baos.toByteArray(),
                        android.util.Base64.NO_WRAP);
            } catch (IOException e) {
                return "";
            }
        }

        /** Get the display name of a content:// URI */
        @JavascriptInterface
        public String getFileName(String uriStr) {
            Uri uri = Uri.parse(uriStr);
            Cursor cursor = getContentResolver().query(uri,
                    new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null);
            if (cursor != null && cursor.moveToFirst()) {
                String name = cursor.getString(0);
                cursor.close();
                return name != null ? name : "file";
            }
            return "file";
        }

        /** Save bytes (base64) to Downloads and return the saved path */
        @JavascriptInterface
        public String saveFile(String base64Data, String filename) {
            try {
                byte[] data = android.util.Base64.decode(base64Data, android.util.Base64.NO_WRAP);
                File downloads = android.os.Environment.getExternalStoragePublicDirectory(
                        android.os.Environment.DIRECTORY_DOWNLOADS);
                downloads.mkdirs();
                File out = new File(downloads, filename);
                FileOutputStream fos = new FileOutputStream(out);
                fos.write(data);
                fos.close();
                return out.getAbsolutePath();
            } catch (IOException e) {
                return "";
            }
        }
    }
}