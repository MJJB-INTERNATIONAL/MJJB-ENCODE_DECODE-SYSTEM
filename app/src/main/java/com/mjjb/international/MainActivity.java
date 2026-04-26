package com.mjjb.international;
import android.content.Intent;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {

    WebView webView;

@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    // Request MANAGE_EXTERNAL_STORAGE (Android 11+)
    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
        if (!android.os.Environment.isExternalStorageManager()) {
            Intent intent = new Intent(
                android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION
            );
            startActivity(intent);
        }
    }

    String url = getIntent().getStringExtra("url");
    if (url == null || url.isEmpty()) { finish(); return; }

    webView = findViewById(R.id.webView);
    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDomStorageEnabled(true);
    webView.setWebViewClient(new WebViewClient());
    webView.addJavascriptInterface(new FileBridge(this), "Android");
    webView.loadUrl(url);
}


// Back button = exit app
@Override
public void onBackPressed() {
    finishAffinity(); // kills entire app
}
}
