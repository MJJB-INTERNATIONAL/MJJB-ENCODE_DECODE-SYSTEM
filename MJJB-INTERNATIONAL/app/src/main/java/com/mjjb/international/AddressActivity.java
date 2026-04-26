package com.mjjb.international;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.app.Activity;

public class AddressActivity extends Activity {

    public static String SERVER_URL;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_address);

        EditText input = findViewById(R.id.urlInput);
        Button btn = findViewById(R.id.connectBtn);

        btn.setOnClickListener(v -> {
            SERVER_URL = input.getText().toString().trim();

            Intent i = new Intent(AddressActivity.this, MainActivity.class);
            i.putExtra("url", SERVER_URL);
            startActivity(i);

            finish(); // ALWAYS FORCE RELOAD ON NEXT LAUNCH
        });
    }
}