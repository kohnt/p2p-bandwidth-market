package com.example.p2pdata.ui;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.Button;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.example.p2pdata.R;

public class RoleSelectActivity extends AppCompatActivity {
    private static final int REQ_LOCATION = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_role_select);

        Button providerBtn = findViewById(R.id.btn_provider);
        Button requesterBtn = findViewById(R.id.btn_requester);

        providerBtn.setOnClickListener(v -> {
            ensurePermissions(() -> startActivity(new Intent(this, ProviderActivity.class)));
        });
        requesterBtn.setOnClickListener(v -> {
            ensurePermissions(() -> startActivity(new Intent(this, RequesterActivity.class)));
        });
    }

    private void ensurePermissions(Runnable onGranted) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            if (ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.ACCESS_FINE_LOCATION)) {
                new AlertDialog.Builder(this)
                        .setTitle(R.string.permission_title)
                        .setMessage(R.string.permission_rationale)
                        .setPositiveButton(android.R.string.ok, (d, w) -> ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, REQ_LOCATION))
                        .setNegativeButton(android.R.string.cancel, null)
                        .show();
            } else {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, REQ_LOCATION);
            }
        } else {
            onGranted.run();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
}
