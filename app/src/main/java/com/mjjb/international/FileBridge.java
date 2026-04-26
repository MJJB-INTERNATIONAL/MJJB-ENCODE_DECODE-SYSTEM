package com.mjjb.international;

import android.content.Context;
import android.webkit.JavascriptInterface;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;

public class FileBridge {

    Context context;

    public FileBridge(Context ctx) {
        this.context = ctx;
    }

    private String root() {
        return "/storage/emulated/0/";
    }

    @JavascriptInterface
    public String readFile(String path) {
        try {
            File f = new File(root() + path);
            return new String(Files.readAllBytes(f.toPath()));
        } catch (Exception e) {
            return "ERROR";
        }
    }

    @JavascriptInterface
    public String writeFile(String path, String data) {
        try {
            File f = new File(root() + path);
            f.getParentFile().mkdirs();

            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data.getBytes());
            fos.close();

            return "OK";
        } catch (Exception e) {
            return "ERROR";
        }
    }

    @JavascriptInterface
    public String deleteFile(String path) {
        try {
            File f = new File(root() + path);
            return f.delete() ? "DELETED" : "FAILED";
        } catch (Exception e) {
            return "ERROR";
        }
    }

    @JavascriptInterface
    public String listDir(String path) {
        try {
            File f = new File(root() + path);
            File[] list = f.listFiles();

            StringBuilder sb = new StringBuilder();
            if (list != null) {
                for (File file : list) {
                    sb.append(file.getName()).append("\n");
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return "ERROR";
        }
    }
}
