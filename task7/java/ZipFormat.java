package net.axolotl.zippier;

import java.io.File;

public interface ZipFormat {
    String getExtension();

    void uncompress(File file, File file2, ZipFile zipFile);
}