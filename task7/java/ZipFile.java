package net.axolotl.zippier;

import java.io.File;

public interface ZipFile {
    ZipFile addFile(File file);

    void write();
}