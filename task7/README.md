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

Use APKtool to view the Android Manifest

Use JADX to decompile the Kotlin code into Java

Install Android Studio to run an Android open-source emulator with root

Use adb root shell to explore the app files on the emulator

Use adb logcat to view log files

Upload a test file to MM and watch the file appear in the app

Notice that file downloader has no checks against path traversal

Wonder how to create a file name with slashes in it that can live on my computer and be submitted to the challenge website

Try a zipslip attack and find that the zip implementation has a canonical path check

More testing to find that creating a file in a folder passes

More testing to realize that `...zip` can exploit path traversal before canonical check

Know from staring at the code that `zippier.json` is a config for dynamic class loading for given list of compression formats downloaded from badguy server to `formats/`

Watch logs to see code in action on `test.7z` and see that the app tries to download the format

Inspect code to find dynamic class name should be `net.axolotl.zippier.ZipFormat_7z.jar`

Think about replacing `zippier.json`: no, because it is a static app asset

Think about standing up a server to connect to badguy address: no, because how will we poison his DNS

Decide to try to create a malicious class with the same name

Package the file in the zip folder in `formats/`

See in the logs that the app does attempt to dynamically load the uploaded file

Copy Java code to recreate the class

Compile using javac

Convert to DEX using j8

Iterate until logs indicate a successful load

Submit and find that this satisfies the task!

### Notes

Tried a zip bomb, small at first to test the servers and then large to try to takeout the device. This was not the answer.

Open-ended prompt led to consideration of what constituted "exploits the device". We could delete the Mattermost database in task 6 as that was not a mod or admin restricted function. Then, use our malicious file to delete the app database and get rid of all history, assuming no other backups. Or, could change everyone's backup settings so they would in fact, miss message updates (see task 6 forum posts). Could potentially stay embedded and watch for malicious activity to see if admin is part of a larger network of players.


## Result

<div align="center" 
     style="background-color: #dff0d8;
            border-color: #d6e9c6;
            color: #3c763d;
            padding: 15px;
            border-radius: 4px;
            font-family: Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.42857143;">
Task Completed at Sat, 10 Jan 2026 16:47:36 GMT:

---

With full access to the device we now have ull visibility into this threat actor's entire infrastructure and capabilities. The US Military has everything they need to take decisive action against this threat. The security configurations of DoD networks worldwide are updated to guard against the exploited vulnerabilities, the adversary's infrastructure is destroyed, and the entire team of threat actors are identified. DIRNSA briefed the president on your work and how you enabled the mitigation of this threat. Great job!

Through dedication, skill, and teamwork; NSA guaranteed the protection of the US Militaries advantage in the cyber domian.

---

You may join a <b>special 
<span style="padding: 2px 4px;
            font-size: 90%;
            color: #c7254e;
            background-color: #f9f2f4;
            border-radius: 4px;
            font-family: Menlo, Monaco, Consolas, Courier New, monospace;">
            #2025-solvers</span>
Discord channel</b>. Be aware that other players will see your membership. Paste the following into the 
<span style="padding: 2px 4px;
            font-size: 90%;
            color: #c7254e;
            background-color: #f9f2f4;
            border-radius: 4px;
            font-family: Menlo, Monaco, Consolas, Courier New, monospace;">
            #bot-commands</span> 
channel:
<span style="padding: 2px 4px;
            font-size: 90%;
            color: #c7254e;
            background-color: #f9f2f4;
            border-radius: 4px;
            font-family: Menlo, Monaco, Consolas, Courier New, monospace;">
            /solver token:REDACTED</span> 


</div>

---

<div align="center">

![badge7.png](badge7.png)

</div>