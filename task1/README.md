# Task 1 - Getting Started - (Forensics)

You arrive on site and immediately get to work. The DAFIN-SOC team quickly briefs you on the situation. They have noticed numerous anomalous behaviors, such as; tools randomly failing tests and anti-virus flagging on seemingly clean workstations. They have narrowed in on one machine they would like NSA to thoroughly evaluate.

They have provided a zipped EXT2 image from this development machine. Help DAFIN-SOC perform a forensic analysis on this - looking for any suspicious artifacts.


## Downloads

  - [zipped EXT2 image (image.ext2.zip)](Downloads/image.ext2.zip)

## Prompt

    Provide the SHA-1 hash of the suspicious artifact.

## Solution

To examine the provided filesystem image, it is first necessary to mount the image. Throughout these writeups, I am using Windows 11 EDU as my primary OS and then utilizing WSL, Docker, and VMs as necessary to complete the tasks.

To view the filesystem image in WSL Ubuntu, mount it as a [loop device](https://en.wikipedia.org/wiki/Loop_device). I run Docker Desktop, which was blocking `loop0` and `loop1`, but `loop2` was available. Run the following commands from the `task1/` folder in WSL Ubuntu:

```
sudo losetup /dev/loop2 image.ext2
sudo mount /dev/loop2 ~/cbc2025/task1
```

In another WSL Ubuntu shell, changing directories to `~/cbc2025/task1` now reveals the development machine filesystem. Running the following command recursively outputs details of the filesystem files and folders to a text file that is a bit easier to peruse:

```
~/cbc2025$ sudo ls -laLR ~/cbc2025/task1/ > task1_files.txt
```

Scrolling through the folder and file listing, this sequence in `/etc/periodic/` stands out because the only file is a strangely named `mceruozsvw` that apparently runs once per day:

```sh
/home/naww/cbc2025/task1/etc/periodic:
total 28
drwxr-xr-x.  7 root root 4096 Dec 31  1969 .
drwxr-xr-x. 22 root root 4096 Dec 31  1969 ..
drwxr-xr-x.  2 root root 4096 Dec 31  1969 15min
drwxr-xr-x.  2 root root 4096 Dec 31  1969 daily
drwxr-xr-x.  2 root root 4096 Dec 31  1969 hourly
drwxr-xr-x.  2 root root 4096 Dec 31  1969 monthly
drwxr-xr-x.  2 root root 4096 Dec 31  1969 weekly

/home/naww/cbc2025/task1/etc/periodic/15min:
total 8
drwxr-xr-x. 2 root root 4096 Dec 31  1969 .
drwxr-xr-x. 7 root root 4096 Dec 31  1969 ..

/home/naww/cbc2025/task1/etc/periodic/daily:
total 12
drwxr-xr-x. 2 root root 4096 Dec 31  1969 .
drwxr-xr-x. 7 root root 4096 Dec 31  1969 ..
-rw-r--r--. 1 root root   59 Dec 31  1969 mceruozsvw

/home/naww/cbc2025/task1/etc/periodic/hourly:
total 8
drwxr-xr-x. 2 root root 4096 Dec 31  1969 .
drwxr-xr-x. 7 root root 4096 Dec 31  1969 ..

/home/naww/cbc2025/task1/etc/periodic/monthly:
total 8
drwxr-xr-x. 2 root root 4096 Dec 31  1969 .
drwxr-xr-x. 7 root root 4096 Dec 31  1969 ..

/home/naww/cbc2025/task1/etc/periodic/weekly:
total 8
drwxr-xr-x. 2 root root 4096 Dec 31  1969 .
drwxr-xr-x. 7 root root 4096 Dec 31  1969 ..
```

Let's look at the contents of this file:

`sudo cat ~/cbc2025/task1/etc/periodic/daily/mceruozsvw`
```sh
U=/a/f1b6f590ad57e57904e028ccb6bf7b25/xxyz
P=20
A=/app/www
```

It is unclear exactly what this means, but it seems like potentially a C2 server connection configuration with a user, password/period, and app URL. Let's get the SHA-1 hash and see if this is the indicated suspicious artifact:

`sha1sum ~/cbc2025/task1/etc/periodic/daily/mceruozsvw`
```sh
264352e3271d80e7ea777362353222201f614a55  /home/naww/cbc2025/task1/etc/periodic/daily/mceruozsvw
```

The correct submission is `264352e3271d80e7ea777362353222201f614a55`!

To cleanup the filesystem mount:
```
sudo umount ~/cbc2025/task1
sudo losetup -d /dev/loop2
```


### Notes

After further examination during this writeup, it is clear that the filesystem image is for a device running Apline Linux with MUSL, indicating that this machine is likely resource constrained and/or narrowly focused on completing a specific task. The wording of "development machine" in the task prompt threw me off of this important detail.


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
Task Completed at Thu, 25 Sep 2025 00:50:39 GMT: 

---

Great job finding that artifact! Let's report what we found to DAFIN-SOC leadership.

</div>

---

<div align="center">

![badge1.png](badge1.png)

</div>