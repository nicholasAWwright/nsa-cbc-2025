# Task 5 - Putting it all together - (Cryptanalysis)

NSA analysts confirm that there is solid evidence that this binary was at least part of what had been installed on the military development network. Unfortunately, we do not yet have enough information to update NSA senior leadership on this threat. We need to move forward with this investigation!

The team is stumped - they need to identify something about who was controlling this malware. They look to you. "Do you have any ideas?"

## Prompt

    Submit the full URL to the adversary's server

## Solution

No files given, open-ended

Luckily, I have a good hunch from staring at the PCAP and finding 0xdec0dec0ffee

Look through the dropped binary to find RSA handshake to double DES encryption

Realize what the first plaintext + padding must be

Realize that all subsequent messages have the same ending padding - this must be single DES on full 16bytes of padding

DES must be in CBC? mode for this to happen, thus there is no IV

Code bit shifts key from 128-bits down to 26-bits. Easily crackable on a desktop PC in a few minutes

Write cracking code for a Meet-in-the-Middle attack

Recover 2 keys

Decrypt PCAP messages to find the answer

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
Task Completed at Tue, 30 Dec 2025 05:33:21 GMT: 

---

Brilliant! The malware communications lead us right to the adversary's Mattermost server!

</div>

---

![badge5.png](badge5.png)