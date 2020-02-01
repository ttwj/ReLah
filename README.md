ReLah
=====

Implementation of DBS PayLah!'s transaction features in Python (still works as of December 2019). This was originally developed back in 2016 when the NETS QR/PayNow API was not ready. 

It may still be useful if one would like to initiate peer to peer transactions or view transaction history programatically.


DISCLAIMER
========

This repository is for research purposes only, the use of this code is your responsibility.

I take NO responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files available in this repository, you understand that you are AGREEING TO USE AT YOUR OWN RISK. Once again, ALL files available here are for EDUCATION and/or RESEARCH purposes ONLY.

This project is not certified by DBS to perform any transactions. You acknowledge that the intellectual property rights in or to the DBS PayLah! Application are owned by DBS.

I want to accept DBS PayLah! payments! What should I do?
======
You should NOT be using this if you want to accept PayLah! payments, this is purely for educational purposes to learn more about how banking transactions work and the various security measures implemented to inhibit MITM spoofing.

If you wanted to accept DBS PayLah! payments, it would be much faster if you use one of the following acquirers (ordered in technical & commercial complexity)
- NETS: Dynamic QR, Verifone/Ingenico/Castles Terminals, Electronic Cash Register (ECR) via RS232 or MDB: https://www.nets.com.sg
- eNETS: Dynamic QR, HTTPS API: https://developers.nets.com.sg
- DBS Host to Host: Express Checkout or App-to-App DeepLink (contact the Relationship Manager for your DBS Corporate account)

NETS is jointly owned by DBS, UOB & OCBC, and can support the iBanking & e-wallet applications of these banks as well.

You can also drop us a note at hello@beepbeep.tech, will be happy to render assistance within our capacity :-)

How it works
=====
ReLah comprises of a Theos (Cydia Substrate) module which enables one to extract the DeviceID & Encrypted Password on a jailbroken iPhone/iPad, which you then feed into the Python script

- Theos: https://github.com/theos/theos
- Cydia Substrate: http://www.cydiasubstrate.com/
