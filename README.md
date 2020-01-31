ReLah
=====

Implementation of DBS PayLah!'s transaction features in Python (still works as of December 2019). This was originally developed back in 2016 when the NETS QR/PayNow API was not ready. 

It may still be useful if one would like to initiate peer to peer transactions or view transaction history programatically.


DISCLAIMER
========

This repository is for research purposes only, the use of this code is your responsibility.

I take NO responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files available in this repository, you understand that you are AGREEING TO USE AT YOUR OWN RISK. Once again, ALL files available here are for EDUCATION and/or RESEARCH purposes ONLY.

This project is not certified DBS to perform any transactions. You acknowledge that the intellectual property rights in or to the DBS PayLah! Application are owned by DBS.

I want to accept DBS PayLah! payments! What should I do?
======
You should NOT be using this if you want to accept PayLah! payments, this is purely for educational purposes to learn more about how CEPAS debit transactions work


If you wanted to accept PayLah! Payments, it would be faster if you find an approved acquirer.
- NETS: Verifone/Ingenico Terminals, ECR RS232 (https://www.nets.com.sg/)
- eNETS: Dynamic QR, HTTPS API

How it works
=====
ReLah comprises of a theos module which enables one to extract the DeviceID & Encrypted Password, which you then feed into the Python script

