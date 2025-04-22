A script that simulates encryption and decryption of files (like a ransomware) that takes into consideration possible encryption corruptions during the process of said encryption/decryption. 
It uses a simple file handling technique to ensure that a file will always be recoverable regardless if it is corrupted while in the process of encryption/decryption. (creating copies before any operation starts, deleting them if operation is successful, using them as recovery if operation deemed unsuccessful).

The scripts were implemented with the help of the DeepSeek tool.
100 tests were ran on 103 txt files (3 of the files having an abnormal size of 1.1GB).
Tests were ran on Ubuntu 24.04.2 LTS in a Surface Pro 3, Processor: Intel(R) Core(TM) i7-4650U CPU @ 1.70 GHz, 2 Core(s), 4 Logical Processor(s) with 8GB of RAM

Test results can be found here: https://docs.google.com/spreadsheets/d/1u_rt9VSFpe4kgU2O5EZBsnGz_CW2rBop9KMBn9If6IQ/edit?gid=0#gid=0
(Row 14 has multiple entries with notes attached to them detailing the results and some interpretations)
