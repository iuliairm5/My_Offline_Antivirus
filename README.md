# My_Offline_Antivirus

-	a Java solution that uses Java Cryptographic Architecture classes to verify the integrity of the files on a given folder/drive;
-	the solution has 2 ways of running
                •	Status update: computes and stores the HashMAC of all the files of a received path;
                •	Integrity check: verifies if any of the monitored files has been changed since the last status update;


The solution will store the HashMAC values of each file in a known text/binary file.
After each Integrity check the solution will generate a report (text file) showing the status of each verified file (OK or CORRUPTED). The report file name should contain the date and time of the check.
