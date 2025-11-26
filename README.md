# Digital-forensics-Part-1-2
part1: Analyze the partition table

1.first the code starts with data structure and creates simple data structure to store information; each partition contains status type, start location, sector size which calculated is calculated in mb.

2. Partition mapping Converts numeric partition codes that uses 0x07 to NTFS

3. the main analisis function reads sector in 512 bytes 

4. validation of MBR; reads the first sector, checks for the signature to confirm its a valid disk. 

5. the partition table reading, MBR has 4 partition entries starting at byte 446 .Each entry is 16 bytes long
The loop reads all 4 possible partitions

6. unpacking of partition data, struct.unpack converts binary data into usable values,
status: check activity and inactivity of partition
type: what filestems the partition use 
sector number : where the partition begins 

7. The error checking detects  partition table corruption the start sector 0 indicates the corrupted structure. 

8. then the code reads thesecond partition and analyse it 

9. the file systems signatures are checked. the partion format are detected by patterns including NFTS, FAT32.

part2: Disk Image Analysis

1. the extracted system information reads the software registry hive to get operating system details including Windows version, registered owner, build number, and service pack information.

2. User account analysis accesses the sam hive to list all local user accounts stored in the security database, displaying both active and inactive user profiles.

3. It makes a list of all installed programs by looking in two places in the registry the uninstall list and registered applications.
4. then the usb devices histrory are read through thr system registry file 

