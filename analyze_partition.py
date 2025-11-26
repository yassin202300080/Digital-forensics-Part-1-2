import struct
import os
import sys
from collections import namedtuple

PartitionEntry = namedtuple('PartitionEntry', 
                           ['status', 'type_code', 'lba_start', 'sector_count', 'size_mb'])

def get_partition_type(type_code):
    """Map partition type codes to human-readable names"""
    type_map = {
        0x00: "Unallocated",
        0x07: "NTFS",
        0x0B: "FAT32",
        0x0C: "FAT32 LBA",
        0x83: "Linux",
        0x82: "Linux Swap",
        0x05: "Extended",
        0x0F: "Extended LBA",
        0xEE: "GPT Protective"
    }
    return type_map.get(type_code, f"Unknown (0x{type_code:02x})")

def detailed_partition_analysis(image_path):
    """Detailed partition analysis with error detection"""
    
    def read_sector(f, sector):
        f.seek(sector * 512)
        return f.read(512)
    
    try:
        with open(image_path, 'rb') as f:
            # Read MBR
            mbr = read_sector(f, 0)
            
            # Check MBR signature
            if mbr[510:512] != b'\x55\xaa':
                print("ERROR: Invalid MBR signature!")
                return
            
            print(f"Partition Table Analysis for: {image_path}")
            print("=" * 60)
            
            partitions = []
            for i in range(4):
                offset = 446 + (i * 16)
                entry_data = mbr[offset:offset+16]
                
                # REMOVED THE FILTER - Show ALL partitions
                status, chs_start, type_code, chs_end, lba_start, sector_count = \
                    struct.unpack('<B3sB3sII', entry_data)
                
                size_mb = (sector_count * 512) / (1024 * 1024)
                partition = PartitionEntry(status, type_code, lba_start, sector_count, size_mb)
                partitions.append(partition)
                
                print(f"Partition {i+1}:")
                print(f"  Status: 0x{status:02x} {'(Active)' if status == 0x80 else ''}")
                print(f"  Type: 0x{type_code:02x} ({get_partition_type(type_code)})")
                print(f"  LBA Start: {lba_start}")
                print(f"  Sector Count: {sector_count}")
                print(f"  Size: {size_mb:.2f} MB")
                
                # Check for common issues
                if lba_start == 0 and sector_count > 0:
                    print("  WARNING: LBA start is 0 but sector count > 0")
                if sector_count == 0 and type_code != 0x00:
                    print("  WARNING: Sector count is 0 but partition type is not unallocated")
                    
                print()
            
            # Analyze second partition specifically (skip unallocated)
            allocated_partitions = [p for p in partitions if p.type_code != 0x00]
            if len(allocated_partitions) >= 2:
                print("\n" + "="*50)
                analyze_second_partition(f, allocated_partitions[1])
            else:
                print("No second allocated partition found!")
                
    except FileNotFoundError:
        print(f"ERROR: File '{image_path}' not found!")
        print("Please make sure 'CW Image.dd' is in the same folder as this script")
    except Exception as e:
        print(f"ERROR: {e}")

def analyze_second_partition(f, partition):
    """Specifically analyze the second partition"""
    print("Second Partition Detailed Analysis:")
    print("=" * 40)
    
    try:
        # Read beginning of second partition
        f.seek(partition.lba_start * 512)
        partition_start = f.read(512)
        
        # Check for file system signatures
        if partition_start[3:7] == b'NTFS':
            print("  File System: NTFS")
        elif partition_start[510:512] == b'\x55\xaa':
            print("  Valid boot sector signature found")
        elif partition_start[0:2] == b'\xeb\x3c' or partition_start[0:2] == b'\xeb\x58':
            print("  File System: FAT32")
        elif partition_start[0x36:0x3A] == b'FAT32':
            print("  File System: FAT32")
        else:
            print("  Unknown file system or corrupted boot sector")
            
        print(f"  Starting at sector: {partition.lba_start}")
        print(f"  Total sectors: {partition.sector_count}")
        print(f"  Total size: {partition.size_mb:.2f} MB")
        
    except Exception as e:
        print(f"  ERROR reading partition: {e}")

def auto_detect_and_analyze():
    """Automatically detect and analyze CW Image.dd"""
    image_filename = "CW Image.dd"
    
    if os.path.exists(image_filename):
        print(f"Found image file: {image_filename}")
        detailed_partition_analysis(image_filename)
    else:
        print(f"File '{image_filename}' not found in current directory.")
        print("Files in current directory:")
        for file in os.listdir('.'):
            print(f"  - {file}")
        print(f"\nPlease make sure '{image_filename}' is in the same folder as this script")

if __name__ == "__main__":
    # Check if specific file was provided as argument
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        detailed_partition_analysis(image_path)
    else:
        # Auto-detect "CW Image.dd"
        auto_detect_and_analyze()