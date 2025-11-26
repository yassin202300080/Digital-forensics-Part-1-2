import sys
from Registry import Registry

def setup_output():
    """Set up output to both console and file"""
    class TeeOutput:
        def __init__(self, *files):
            self.files = files
        
        def write(self, obj):
            for f in self.files:
                f.write(obj)
        
        def flush(self):
            for f in self.files:
                f.flush()
    
    # Create output file
    output_file = open("forensics_analysis_report.txt", "w", encoding="utf-8")
    
    # Tee output to both console and file
    sys.stdout = TeeOutput(sys.stdout, output_file)
    return output_file

def analyze_system_info(software_hive_path):
    print("=== SYSTEM INFORMATION FROM SOFTWARE HIVE ===")
    try:
        reg = Registry.Registry(software_hive_path)
        key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
        
        print(f"Product Name: {key.value('ProductName').value()}")
        print(f"Registered Owner: {key.value('RegisteredOwner').value()}")
        print(f"Version: {key.value('CurrentVersion').value()}")
        print(f"Build: {key.value('CurrentBuildNumber').value()}")
        
        # Handle Service Pack which might not exist
        try:
            sp = key.value('CSDVersion').value()
            print(f"Service Pack: {sp}")
        except Registry.RegistryValueNotFoundException:
            print("Service Pack: None")
            
    except Exception as e:
        print(f"Error reading SOFTWARE hive: {e}")

def analyze_user_accounts(sam_hive_path):
    print("\n=== USER ACCOUNTS FROM SAM HIVE ===")
    try:
        reg = Registry.Registry(sam_hive_path)
        key = reg.open("SAM\\Domains\\Account\\Users\\Names")
        
        users = []
        for user in key.subkeys():
            users.append(user.name())
        
        print("Local Users Found:")
        for user in sorted(users):
            print(f"  - {user}")
            
        print(f"\nTotal Users: {len(users)}")
            
    except Exception as e:
        print(f"Error reading SAM hive: {e}")

def analyze_installed_apps(software_hive_path):
    print("\n=== INSTALLED APPLICATIONS ===")
    try:
        reg = Registry.Registry(software_hive_path)
        
        # Method 1: From Uninstall keys
        print("From Uninstall Keys:")
        app_count = 0
        try:
            uninstall_key = reg.open("Microsoft\\Windows\\CurrentVersion\\Uninstall")
            for app in uninstall_key.subkeys():
                try:
                    name = app.value("DisplayName").value()
                    print(f"  - {name}")
                    app_count += 1
                except Registry.RegistryValueNotFoundException:
                    continue
        except Registry.RegistryKeyNotFoundException:
            pass
        
        # Method 2: From App Paths (executable applications)
        print("\nFrom Application Paths:")
        try:
            app_paths = reg.open("Microsoft\\Windows\\CurrentVersion\\App Paths")
            for app in app_paths.subkeys():
                print(f"  - {app.name()}")
                app_count += 1
        except Registry.RegistryKeyNotFoundException:
            pass
        
        print(f"\nTotal Applications Found: {app_count}")
            
    except Exception as e:
        print(f"Error reading installed apps: {e}")

def analyze_usb_history(system_hive_path):
    print("\n=== USB DEVICE HISTORY ===")
    try:
        reg = Registry.Registry(system_hive_path)
        
        # USB Device IDs
        usb_count = 0
        try:
            usb_key = reg.open("ControlSet001\\Enum\\USB")
            print("USB Devices Found:")
            for device in usb_key.subkeys():
                if device.name() not in ["ROOT_HUB", "ROOT_HUB20"]:  # Filter out root hubs
                    print(f"  - {device.name()}")
                    usb_count += 1
                    for subdevice in device.subkeys():
                        try:
                            friendly_name = subdevice.value("FriendlyName").value()
                            print(f"    -> {friendly_name}")
                        except Registry.RegistryValueNotFoundException:
                            print(f"    -> {subdevice.name()}")
        except Registry.RegistryKeyNotFoundException:
            print("No USB history found")
            
        # USBSTOR - Mass Storage Devices
        try:
            usbstor_key = reg.open("ControlSet001\\Enum\\USBSTOR")
            print("\nUSB Mass Storage Devices:")
            for device in usbstor_key.subkeys():
                print(f"  - {device.name()}")
                usb_count += 1
        except Registry.RegistryKeyNotFoundException:
            print("No USB storage devices found")
        
        print(f"\nTotal USB Devices: {usb_count}")
            
    except Exception as e:
        print(f"Error reading USB history: {e}")

def analyze_command_history(ntuser_path):
    print("\n=== COMMAND HISTORY ===")
    try:
        reg = Registry.Registry(ntuser_path)
        
        # PowerShell History
        try:
            ps_key = reg.open("Software\\Microsoft\\PowerShell\\ConsoleHost\\History")
            commands = ps_key.value("History").value().split('\x00')
            print("PowerShell Command History:")
            cmd_count = 0
            for cmd in commands:
                if cmd.strip():
                    print(f"  - {cmd}")
                    cmd_count += 1
            if cmd_count == 0:
                print("  No PowerShell commands found")
        except Registry.RegistryKeyNotFoundException:
            print("No PowerShell history found")
        
        # CMD RunMRU (recent Run commands)
        try:
            runmru_key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
            print("\nRun Dialog History (Recent Commands):")
            run_count = 0
            for value in runmru_key.values():
                if value.name() != "MRUList":
                    print(f"  - {value.value()}")
                    run_count += 1
            if run_count == 0:
                print("  No Run commands found")
        except Registry.RegistryKeyNotFoundException:
            print("No RunMRU history found")
            
    except Exception as e:
        print(f"Error reading command history: {e}")

def main():
    # Set up output to file and console
    output_file = setup_output()
    
    print("=" * 60)
    print("DIGITAL FORENSICS REGISTRY ANALYZER")
    print("KH5036CMD Digital Forensics Coursework")
    print("=" * 60)
    print("Output also saved to: forensics_analysis_report.txt")
    print("=" * 60)
    
    # File names - must match your extracted files exactly
    software_hive = "software_hive"
    sam_hive = "sam_hive" 
    system_hive = "system_hive"
    ntuser_hive = "ntuser.dat"
    
    # Run all analyses
    analyze_system_info(software_hive)
    analyze_user_accounts(sam_hive)
    analyze_installed_apps(software_hive)
    analyze_usb_history(system_hive)
    analyze_command_history(ntuser_hive)
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("Output saved to: forensics_analysis_report.txt")
    print("=" * 60)
    
    # Close the output file
    output_file.close()
    
    # Restore stdout
    sys.stdout = sys.__stdout__
    
    print("\n✅ Analysis complete! Check 'forensics_analysis_report.txt' for saved results.")

if __name__ == "__main__":
    main()