import sys
from Registry import Registry

def setup_output():
    """Set up output to console and file"""
    class DualOutput:
        def __init__(self, *files):
            self.files = files
        def write(self, text):
            for f in self.files:
                f.write(text)
        def flush(self):
            for f in self.files:
                f.flush()
    
    output_file = open("forensics_report.txt", "w", encoding="utf-8")
    sys.stdout = DualOutput(sys.stdout, output_file)
    return output_file

def analyze_system_info(software_hive):
    """Get basic system information"""
    print("=== SYSTEM INFORMATION ===")
    try:
        reg = Registry.Registry(software_hive)
        key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
        
        print(f"OS: {key.value('ProductName').value()}")
        print(f"User: {key.value('RegisteredOwner').value()}")
        print(f"Version: {key.value('CurrentVersion').value()}")
        print(f"Build: {key.value('CurrentBuildNumber').value()}")
        
        try:
            sp = key.value('CSDVersion').value()
            print(f"Service Pack: {sp}")
        except:
            print("Service Pack: None")
            
    except Exception as e:
        print(f"Error reading system info: {e}")

def analyze_users(sam_hive):
    """List all user accounts"""
    print("\n=== USER ACCOUNTS ===")
    try:
        reg = Registry.Registry(sam_hive)
        key = reg.open("SAM\\Domains\\Account\\Users\\Names")
        
        users = [user.name() for user in key.subkeys()]
        print("Accounts found:")
        for user in sorted(users):
            print(f"  - {user}")
        print(f"Total: {len(users)} users")
            
    except Exception as e:
        print(f"Error reading user accounts: {e}")

def analyze_software(software_hive):
    """List installed programs"""
    print("\n=== INSTALLED SOFTWARE ===")
    try:
        reg = Registry.Registry(software_hive)
        programs = []
        
        # Get programs from uninstall entries
        try:
            uninstall = reg.open("Microsoft\\Windows\\CurrentVersion\\Uninstall")
            for app in uninstall.subkeys():
                try:
                    programs.append(app.value("DisplayName").value())
                except:
                    continue
        except:
            pass
        
        # Get registered applications
        try:
            app_paths = reg.open("Microsoft\\Windows\\CurrentVersion\\App Paths")
            for app in app_paths.subkeys():
                programs.append(app.name())
        except:
            pass
        
        for program in programs:
            print(f"  - {program}")
        print(f"Total: {len(programs)} programs")
            
    except Exception as e:
        print(f"Error reading software: {e}")

def analyze_usb(system_hive):
    """Show USB device history"""
    print("\n=== USB DEVICES ===")
    try:
        reg = Registry.Registry(system_hive)
        usb_count = 0
        
        # USB devices
        try:
            usb_key = reg.open("ControlSet001\\Enum\\USB")
            for device in usb_key.subkeys():
                if device.name() not in ["ROOT_HUB", "ROOT_HUB20"]:
                    print(f"  - {device.name()}")
                    usb_count += 1
        except:
            print("No USB devices found")
        
        # USB storage
        try:
            usbstor = reg.open("ControlSet001\\Enum\\USBSTOR")
            for device in usbstor.subkeys():
                print(f"  - {device.name()}")
                usb_count += 1
        except:
            pass
        
        print(f"Total: {usb_count} USB devices")
            
    except Exception as e:
        print(f"Error reading USB history: {e}")

def analyze_commands(ntuser_hive):
    """Check command history"""
    print("\n=== COMMAND HISTORY ===")
    try:
        reg = Registry.Registry(ntuser_hive)
        
        # PowerShell
        try:
            ps = reg.open("Software\\Microsoft\\PowerShell\\ConsoleHost\\History")
            commands = [cmd for cmd in ps.value("History").value().split('\x00') if cmd.strip()]
            if commands:
                print("PowerShell commands:")
                for cmd in commands:
                    print(f"  - {cmd}")
            else:
                print("No PowerShell history")
        except:
            print("No PowerShell history")
        
        # Run commands
        try:
            run = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
            commands = [v.value() for v in run.values() if v.name() != "MRUList"]
            if commands:
                print("Recent Run commands:")
                for cmd in commands:
                    print(f"  - {cmd}")
            else:
                print("No Run commands")
        except:
            print("No Run commands")
            
    except Exception as e:
        print(f"Error reading command history: {e}")

def main():
    output_file = setup_output()
    
    print("=" * 50)
    print("FORENSIC REGISTRY ANALYSIS")
    print("=" * 50)
    
    # Analyze registry hives
    analyze_system_info("software_hive")
    analyze_users("sam_hive")
    analyze_software("software_hive")
    analyze_usb("system_hive")
    analyze_commands("ntuser.dat")
    
    print("\n" + "=" * 50)
    print("ANALYSIS COMPLETE")
    print("=" * 50)
    
    output_file.close()
    sys.stdout = sys.__stdout__

if __name__ == "__main__":
    main()