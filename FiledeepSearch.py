'''Code to find files in a system with extensions .pdf, .txt, and .docs'''
import os
import platform
def search_files(start_path):
    target_extensions = (".pdf", ".txt", ".docx")
    def on_error(error):
        print(f" [!] Access Denied: {error.filename}")
    for root, dirs, files in os.walk(start_path, onerror=on_error):
        for file in files:
            if file.endswith(target_extensions):
                full_path = os.path.join(root, file)
                print(f"[+] Found: {full_path}") #print(f"[+] Found: {os.path.join(root,file)}")
if __name__ == "__main__":
    current_os = platform.system()
    if current_os == "Linux":
        search_files("/home/kali/")
    elif current_os == "Windows":
        search_files("C:\\Users\\Public")
    else:
        print(f"OS {current_os} not specifically configured, but starting search...")
        search_files("/")
