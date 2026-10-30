import os
import shutil
import zipfile
from PIL import Image
import numpy as np

sample_dir = r"C:\Users\user\OneDrive\Desktop\HCLCP\Sample_Test_Files"
os.makedirs(sample_dir, exist_ok=True)

# 1. Clean Windows Utility (Copied from hostname.exe / whoami.exe)
for exe_name in ["hostname.exe", "whoami.exe", "calc.exe"]:
    sys_exe = os.path.join(r"C:\Windows\System32", exe_name)
    if os.path.exists(sys_exe):
        shutil.copyfile(sys_exe, os.path.join(sample_dir, f"1_Clean_{exe_name}"))
        print(f"Copied clean Windows binary: 1_Clean_{exe_name}")
        break

# 2. Clean Mobile App APK
clean_apk_path = os.path.join(sample_dir, "2_Clean_Calculator_App.apk")
with zipfile.ZipFile(clean_apk_path, "w") as z:
    manifest_clean = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.utility.calculator">\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        '    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />\n'
        '    <application android:label="Clean Calc">\n'
        '        <activity android:name=".MainActivity">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.MAIN" />\n'
        '                <category android:name="android.intent.category.LAUNCHER" />\n'
        '            </intent-filter>\n'
        '        </activity>\n'
        '    </application>\n'
        '</manifest>'
    )
    z.writestr("AndroidManifest.xml", manifest_clean)
    z.writestr("classes.dex", b"DEX\n035\x00" + b"println read write open close Math.sqrt" * 150)
print("Created: 2_Clean_Calculator_App.apk")

# 3. Suspicious Android Trojan APK
trojan_apk_path = os.path.join(sample_dir, "3_Suspicious_Trojan_Spyware.apk")
with zipfile.ZipFile(trojan_apk_path, "w") as z:
    manifest_trojan = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.infiltrator.stealth">\n'
        '    <uses-permission android:name="android.permission.SEND_SMS" />\n'
        '    <uses-permission android:name="android.permission.RECEIVE_SMS" />\n'
        '    <uses-permission android:name="android.permission.READ_SMS" />\n'
        '    <uses-permission android:name="android.permission.READ_PHONE_STATE" />\n'
        '    <uses-permission android:name="android.permission.RECORD_AUDIO" />\n'
        '    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />\n'
        '    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />\n'
        '    <uses-permission android:name="android.permission.BIND_DEVICE_ADMIN" />\n'
        '    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />\n'
        '    <application android:label="System Update Helper">\n'
        '        <receiver android:name=".BootReceiver">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.BOOT_COMPLETED" />\n'
        '            </intent-filter>\n'
        '        </receiver>\n'
        '        <service android:name=".BackdoorService" />\n'
        '    </application>\n'
        '</manifest>'
    )
    z.writestr("AndroidManifest.xml", manifest_trojan)
    z.writestr("classes.dex", b"DEX\n035\x00" + b"execve ptrace kill fork chmod getuid setuid socket connect sendto recvfrom" * 200)
print("Created: 3_Suspicious_Trojan_Spyware.apk")

# 4. Visual Byte Matrix PNGs (for testing Grad-CAM & Visual Byte Matrix mode)
np.random.seed(42)
mal_bytes = np.random.randint(60, 240, (224, 224), dtype=np.uint8)
mal_bytes[:30, :] = 130
mal_bytes[180:, :] = 40
mal_img = Image.fromarray(mal_bytes)
mal_img.save(os.path.join(sample_dir, "4_ByteMatrix_Malware_Sim.png"))
print("Created: 4_ByteMatrix_Malware_Sim.png")

ben_bytes = np.zeros((224, 224), dtype=np.uint8)
ben_bytes[20:70, 20:180] = np.random.randint(80, 180, (50, 160), dtype=np.uint8)
ben_bytes[90:130, 40:140] = np.random.randint(60, 140, (40, 100), dtype=np.uint8)
ben_img = Image.fromarray(ben_bytes)
ben_img.save(os.path.join(sample_dir, "5_ByteMatrix_Benign_Sim.png"))
print("Created: 5_ByteMatrix_Benign_Sim.png")

print(f"\nAll test samples ready in: {sample_dir}")

