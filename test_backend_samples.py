import urllib.request
import os
import json

sample_dir = r"C:\Users\user\OneDrive\Desktop\HCLCP\Sample_Test_Files"

def test_upload(filename, platform):
    filepath = os.path.join(sample_dir, filename)
    with open(filepath, "rb") as f:
        file_bytes = f.read()

    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin1") + file_bytes + (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="platform"\r\n\r\n'
        f"{platform}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="threshold"\r\n\r\n'
        f"0.5\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin1")

    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/scan",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        print(f"[{res['prediction'].upper()}] {filename} ({platform}) => Confidence: {res['confidence']*100:.2f}% | Raw Score: {res['raw_score']:.4f}")

if __name__ == "__main__":
    print("Testing generated test files with Vektor Deep Learning backend:\n")
    test_upload("1_Clean_hostname.exe", "windows")
    test_upload("2_Clean_Calculator_App.apk", "android")
    test_upload("3_Suspicious_Trojan_Spyware.apk", "android")
    test_upload("4_ByteMatrix_Malware_Sim.png", "windows")
    test_upload("5_ByteMatrix_Benign_Sim.png", "windows")

