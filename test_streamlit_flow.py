import os
import sys
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from btech.predict import TrustLensPredictor
from btech.report import generate_pdf_report

predictor = TrustLensPredictor()
predictor.load_assets()

def test_file(file_name, file_bytes):
    try:
        result = predictor.predict_file(file_bytes, filename=file_name)
        pdf_bytes = generate_pdf_report(
            file_name,
            result["features"],
            {
                "trust_score": result["trust_score"],
                "risk_level": f"{result['risk_category']} Risk",
                "prediction": result["prediction"],
            },
            result["explanation_data"],
        )
        print(f"{file_name} success, pdf size: {len(pdf_bytes)}")
    except Exception as e:
        print(f"Error testing {file_name}: {e}")
        traceback.print_exc()

test_file("normal.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF")
