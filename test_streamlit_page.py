import sys
import os
import traceback

class DummyST:
    def set_page_config(self, **kwargs): pass
    def markdown(self, text, **kwargs): pass
    def file_uploader(self, label, **kwargs): 
        class DummyFile:
            name = "normal.pdf"
            def read(self):
                return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        return DummyFile()
    def error(self, text):
        print(f"ST ERROR: {text}")
    def stop(self):
        sys.exit(1)
    class SessionState:
        def __init__(self):
            self.scan_history = []
        def __contains__(self, key):
            return hasattr(self, key)
        def __getattr__(self, key):
            return getattr(self, key, None)
    session_state = SessionState()
    class spinner:
        def __init__(self, text): pass
        def __enter__(self): pass
        def __exit__(self, exc_type, exc_val, exc_tb): pass
    def columns(self, spec, gap="small"):
        class DummyCol:
            def __enter__(self): pass
            def __exit__(self, exc_type, exc_val, exc_tb): pass
        return [DummyCol()] * len(spec)
    def plotly_chart(self, fig, **kwargs): pass
    def download_button(self, **kwargs): pass
    class sidebar:
        @staticmethod
        def markdown(*args, **kwargs): pass

sys.modules["streamlit"] = DummyST()
import streamlit as st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

# Fix model paths before running the page
from btech.predict import TrustLensPredictor
original_init = TrustLensPredictor.__init__
def new_init(self, model_path="Models/multiformat_model.joblib", preprocessor_path="Models/multiformat_preprocessor.joblib"):
    original_init(self, model_path, preprocessor_path)
    self.pe_model_path = "Models/malware_model.joblib"
    self.pe_preprocessor_path = "Models/preprocessor.joblib"
TrustLensPredictor.__init__ = new_init

try:
    with open("src/btech/pages/01_Upload_Predict.py") as f:
        code = f.read()
    exec(code)
except Exception as e:
    traceback.print_exc()
print('SUCCESS')
