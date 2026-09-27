"""Evaluate the TrustLens-compatible PDF real-world benchmark model.

Usage:
  python run_external_pdf_benchmark.py /path/to/PDFMalware2022.csv

The CSV is used only as an external labelled benchmark and is not bundled with
TrustLens. The model is trained on the CIC feature table using a 10-feature
PDF adapter whose features can also be extracted from raw PDF bytes.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

ROOT=Path(__file__).resolve().parent
MODEL=ROOT/'Models'/'realworld_pdf_model.joblib'
FEATURES=["file_size_kb","structural_complexity","has_executable_code","has_obfuscation","has_network_indicators","has_macros_or_scripts","is_encrypted_or_packed","has_masquerading","metadata_density","suspicious_indicators_count"]

def make_features(df):
    def n(c): return pd.to_numeric(df[c],errors='coerce').fillna(0) if c in df else pd.Series(0,index=df.index)
    obj=n('obj'); stream=n('stream'); endstream=n('endstream'); xref=n('xref'); trailer=n('trailer'); emb=n('embedded files')
    js=n('JS'); javascript=n('Javascript'); aa=n('AA'); oa=n('OpenAction'); launch=n('launch'); enc=n('isEncrypted')+n('encrypt')
    ob=n('ObjStm')+n('JBIG2Decode')+n('XFA')+n('RichMedia'); metadata=n('metadata size'); pdfsize=n('pdfsize'); acro=n('Acroform')+n('XFA')
    return pd.DataFrame({
      'file_size_kb':pdfsize,
      'structural_complexity':np.log1p(np.maximum(0,obj+stream+endstream+xref+trailer+emb)),
      'has_executable_code':((js+javascript+aa+oa+launch)>0).astype(float),
      'has_obfuscation':(ob>0).astype(float),
      'has_network_indicators':((oa+launch)>0).astype(float),
      'has_macros_or_scripts':((js+javascript+aa)>0).astype(float),
      'is_encrypted_or_packed':(enc>0).astype(float),
      'has_masquerading':0.0,
      'metadata_density':np.clip(metadata/(pdfsize+1),0,1),
      'suspicious_indicators_count':((js+javascript+aa+oa+launch)>0).astype(float)+(ob>0).astype(float)+((oa+launch)>0).astype(float)+((js+javascript+aa)>0).astype(float)+(enc>0).astype(float)+((n('EmbeddedFile')+emb)>0).astype(float)+(acro>0).astype(float)
    })[FEATURES]

def evaluate(path):
    df=pd.read_csv(path); df=df[df['Class'].isin(['Malicious','Benign'])].copy()
    y=(df['Class']=='Malicious').astype(int)
    X=make_features(df)
    _, Xtest, _, ytest=train_test_split(X,y,test_size=.30,random_state=42,stratify=y)
    model=joblib.load(MODEL)
    pred=model.predict(Xtest); prob=model.predict_proba(Xtest)[:,1]
    cm=confusion_matrix(ytest,pred,labels=[1,0])
    return {'evaluation_type':'TrustLens-compatible real-world PDF benchmark','dataset':'CIC-Evasive-PDFMal2022','total_samples':len(df),'test_samples':len(ytest),'accuracy':float(accuracy_score(ytest,pred)),'precision_malicious':float(precision_score(ytest,pred,pos_label=1)),'recall_malicious':float(recall_score(ytest,pred,pos_label=1)),'f1_malicious':float(f1_score(ytest,pred,pos_label=1)),'roc_auc':float(roc_auc_score(ytest,prob)),'confusion_matrix_malicious_first':cm.tolist(),'features':FEATURES,'note':'PDF-specific real-world benchmark using the same 10-feature adapter for benchmark features and raw-file extraction. Not a universal multi-format accuracy.'}

if __name__=='__main__':
    if len(sys.argv)!=2: raise SystemExit('Usage: python run_external_pdf_benchmark.py /path/to/PDFMalware2022.csv')
    m=evaluate(sys.argv[1]); out=ROOT/'data'/'real_world_evaluation'; out.mkdir(parents=True,exist_ok=True); (out/'external_pdf_benchmark_metrics.json').write_text(json.dumps(m,indent=2)); print(json.dumps(m,indent=2))
