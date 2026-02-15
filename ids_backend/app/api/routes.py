from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
import numpy as np
import io
from collections import Counter

from app.services.metrics import get_metrics
from app.models.metadata import MODEL_FEATURES, ATTACK_CLASSES
from app.preprocessing.clean import clean_df
from app.config import settings
import app.models.loader as loader

router = APIRouter()

@router.get("/health")
def health():
    return {"status": "ok", "service": "ids-backend"}

@router.get("/metrics")
def metrics():
    return get_metrics()

@router.post("/analyze_csv")
async def analyze_csv(file: UploadFile = File(...)):
    
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV.")

    try:
        print(f"Starting analysis for {file.filename}...")
        contents = await file.read()
        print(f"File read: {len(contents)} bytes")

        try:
            df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
        except UnicodeDecodeError:
            print("UTF-8 decode failed, trying latin-1...")
            df = pd.read_csv(io.StringIO(contents.decode('latin-1')))
        
        print(f"DataFrame loaded: {df.shape}")

        # Validate columns
        missing_cols = [col for col in MODEL_FEATURES if col not in df.columns]
        if missing_cols:
            # Try stripping whitespace from columns
            df.columns = df.columns.str.strip()
            missing_cols = [col for col in MODEL_FEATURES if col not in df.columns]
            if missing_cols:
                 print(f"Missing columns: {missing_cols}")
                 raise HTTPException(status_code=400, detail=f"Missing columns: {missing_cols}")

        # Keep only relevant columns and clean
        df_features = df[MODEL_FEATURES]
        df_features = clean_df(df_features)
        print("Features cleaned.")

        # 1. Binary Classification
        # Ensure models are loaded
        if loader.binary_ids is None:
             print("Loading models...")
             loader.load_models()
             
        print("Running binary inference...")
        X_bin = loader.binary_ids.preprocess(df_features)
        y_prob = loader.binary_ids.model.predict(X_bin, verbose=0).flatten()
        
        # 2. Filter Attack Candidates
        attack_indices = np.where(y_prob >= settings.ATTACK_THRESHOLD)[0]
        benign_count = len(y_prob) - len(attack_indices)
        print(f"Inference done. Malicious: {len(attack_indices)}, Benign: {benign_count}")
        
        attack_results = []
        
        if len(attack_indices) > 0:
            # 3. Multiclass Classification 
            print("Running multiclass inference...")
            df_attacks = df_features.iloc[attack_indices]
            X_multi = loader.multi_ids.preprocess(df_attacks)
            y_multi_prob = loader.multi_ids.model.predict(X_multi, verbose=0)
            y_multi_pred = np.argmax(y_multi_prob, axis=1)
            
            for idx, label_idx in zip(attack_indices, y_multi_pred):
                attack_type = ATTACK_CLASSES.get(label_idx, "Unknown")
                confidence = float(y_multi_prob[list(attack_indices).index(idx)][label_idx])
                attack_results.append({
                    "row_index": int(idx),
                    "attack_type": attack_type,
                    "confidence": confidence,
                    "p_attack": float(y_prob[idx])
                })

        # Aggregate Results
        attack_counts = Counter([r['attack_type'] for r in attack_results])
        print("Analysis complete. Sending response.")
        
        return JSONResponse(content={
            "filename": file.filename,
            "total_rows": len(df),
            "benign_count": benign_count,
            "malicious_count": len(attack_indices),
            "attack_distribution": dict(attack_counts),
            "attacks": attack_results[:100] # Return first 100 attacks detailed
        })

    except Exception as e:
        print(f"ERROR in analyze_csv: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
