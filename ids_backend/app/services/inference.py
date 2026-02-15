import numpy as np
import app.models.loader as loader
from app.preprocessing.clean import clean_df
from app.config import settings
from app.models.metadata import MODEL_FEATURES, ATTACK_CLASSES

ATTACK_THRESHOLD = settings.ATTACK_THRESHOLD



def infer(df):
    # Enforce feature order
    df = df[MODEL_FEATURES]
    df = clean_df(df)

    print(f"DEBUG Features: SYN={df['SYN Flag Count'].iloc[0]}, Dur={df['Flow Duration'].iloc[0]}, Pkts={df['Total Fwd Packets'].iloc[0]}")

    # Binary Stage 
    X_bin = loader.binary_ids.preprocess(df)
    p_attack = float(loader.binary_ids.model.predict(X_bin)[0][0])
    
    print(f"DEBUG Prediction: p_attack={p_attack}")

    if p_attack < ATTACK_THRESHOLD:
        return {
            "is_attack": False,
            "binary_confidence": p_attack,
            "attack_type": "Benign"
        }

    # Multiclass Stage 
    X_multi = loader.multi_ids.preprocess(df)
    probs = loader.multi_ids.model.predict(X_multi)[0]
    attack_class_idx = int(np.argmax(probs))
    attack_type = ATTACK_CLASSES.get(attack_class_idx, "Unknown")

    return {
        "is_attack": True,
        "attack_class": attack_class_idx,
        "attack_type": attack_type,
        "multiclass_confidence": float(np.max(probs)),
        "binary_confidence": p_attack
    }

