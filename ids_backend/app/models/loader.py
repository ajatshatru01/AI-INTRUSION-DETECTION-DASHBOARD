import tensorflow as tf
import joblib
import numpy as np
from app.config import settings

class IDSModel:
    def __init__(self, model_path, scaler_path, selector_path):
        
        self.model = tf.keras.models.load_model(
            model_path,
            compile=False
        )

        self.scaler = joblib.load(scaler_path)
        self.selector = joblib.load(selector_path)

       
        dummy = np.zeros((1, self.selector.transform(
            np.zeros((1, self.selector.n_features_in_))
        ).shape[1]))
        self.model.predict(
            dummy.reshape(1, dummy.shape[1], 1),
            verbose=0
        )

    def preprocess(self, df):
        X = self.selector.transform(df)
        X = self.scaler.transform(X)
        return X.reshape(X.shape[0], X.shape[1], 1)


binary_ids = None
multi_ids = None

def load_models():
    global binary_ids, multi_ids

    binary_ids = IDSModel(
        settings.BINARY_MODEL_PATH,
        settings.BINARY_SCALER_PATH,
        settings.BINARY_SELECTOR_PATH
    )

    multi_ids = IDSModel(
        settings.MULTICLASS_MODEL_PATH,
        settings.MULTICLASS_SCALER_PATH,
        settings.MULTICLASS_SELECTOR_PATH
    )
