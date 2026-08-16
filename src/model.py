import joblib
import os
import pandas as pd

class PhishingModel:
    def __init__(self, model_path: str = None):
        self.model = None
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def load_model(self, model_path: str):
        self.model = joblib.load(model_path)

    def predict_proba(self, features_df: pd.DataFrame):
        if self.model is None:
            return [[0.9, 0.1]]
        return self.model.predict_proba(features_df)
