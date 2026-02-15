import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Kafka Config
    KAFKA_BROKER_URL: str = "127.0.0.1:9092"
    KAFKA_TOPIC: str = "flows.raw.v1"
    KAFKA_GROUP_ID: str = "ids_consumer_group"

    # Model Config
    ATTACK_THRESHOLD: float = 0.4446967
    
    # Paths (Relative to app/models or absolute)
    BINARY_MODEL_PATH: str = "app/models/binary/binary_cnn_bilstm.keras"
    BINARY_SCALER_PATH: str = "app/models/binary/scaler.pkl"
    BINARY_SELECTOR_PATH: str = "app/models/binary/selector.pkl"

    MULTICLASS_MODEL_PATH: str = "app/models/multiclass/multiclass_cnn_bilstm.keras"
    MULTICLASS_SCALER_PATH: str = "app/models/multiclass/scaler.pkl"
    MULTICLASS_SELECTOR_PATH: str = "app/models/multiclass/selector.pkl"

    class Config:
        env_file = ".env"

settings = Settings()
