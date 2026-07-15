import os
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

def train_model(data_path, model_path):
    # Load the preprocessed data
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"The specified data path does not exist: {data_path}")

    print(f"[*] Loading dataset from {data_path}...")
    df = pd.DataFrame(pd.read_csv(data_path))
    feature_columns = ["length", "num_special_chars", "num_attack_patterns", "num_keywords", "entropy"]
           
    X = df[feature_columns]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"[*] Data split complete. Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # Initialize and train the model
    print("[*] Training Random Forest model (this may take a moment)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced', n_jobs=-1)
    model.fit(X_train, y_train)

    print("[+] Model training complete!")

    # Make predictions and evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n================ MODEL PERFORMANCE METRICS ================")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Malicious (1)"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("===========================================================\n")
 
    #Export the model to a file
    print(f"[*] Exporting trained model to {model_path}...")
    joblib.dump(model, model_path, compress=3)
    print("[+] Model successfully exported!")

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_PATH = os.path.join(os.path.dirname(BASE_DIR), "datasets", "dataset_features.csv")
    MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
    train_model(DATA_PATH, MODEL_PATH)