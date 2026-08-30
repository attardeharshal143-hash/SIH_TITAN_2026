import json
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

FEATURE_NAMES = [
    "packet_length",
    "ip_version",
    "ip_protocol_number",
    "src_port",
    "dst_port",
    "ike_candidate",
    "esp",
    "ah",
    "icmp",
    "dns"
]

def train_ipsec_model(dataset_json_path, output_model_path):
    dataset_json_path = Path(dataset_json_path)
    output_model_path = Path(output_model_path)

    if not dataset_json_path.exists():
        raise FileNotFoundError(f"Training dataset not found: {dataset_json_path}")

    with open(dataset_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    X = [[row[key] for key in FEATURE_NAMES] for row in data]
    y = [row["label"] for row in data]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, str(output_model_path))

    print("================================")
    print("       ML MODEL TRAINING")
    print("================================")
    print(f"Dataset:          {dataset_json_path.name}")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples:  {len(X_test)}")
    print(f"Accuracy:         {accuracy * 100:.2f}%")
    print(f"Model saved to:   {output_model_path}")
    print("================================")
    return model

if __name__ == "__main__":
    base = Path(__file__).resolve().parent.parent
    ds = base / "dataset" / "ml_training_dataset.json"
    out = base / "dataset" / "ipsec_ml_model.joblib"
    if ds.exists():
        train_ipsec_model(ds, out)
    else:
        print(f"No training file found at {ds}")
