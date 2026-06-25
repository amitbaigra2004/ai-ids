
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
import matplotlib
matplotlib.use("Agg") 
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
import time

DATA_DIR  = "data/processed/"
MODEL_DIR = "models/saved/"


def load_data():
    print("Loading processed data...")
    X_train = np.load(os.path.join(DATA_DIR, "X_train.npy"))
    X_test  = np.load(os.path.join(DATA_DIR, "X_test.npy"))
    y_train = np.load(os.path.join(DATA_DIR, "y_train.npy"))
    y_test  = np.load(os.path.join(DATA_DIR, "y_test.npy"))

    print(f"  X_train: {X_train.shape}")
    print(f"  X_test:  {X_test.shape}")
    print(f"  y_train attack rate: {y_train.mean():.2%}")
    print(f"  y_test  attack rate: {y_test.mean():.2%}")

    return X_train, X_test, y_train, y_test


def train_random_forest(X_train, y_train):
 
    print("\nTraining Random Forest...")
    print("(this may take a few minutes on 2.2M rows)")

    start = time.time()

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        verbose=1,
    )
    model.fit(X_train, y_train)

    elapsed = time.time() - start
    print(f"\nTraining complete in {elapsed:.1f} seconds.")

    return model


def evaluate(model, X_test, y_test):
   
    print("\nRunning predictions on test set...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 55)
    print("CLASSIFICATION REPORT")
    print("=" * 55)
    print(classification_report(
        y_test, y_pred,
        target_names=["BENIGN", "ATTACK"],
        digits=4
    ))

    auc = roc_auc_score(y_test, y_prob)
    print(f"AUC-ROC Score: {auc:.4f}")
    print("(1.0 = perfect separation, 0.5 = random guessing)")

  
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(f"                 Predicted BENIGN   Predicted ATTACK")
    print(f"Actual BENIGN    {cm[0][0]:<18} {cm[0][1]}")
    print(f"Actual ATTACK    {cm[1][0]:<18} {cm[1][1]}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    plt.figure(figsize=(7, 6))
    sns.heatmap(
        cm, annot=True, fmt="d",
        xticklabels=["BENIGN", "ATTACK"],
        yticklabels=["BENIGN", "ATTACK"],
        cmap="Blues"
    )
    plt.title("Confusion Matrix — Random Forest (CICIDS2017)")
    plt.ylabel("Actual")
    plt.xlabel("Predicted")
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"))
    print(f"\nConfusion matrix image saved to {MODEL_DIR}confusion_matrix.png")

    return y_pred


def show_feature_importance(model):
   
    from preprocessing.feature_engineering import FEATURE_ORDER

    importances = model.feature_importances_
    pairs = sorted(
        zip(FEATURE_ORDER, importances),
        key=lambda x: x[1],
        reverse=True
    )

    print("\n" + "=" * 55)
    print("FEATURE IMPORTANCE (highest to lowest)")
    print("=" * 55)
    for name, score in pairs:
        
        print(f"  {name:20s} {score:.4f}")


def save_model(model):
    os.makedirs(MODEL_DIR, exist_ok=True)
    path = os.path.join(MODEL_DIR, "random_forest.pkl")
    joblib.dump(model, path)
    print(f"\nModel saved to {path}")


if __name__ == "__main__":
    print("=" * 55)
    print("Day 7 — Random Forest Training")
    print("=" * 55)

    X_train, X_test, y_train, y_test = load_data()
    model = train_random_forest(X_train, y_train)
    evaluate(model, X_test, y_test)
    show_feature_importance(model)
    save_model(model)

    print("\n" + "=" * 55)
    print("Day 7 complete. Model ready for hybrid engine (Day 8).")
    print("=" * 55)
