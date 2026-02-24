import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_predict
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import os
import joblib

# 📥 Chargement du dataset
df = pd.read_csv("ia_cms_detection/dataset_training.csv")

# ❌ Suppression des classes trop rares
cms_counts = df["CMS"].value_counts()
df = df[df["CMS"].isin(cms_counts[cms_counts >= 3].index)]

# ✅ Features et labels
X = df.drop(columns=["URL", "CMS", "cms_detect"])
y = df["CMS"]
le = LabelEncoder()
y_encoded = le.fit_transform(y)

print("📌 Répartition des CMS :\n")
print(y.value_counts(), "\n")

# ✂️ Split 70/15/15
X_temp, X_test, y_temp, y_test = train_test_split(X, y_encoded, test_size=0.15, stratify=y_encoded, random_state=42)
X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.176, stratify=y_temp, random_state=42)

X_trainval = pd.concat([X_train, X_val])
y_trainval = pd.concat([pd.Series(y_train), pd.Series(y_val)])

# 🔁 Validation croisée
min_class_size = pd.Series(y_trainval).value_counts().min()
cv = StratifiedKFold(n_splits=min(5, min_class_size), shuffle=True, random_state=42)

results = {}

# ========== RANDOM FOREST ==========
print("🌳 Entraînement RandomForest...")
rf_model = RandomForestClassifier(n_estimators=150, max_depth=20, random_state=42)
rf_pred_cv = cross_val_predict(rf_model, X_trainval, y_trainval, cv=cv)
rf_cv_acc = accuracy_score(y_trainval, rf_pred_cv)
rf_model.fit(X_trainval, y_trainval)
rf_test_acc = accuracy_score(y_test, rf_model.predict(X_test))
results["RandomForest"] = (rf_cv_acc, rf_test_acc, rf_model)

# ========== LIGHTGBM ==========
print("💡 Entraînement LightGBM...")
lgb_model = LGBMClassifier(n_estimators=150, max_depth=20, random_state=42, verbose=-1)
lgb_pred_cv = cross_val_predict(lgb_model, X_trainval, y_trainval, cv=cv)
lgb_cv_acc = accuracy_score(y_trainval, lgb_pred_cv)
lgb_model.fit(X_trainval, y_trainval)
lgb_test_acc = accuracy_score(y_test, lgb_model.predict(X_test))
results["LightGBM"] = (lgb_cv_acc, lgb_test_acc, lgb_model)

# ========== XGBOOST ==========
print("🚀 Entraînement XGBoost...")
xgb_model = XGBClassifier(n_estimators=150, max_depth=20, use_label_encoder=False, eval_metric="mlogloss", verbosity=0, random_state=42)
xgb_pred_cv = cross_val_predict(xgb_model, X_trainval, y_trainval, cv=cv)
xgb_cv_acc = accuracy_score(y_trainval, xgb_pred_cv)
xgb_model.fit(X_trainval, y_trainval)
xgb_test_acc = accuracy_score(y_test, xgb_model.predict(X_test))
results["XGBoost"] = (xgb_cv_acc, xgb_test_acc, xgb_model)

# 📊 Résumé des scores
print("\n📊 Résultats finaux sur le jeu de test :\n")
for name, (cv_score, test_score, _) in results.items():
    print(f"🔹 {name} - CV : {cv_score * 100:.2f}% | Test : {test_score * 100:.2f}%")

# 🏆 Sélection du meilleur modèle
best_model_name = max(results, key=lambda k: results[k][1])
best_test_score = results[best_model_name][1]
print(f"\n🏆 Meilleur modèle sur test : {best_model_name} ({best_test_score * 100:.2f}%)")

# 📉 Matrice de confusion
print("\n📈 Génération de la matrice de confusion...")
best_model = results[best_model_name][2]
y_test_labels = le.inverse_transform(y_test)
y_pred_labels = le.inverse_transform(best_model.predict(X_test))
cm = confusion_matrix(y_test_labels, y_pred_labels)
cm_percent = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis] * 100
labels = [f"{count}\n{percent:.1f}%" for count, percent in zip(cm.flatten(), cm_percent.flatten())]
labels = np.asarray(labels).reshape(cm.shape)

# 📁 Création des dossiers dans ia_cms_detection
os.makedirs("ia_cms_detection/results", exist_ok=True)
os.makedirs("ia_cms_detection/models", exist_ok=True)

# Sauvegarde de la matrice de confusion
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=labels, fmt="", cmap="Oranges",
            xticklabels=le.classes_, yticklabels=le.classes_)
plt.title(f"{best_model_name} - Matrice de confusion (Test)")
plt.xlabel("Prédit")
plt.ylabel("Réel")
plt.tight_layout()
plt.savefig(f"ia_cms_detection/results/confusion_matrix_{best_model_name.lower()}_test.png")
plt.close()

# 📈 Graphe comparatif des scores
print("📊 Génération du graphe comparatif des scores...")
model_names = list(results.keys())
cv_scores = [results[m][0] for m in model_names]
test_scores = [results[m][1] for m in model_names]

plt.figure(figsize=(8, 5))
x = np.arange(len(model_names))

plt.plot(x, cv_scores, marker='o', label='Score CV', color='royalblue')
plt.plot(x, test_scores, marker='s', label='Score Test', color='darkorange')

for i in range(len(model_names)):
    plt.text(x[i] - 0.1, cv_scores[i] + 0.01, f"{cv_scores[i]*100:.1f}%", color='royalblue')
    plt.text(x[i] - 0.1, test_scores[i] - 0.05, f"{test_scores[i]*100:.1f}%", color='darkorange')

plt.xticks(x, model_names)
plt.ylim(0, 1.05)
plt.title("Comparaison des scores CV vs Test")
plt.xlabel("Modèles")
plt.ylabel("Accuracy")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("ia_cms_detection/results/model_comparison_scores.png")
plt.close()

# 💾 Sauvegarde du modèle, des features et de l'encoder
joblib.dump(best_model, "ia_cms_detection/models/cms_detector_model.pkl")
joblib.dump(X.columns.tolist(), "ia_cms_detection/models/feature_names.pkl")
joblib.dump(le, "ia_cms_detection/models/label_encoder.pkl")
print(f"\n💾 Modèle {best_model_name} sauvegardé avec ses features et le LabelEncoder.")
