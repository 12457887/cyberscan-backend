import requests

# === CONFIGURATION ===
backend_url = "http://localhost:8000/predict-from-file"  # Change si ton backend est en prod
fichier_xlsx = "backend/Ciberianta_Domaines_Gob.mx_0725_v1.0.xlsx"  # Ton fichier avec la colonne "url"

# === ENVOI DU FICHIER ===
with open(fichier_xlsx, "rb") as f:
    files = {"file": (fichier_xlsx, f, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    response = requests.post(backend_url, files=files)

# === RÉPONSE ===
if response.status_code == 200:
    output_filename = "Ciberianta_Domaines_type.xlsx"
    with open(output_filename, "wb") as out:
        out.write(response.content)
    print(f"✅ Résultat enregistré dans : {output_filename}")
else:
    print(f"❌ Erreur {response.status_code} : {response.text}")