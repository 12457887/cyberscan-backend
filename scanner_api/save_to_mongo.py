from DB.database import db
from pymongo.errors import PyMongoError
import logging
from datetime import datetime  # ✅ pour ajouter la date
logger = logging.getLogger(__name__)
from bson import ObjectId

def save_scan_json_to_mongo(
    data: dict,
    scan_id: str = None,
    from_dict: bool = False,
    collection_override: str | None = None,
) -> str:
    if not data:
        logger.error("❌ Données vides, insertion annulée.")
        raise ValueError("Données vides, impossible d'insérer dans MongoDB.")
    
    try:
        if collection_override:
            collection_name = collection_override
        else:
            cms_type = (data.get("cms_type") or "").lower()
            if not cms_type:
                raise ValueError("cms_type manquant dans les données.")

            # Cas particulier: inconnu → on stocke dans scan_generic
            if cms_type not in ["wordpress", "prestashop", "drupal", "inconnu"]:
                cms_type = "inconnu"

            collection_name = "scan_generic" if cms_type == "inconnu" else f"scan_{cms_type}"

        collection = db[collection_name]

        effective_scan_id = scan_id or data.get("scan_id")
        if from_dict and effective_scan_id:
            now = datetime.utcnow()
            update_data = dict(data)
            update_data.pop("_id", None)
            update_data.pop("record_type", None)
            created_at = update_data.pop("created_at", None)
            update_data["scan_id"] = effective_scan_id
            update_data["updated_at"] = now

            logger.info(f"[MongoDB] Mise à jour dans la collection: {collection_name} pour scan_id={effective_scan_id}")
            result = collection.update_one(
                {"scan_id": effective_scan_id},
                {"$set": update_data, "$setOnInsert": {"created_at": created_at or now}},
                upsert=True,
            )
            if result.upserted_id:
                logger.info(f"[MongoDB] Upsert réussi dans {collection_name} avec ID {result.upserted_id}")
                return str(result.upserted_id)

            existing = collection.find_one({"scan_id": effective_scan_id}, {"_id": 1})
            if existing and existing.get("_id"):
                return str(existing.get("_id"))
            raise ValueError(f"Scan {effective_scan_id} introuvable après update")

        if "created_at" not in data:
            data["created_at"] = datetime.utcnow()

        logger.info(f"[MongoDB] Enregistrement dans la collection: {collection_name} pour scan_id={scan_id}")
        result = collection.insert_one(data)
        logger.info(f"[MongoDB] Sauvegarde réussie dans {collection_name} avec ID {result.inserted_id}")
        return str(result.inserted_id)

    except PyMongoError as e:
        logger.error(f"[MongoDB] Erreur d'insertion pour scan_id={scan_id} : {str(e)}")
        raise


def get_scan_from_mongo(scan_id: str, include_preview: bool = True) -> dict:
    try:
        # Recherche dans toutes les collections possibles - on accepte soit le champ `scan_id`,
        # soit un identifiant Mongo `_id` passé depuis le frontend (mongo_report_id).
        collections = ["scan_wordpress", "scan_prestashop", "scan_drupal", "scan_generic", "scan_medianet", "cybershield"]
        if include_preview:
            collections.append("scan-gratuit")

        for collection_name in collections:
            collection = db[collection_name]
            # 1) Cherche par champ scan_id (UUID généré par le backend)
            result = collection.find_one({"scan_id": scan_id})
            if result:
                return result

            # 2) Si non trouvé, et si scan_id ressemble à un ObjectId, cherche par _id
            try:
                oid = ObjectId(scan_id)
            except Exception:
                oid = None

            if oid:
                result = collection.find_one({"_id": oid})
                if result:
                    return result

        return None
    except PyMongoError as e:
        logger.error(f"[MongoDB] Erreur lors de la récupération du scan : {str(e)}")
        return None


def test_mongo_connection() -> bool:
    try:
        db.list_collection_names()
        return True
    except Exception as e:
        logger.error(f"[MongoDB] Connexion échouée : {e}")
        return False
