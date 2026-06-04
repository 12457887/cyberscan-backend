# db/mongo.py
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB")

client = MongoClient(MONGODB_URI)

# Base de données principale
db = client[MONGODB_DB]

# Collections scan_prod
scan_drupal_collection = db["scan_drupal"]
scan_wp_collection = db["scan_wordpress"]
scan_presta_collection = db["scan_prestashop"]
scan_generic_collection = db["scan_generic"]
scan_network_collection = db["scan_network"]
scan_ssl_collection = db["scan_ssl"]
free_scan_emails_collection = db["free_scan_emails"]

# Base de données medianet
medianet_db = client["medianet_db"]
medianet_dehashed_usage_collection = medianet_db["medianet_dehashed_usage"]
scan_medianet_collection = medianet_db["scan_medianet"]
