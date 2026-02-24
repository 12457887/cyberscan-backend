# db/mongo.py
from pymongo import MongoClient

client = MongoClient("mongodb+srv://bennasserrania62:ycUYcyfVNtqjBubG@cluster0.fgwpmm3.mongodb.net/?retryWrites=true&w=majority")

# Base de données
db = client["cms_scan_db"]

# Collection où on stocke les résultats
scan_drupal_collection = db["scan_drupal"]
scan_wp_collection = db["scan_wordpress"]
scan_presta_collection = db["scan_prestashop"]
scan_generic_collection = db["scan_generic"]
free_scan_emails_collection = db["free_scan_emails"]
