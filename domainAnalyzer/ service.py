from fastapi import APIRouter, UploadFile, File, Form
from fastapi.responses import JSONResponse
from threading import Thread
import uuid
import json
import csv
from .app import analyze_domains_task, save_analysis, get_analysis, get_results

router = APIRouter(prefix="/domain-analyzer", tags=["Domain Analyzer"])

@router.post("/upload")
async def upload_domains(file: UploadFile = File(...), name: str = Form(None)):
    """Démarrer une nouvelle analyse de domaine"""
    content = await file.read()
    domains = [line.strip() for line in content.decode("utf-8").split("\n") if line.strip()]
    domains = list(dict.fromkeys(domains))  # dédupliquer
    
    if not domains:
        return JSONResponse({"error": "No valid domains found"}, status_code=400)

    analysis_id = str(uuid.uuid4())
    analysis_name = name or file.filename
    save_analysis(analysis_id, analysis_name, len(domains))

    # lancer en thread
    thread = Thread(target=analyze_domains_task, args=(analysis_id, domains))
    thread.daemon = True
    thread.start()

    return {
        "analysis_id": analysis_id,
        "total_domains": len(domains),
        "message": "Analysis started"
    }

@router.get("/status/{analysis_id}")
async def get_status(analysis_id: str):
    """Obtenir le statut d'une analyse"""
    analysis = get_analysis(analysis_id)
    if not analysis:
        return JSONResponse({"error": "Analysis not found"}, status_code=404)
    return analysis

@router.get("/results/{analysis_id}")
async def get_results_api(analysis_id: str):
    """Obtenir les résultats JSON"""
    results = get_results(analysis_id)
    return results
