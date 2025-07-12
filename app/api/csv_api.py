# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
import csv
import os
import portalocker
import logging
from app.core import csrf_protected
from app.core.security import get_current_user

# Create API router instance / API-Router-Instanz erstellen
router = APIRouter()

# Path to the CSV file / Pfad zur CSV-Datei
CSV_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'canteen.csv')

# Get all rows from the CSV file / Alle Zeilen aus der CSV-Datei abrufen
@router.get("/plan")
def get_plan(current_user=Depends(get_current_user)):
    logging.debug(f"Authenticated user: {current_user}")  # Log authenticated user
    try:
        with open(CSV_PATH, 'r', newline='', encoding='utf-8') as csvfile:
            portalocker.lock(csvfile, portalocker.LOCK_SH)
            reader = csv.DictReader(csvfile)
            rows = list(reader)
            portalocker.unlock(csvfile)
        return JSONResponse(content=rows)
    except Exception as e:
        logging.error(f"Error reading CSV: {e}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Lesen der CSV: {e}")

# Update the CSV file with the new data / CSV-Datei mit den neuen Daten aktualisieren
@router.post("/plan", response_model=dict)
async def update_plan(plan_data: dict, response: Response, user=Depends(get_current_user), _=Depends(csrf_protected)):
    logging.debug(f"Authenticated user: {user}")  # Log authenticated user
    if not plan_data:
        raise HTTPException(status_code=400, detail="Keine Daten erhalten.")
    try:
        fieldnames = ['datum', 'menu1', 'menu2', 'dessert']
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as csvfile:
            portalocker.lock(csvfile, portalocker.LOCK_EX)
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in plan_data:
                writer.writerow({fn: row.get(fn, '') for fn in fieldnames})
            portalocker.unlock(csvfile)
        return {"status": "success"}
    except Exception as e:
        logging.error(f"Error writing CSV: {e}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Schreiben der CSV: {e}")
