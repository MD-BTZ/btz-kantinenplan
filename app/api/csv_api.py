# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import APIRouter, HTTPException, Body, Depends
from fastapi.responses import JSONResponse
import csv
import os

from app.core.security import manager

# Create API router instance / API-Router-Instanz erstellen
router = APIRouter()

# Path to the CSV file / Pfad zur CSV-Datei
CSV_PATH = os.path.join(os.path.dirname(__file__), '..', 'canteen.csv')

# Get all rows from the CSV file / Alle Zeilen aus der CSV-Datei abrufen
@router.get("/plan")
def get_plan(current_user=Depends(manager)):
    try:
        with open(CSV_PATH, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)
        return JSONResponse(content=rows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Lesen der CSV: {e}")

# Update the CSV file with the new data / CSV-Datei mit den neuen Daten aktualisieren
@router.post("/plan")
def update_plan(data: list = Body(...), current_user=Depends(manager)):
    if not data:
        raise HTTPException(status_code=400, detail="Keine Daten erhalten.")
    try:
        fieldnames = ['datum', 'menu1', 'menu2', 'dessert']
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow({fn: row.get(fn, '') for fn in fieldnames})
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Schreiben der CSV: {e}")
