# api/

FastAPI backend exposing the investigation orchestrator over Server-Sent
Events (SSE), so the React UI can stream agent progress and findings in
real time.

- `main.py` — FastAPI app, SSE endpoint
- `schemas.py` — request/response models

Implemented in Phase 7.
