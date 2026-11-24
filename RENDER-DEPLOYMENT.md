# Deploy Scam Spotter on Render

1. Create a GitHub repository named `scam-spotter`.
2. Upload the *contents* of this folder to the repository root (app.py, database.py, detector.py, requirements.txt, templates/, static/, render.yaml).
3. In Render, choose New > Blueprint if you want Render to read `render.yaml`, or New > Web Service and connect the repository.
4. For a Web Service, use:
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
5. Deploy.

Notes:
- This app uses SQLite, not MySQL. The database file is created automatically.
- On Render's free service, local files are ephemeral; SQLite history can be lost when the service restarts or is redeployed. The detector itself does not require a database to analyze messages.
- The app stores submitted message text in its history database. Avoid entering real personal, banking, or confidential messages in a public demo.
- The project is rule-based and educational; a "Safe" result does not guarantee a message is genuine.
