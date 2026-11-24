import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database, app as app_module


def make_client(tmp_path):
    database.DB_PATH = str(tmp_path / "test.db")
    database.init_db()
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_pages_load(tmp_path):
    c = make_client(tmp_path)
    for url in ["/", "/history", "/tips"]:
        assert c.get(url).status_code == 200


def test_analyze_saves_to_history_and_clears(tmp_path):
    c = make_client(tmp_path)
    r = c.post("/analyze", json={"message": "You won a lottery! Send OTP now http://bit.ly/a"})
    assert r.status_code == 200 and r.get_json()["level"] == "High Risk"
    assert b"lottery" in c.get("/history").data
    c.post("/history/clear")
    assert b"No messages checked yet" in c.get("/history").data


def test_empty_message_rejected(tmp_path):
    c = make_client(tmp_path)
    assert c.post("/analyze", json={"message": ""}).status_code == 400
