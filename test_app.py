from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

print("Testing GET / ...")
r1 = client.get("/")
assert r1.status_code == 200, f"GET / failed: {r1.status_code}"
assert "CyberShield AI" in r1.text

print("Testing GET /analytics ...")
r2 = client.get("/analytics")
assert r2.status_code == 200, f"GET /analytics failed: {r2.status_code}"
assert "Model Accuracy" in r2.text

print("Testing GET /about ...")
r3 = client.get("/about")
assert r3.status_code == 200, f"GET /about failed: {r3.status_code}"
assert "RFC 3986" in r3.text

print("Testing POST /api/analyze with phishing sample ...")
payload_phish = {
    "text": "URGENT: Your PayPal account has been permanently restricted due to unauthorized login attempts. To restore access and verify your identity, please confirm your password immediately within 24 hours.",
    "url": "http://paypal-security-update.com/login"
}
r4 = client.post("/api/analyze", json=payload_phish)
assert r4.status_code == 200, f"Analyze failed: {r4.status_code}"
data4 = r4.json()
print("Phishing Result:", data4["verdict"], "Score:", data4["overall_score"])
assert data4["verdict"] == "Malicious", f"Expected Malicious, got {data4['verdict']}"

print("Testing POST /api/analyze with safe sample ...")
payload_safe = {
    "text": "Hi team, please find attached the quarterly engineering sprint retrospective notes and agenda for tomorrow morning's standup meeting.",
    "url": "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit"
}
r5 = client.post("/api/analyze", json=payload_safe)
assert r5.status_code == 200, f"Safe analyze failed: {r5.status_code}"
data5 = r5.json()
print("Safe Result:", data5["verdict"], "Score:", data5["overall_score"])
assert data5["verdict"] == "Safe", f"Expected Safe, got {data5['verdict']}"

print("Testing GET /api/analytics ...")
r6 = client.get("/api/analytics")
assert r6.status_code == 200
data6 = r6.json()
print("Accuracy:", data6["metrics"]["accuracy"], "%")
print("Top Phishing Features:", [f["word"] for f in data6["top_features"]["phishing"][:4]])

print("Testing GET /api/health ...")
r7 = client.get("/api/health")
assert r7.status_code == 200
print("Health status:", r7.json())

print("\n>>> ALL TEST CASES PASSED SUCCESSFULLY! <<<")
