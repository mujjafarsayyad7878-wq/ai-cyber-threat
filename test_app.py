from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

print("1. Testing GET / (Home Dashboard)...")
r1 = client.get("/")
assert r1.status_code == 200, f"GET / failed: {r1.status_code}"
assert "CyberShield AI" in r1.text
assert "Live Detector" in r1.text

print("2. Testing GET /analytics (ML Telemetry)...")
r2 = client.get("/analytics")
assert r2.status_code == 200, f"GET /analytics failed: {r2.status_code}"
assert "Model Accuracy" in r2.text
assert "Confusion Matrix" in r2.text

print("3. Testing GET /about (Technical Specs & SOP)...")
r3 = client.get("/about")
assert r3.status_code == 200, f"GET /about failed: {r3.status_code}"
assert "RFC 3986" in r3.text
assert "Multinomial Naive Bayes" in r3.text

print("4. Testing POST /api/analyze with PayPal Phishing...")
payload_phish = {
    "text": "URGENT: Your PayPal account has been permanently restricted due to unauthorized login attempts. To restore access and verify your identity, please confirm your password immediately within 24 hours.",
    "url": "http://paypal-security-update.com/login"
}
r4 = client.post("/api/analyze", json=payload_phish)
assert r4.status_code == 200, f"Analyze failed: {r4.status_code}"
data4 = r4.json()
print("   Phishing Result -> Verdict:", data4["verdict"], "| Score:", data4["overall_score"])
assert data4["verdict"] == "Malicious", f"Expected Malicious, got {data4['verdict']}"
assert data4["overall_score"] >= 71
assert len(data4["recommendations"]) > 0

print("5. Testing POST /api/analyze with Safe Corporate Communication...")
payload_safe = {
    "text": "Hi team, please find attached the quarterly engineering sprint retrospective notes and agenda for tomorrow morning's standup meeting.",
    "url": "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit"
}
r5 = client.post("/api/analyze", json=payload_safe)
assert r5.status_code == 200, f"Safe analyze failed: {r5.status_code}"
data5 = r5.json()
print("   Safe Result -> Verdict:", data5["verdict"], "| Score:", data5["overall_score"])
assert data5["verdict"] == "Safe", f"Expected Safe, got {data5['verdict']}"
assert data5["overall_score"] <= 35

print("6. Testing POST /api/analyze with Naked IP Hostname...")
payload_ip = {
    "text": "",
    "url": "http://185.220.101.45:8080/bofa-verification/auth"
}
r_ip = client.post("/api/analyze", json=payload_ip)
assert r_ip.status_code == 200
data_ip = r_ip.json()
print("   Naked IP Result -> Verdict:", data_ip["verdict"], "| Score:", data_ip["overall_score"])
assert data_ip["url_analysis"]["is_ip"] is True
assert data_ip["overall_score"] >= 40

print("7. Testing GET /api/analytics & /api/model-stats...")
r6 = client.get("/api/analytics")
assert r6.status_code == 200
data6 = r6.json()
print("   Accuracy:", data6["metrics"]["accuracy"], "%")
print("   Top Phishing Features:", [f["word"] for f in data6["top_features"]["phishing"][:4]])

r_stats = client.get("/api/model-stats")
assert r_stats.status_code == 200
assert r_stats.json()["metrics"]["accuracy"] == data6["metrics"]["accuracy"]

print("8. Testing GET /api/sample-data & /api/quick-samples...")
r_sample = client.get("/api/sample-data")
assert r_sample.status_code == 200
samples = r_sample.json()
assert "phishing_email" in samples
assert "safe_corporate_message" in samples

r_quick = client.get("/api/quick-samples")
assert r_quick.status_code == 200
assert r_quick.json() == samples

print("9. Testing GET /api/health...")
r7 = client.get("/api/health")
assert r7.status_code == 200
assert r7.json()["status"] == "healthy"
print("   Health status:", r7.json())

print("\n>>> ALL 9 INTEGRATION TEST SUITES PASSED FLAWLESSLY! <<<")
