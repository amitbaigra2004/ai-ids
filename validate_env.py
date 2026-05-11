import sys

packages = {
    "torch": "PyTorch",
    "sklearn": "Scikit-learn",
    "pandas": "Pandas",
    "numpy": "NumPy",
    "scapy": "Scapy",
    "fastapi": "FastAPI",
    "uvicorn": "Uvicorn",
    "streamlit": "Streamlit",
}

print("=" * 40)
print("AI-IDS Environment Validation")
print("=" * 40)

all_ok = True
for module, name in packages.items():
    try:
        __import__(module)
        print(f"  ✅  {name}")
    except ImportError:
        print(f"  ❌  {name} — NOT FOUND")
        all_ok = False

print("=" * 40)
if all_ok:
    print("✅ All good! Ready for Day 2.")
else:
    print("❌ Some packages missing. Re-run: pip install -r requirements.txt")
