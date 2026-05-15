#!/usr/bin/env python3
"""
Retrieve and save threat model from API
Usage: python retrieve_model.py
"""

import requests
import json
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000"
MODEL_ID = "6b33524f-69e8-48f6-a03e-651234bed4cb"  # Your model ID from the logs

def retrieve_threat_model():
    """Retrieve threat model from API and save to JSON file"""

    print(f"Retrieving threat model {MODEL_ID}...")

    try:
        # Get the threat model
        response = requests.get(f"{API_URL}/api/models/{MODEL_ID}")

        if response.status_code == 200:
            threat_model = response.json()

            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_model_{MODEL_ID}_{timestamp}.json"

            with open(filename, 'w') as f:
                json.dump(threat_model, f, indent=2)

            print(f"✅ Threat model saved to: {filename}")

            # Print summary
            print("\n📊 Summary:")
            print(f"  - Model ID: {threat_model.get('model_id')}")
            print(f"  - Total Vulnerabilities: {len(threat_model.get('vulnerabilities', []))}")
            print(f"  - Top Vulnerabilities: {len(threat_model.get('top_vulnerabilities', []))}")
            print(f"  - Attack Paths: {len(threat_model.get('attack_paths', []))}")
            print(f"  - Confidence Score: {threat_model.get('confidence_score', 0) * 100:.1f}%")

            # Check for Mermaid diagrams
            if threat_model.get('threat_graph') and threat_model['threat_graph'].get('dfd_diagram'):
                print("\n📈 DFD Diagram: Available")
                with open(f"dfd_diagram_{timestamp}.mermaid", 'w') as f:
                    f.write(threat_model['threat_graph']['dfd_diagram'])
                print(f"  - Saved to: dfd_diagram_{timestamp}.mermaid")

            return threat_model

        elif response.status_code == 404:
            print(f"❌ Model not found: {MODEL_ID}")
            print("The model may have been lost when the server restarted.")
            return None
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
            return None

    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API. Make sure the server is running:")
        print("   python -m uvicorn src.api.app_improved:app --reload --host 0.0.0.0 --port 8000")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

if __name__ == "__main__":
    retrieve_threat_model()