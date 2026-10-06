import json
import time
import uuid
from pathlib import Path

INPUT_DIR = Path("input")
INPUT_DIR.mkdir(exist_ok=True)

test_flows = [
    {
        "Flow_Duration": 0.45,
        "Total_Fwd_Packets": 10,
        "Total_Bwd_Packets": 8,
        "Total_Fwd_Bytes": 1500,
        "Total_Bwd_Bytes": 2300,
        "Protocol": 6,
        "Destination_Port": 443
    },
    {
        "Flow_Duration": 0.02,
        "Total_Fwd_Packets": 3,
        "Total_Bwd_Packets": 1,
        "Total_Fwd_Bytes": 180,
        "Total_Bwd_Bytes": 60,
        "Protocol": 6,
        "Destination_Port": 22
    }
]

for flow in test_flows:
    filename = INPUT_DIR / f"flow_{uuid.uuid4().hex}.json"

    with filename.open("w") as f:
        json.dump(flow, f)

    print("Created:", filename)

    time.sleep(2)