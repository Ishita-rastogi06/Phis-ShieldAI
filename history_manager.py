import pandas as pd
import os
from datetime import datetime

HISTORY_FILE = "scan_history.csv"

def save_scan(scan_type, target, result, risk):

    new_entry = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Type": scan_type,
        "Target": target,
        "Result": result,
        "Risk Score": risk
    }

    if os.path.exists(HISTORY_FILE):

        df = pd.read_csv(HISTORY_FILE)

        df = pd.concat(
            [df, pd.DataFrame([new_entry])],
            ignore_index=True
        )

    else:

        df = pd.DataFrame([new_entry])

    df.to_csv(HISTORY_FILE, index=False)


def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)


def load_history():
    if os.path.exists(HISTORY_FILE):

        return pd.read_csv(HISTORY_FILE)

    return pd.DataFrame(
        columns=[
            "Timestamp",
            "Type",
            "Target",
            "Result",
            "Risk Score"
        ]
    )