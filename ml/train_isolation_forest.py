from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"

RESULTS_DIR.mkdir(exist_ok=True)

BASELINE_FILE = DATA_DIR / "baseline_features.csv"
EVALUATION_FILE = DATA_DIR / "evaluation_features.csv"

FEATURES = [
    "total_requests",
    "failed_login_ratio",
    "admin_ratio",
    "unique_paths"
]


# --------------------------------------------------
# 1. Load datasets
# --------------------------------------------------

baseline_df = pd.read_csv(BASELINE_FILE)
evaluation_df = pd.read_csv(EVALUATION_FILE)

print(f"Baseline profiles: {len(baseline_df)}")
print(f"Evaluation profiles: {len(evaluation_df)}")


# --------------------------------------------------
# 2. Select numerical behavioural features
# --------------------------------------------------

X_train = baseline_df[FEATURES]
X_evaluation = evaluation_df[FEATURES]


# --------------------------------------------------
# 3. Train Isolation Forest on NORMAL baseline only
# --------------------------------------------------

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42
)

model.fit(X_train)


# --------------------------------------------------
# 4. Calculate anomaly scores
# --------------------------------------------------

baseline_df["anomaly_score"] = -model.score_samples(X_train)

evaluation_df["anomaly_score"] = -model.score_samples(X_evaluation)


# --------------------------------------------------
# 5. Create threshold from baseline behaviour
#
# mean + 3 standard deviations means that a profile
# must be substantially more unusual than the
# normal training population.
# --------------------------------------------------

baseline_mean = baseline_df["anomaly_score"].mean()
baseline_std = baseline_df["anomaly_score"].std()

threshold = baseline_mean + (3 * baseline_std)

evaluation_df["is_anomaly"] = (
    evaluation_df["anomaly_score"] > threshold
)


# --------------------------------------------------
# 6. Sort evaluation results by suspiciousness
# --------------------------------------------------

evaluation_df = evaluation_df.sort_values(
    by="anomaly_score",
    ascending=False
)


# --------------------------------------------------
# 7. Save results
# --------------------------------------------------

baseline_df.to_csv(
    RESULTS_DIR / "baseline_scored.csv",
    index=False
)

evaluation_df.to_csv(
    RESULTS_DIR / "evaluation_scored.csv",
    index=False
)


# --------------------------------------------------
# 8. Display results
# --------------------------------------------------

print()
print(f"Baseline mean anomaly score: {baseline_mean:.4f}")
print(f"Baseline standard deviation: {baseline_std:.4f}")
print(f"Anomaly threshold: {threshold:.4f}")

print()
print("Most unusual evaluation profiles:")
print(
    evaluation_df[
        [
            "source_ip",
            "total_requests",
            "failed_login_ratio",
            "admin_ratio",
            "unique_paths",
            "anomaly_score",
            "is_anomaly"
        ]
    ].head(10).to_string(index=False)
)