from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json
from pyspark.sql.types import (
    StructType,
    StructField,
    StringType,
    DoubleType,
    IntegerType
)

import joblib
import numpy as np
# ------------------------------------------------------------
# SPARK SESSION
# ------------------------------------------------------------

spark = (
    SparkSession.builder
    .appName("RealTimeIDS-Kafka")
    .master("local[2]")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")
# ------------------------------------------------------------
# LOAD ML MODEL ARTIFACTS
# ------------------------------------------------------------

MODEL_DIR = "model_artifacts"

model = joblib.load(f"{MODEL_DIR}/best_model.pkl")
scaler = joblib.load(f"{MODEL_DIR}/scaler.pkl")
label_encoder = joblib.load(f"{MODEL_DIR}/label_encoder.pkl")
feature_columns = joblib.load(f"{MODEL_DIR}/feature_columns.pkl")

print("ML model loaded into Spark")
print("Features:", len(feature_columns))
print("Classes:", len(label_encoder.classes_))
# ------------------------------------------------------------
# FLOW MESSAGE SCHEMA
# Must match the fields sent by realtime_ids.py
# ------------------------------------------------------------

schema = StructType([
    StructField("Destination Port", IntegerType(), True),
    StructField("Flow Duration", DoubleType(), True),

    StructField("Total Fwd Packets", IntegerType(), True),
    StructField("Total Backward Packets", IntegerType(), True),

    StructField("Total Length of Fwd Packets", IntegerType(), True),
    StructField("Total Length of Bwd Packets", IntegerType(), True),

    StructField("Fwd Packet Length Max", IntegerType(), True),
    StructField("Fwd Packet Length Min", IntegerType(), True),
    StructField("Fwd Packet Length Mean", DoubleType(), True),
    StructField("Fwd Packet Length Std", DoubleType(), True),

    StructField("Bwd Packet Length Max", IntegerType(), True),
    StructField("Bwd Packet Length Min", IntegerType(), True),
    StructField("Bwd Packet Length Mean", DoubleType(), True),
    StructField("Bwd Packet Length Std", DoubleType(), True),

    StructField("Flow Bytes/s", DoubleType(), True),
    StructField("Flow Packets/s", DoubleType(), True),

    StructField("Flow IAT Mean", DoubleType(), True),
    StructField("Flow IAT Std", DoubleType(), True),
    StructField("Flow IAT Max", DoubleType(), True),
    StructField("Flow IAT Min", DoubleType(), True),

    StructField("Fwd IAT Total", DoubleType(), True),
    StructField("Fwd IAT Mean", DoubleType(), True),
    StructField("Fwd IAT Std", DoubleType(), True),
    StructField("Fwd IAT Max", DoubleType(), True),
    StructField("Fwd IAT Min", DoubleType(), True),

    StructField("Bwd IAT Total", DoubleType(), True),
    StructField("Bwd IAT Mean", DoubleType(), True),
    StructField("Bwd IAT Std", DoubleType(), True),
    StructField("Bwd IAT Max", DoubleType(), True),
    StructField("Bwd IAT Min", DoubleType(), True),

    StructField("Fwd PSH Flags", IntegerType(), True),
    StructField("Fwd URG Flags", IntegerType(), True),

    StructField("Fwd Header Length", IntegerType(), True),
    StructField("Bwd Header Length", IntegerType(), True),

    StructField("Fwd Packets/s", DoubleType(), True),
    StructField("Bwd Packets/s", DoubleType(), True),

    StructField("Min Packet Length", IntegerType(), True),
    StructField("Max Packet Length", IntegerType(), True),
    StructField("Packet Length Mean", DoubleType(), True),
    StructField("Packet Length Std", DoubleType(), True),
    StructField("Packet Length Variance", DoubleType(), True),

    StructField("FIN Flag Count", IntegerType(), True),
    StructField("SYN Flag Count", IntegerType(), True),
    StructField("RST Flag Count", IntegerType(), True),
    StructField("PSH Flag Count", IntegerType(), True),
    StructField("ACK Flag Count", IntegerType(), True),
    StructField("URG Flag Count", IntegerType(), True),
    StructField("CWE Flag Count", IntegerType(), True),
    StructField("ECE Flag Count", IntegerType(), True),

    StructField("Down/Up Ratio", DoubleType(), True),
    StructField("Average Packet Size", DoubleType(), True),

    StructField("Avg Fwd Segment Size", DoubleType(), True),
    StructField("Avg Bwd Segment Size", DoubleType(), True),

    StructField("Subflow Fwd Packets", IntegerType(), True),
    StructField("Subflow Fwd Bytes", IntegerType(), True),
    StructField("Subflow Bwd Packets", IntegerType(), True),
    StructField("Subflow Bwd Bytes", IntegerType(), True),

    StructField("Init_Win_bytes_forward", IntegerType(), True),
    StructField("Init_Win_bytes_backward", IntegerType(), True),

    StructField("act_data_pkt_fwd", IntegerType(), True),
    StructField("min_seg_size_forward", IntegerType(), True),

    StructField("Active Mean", DoubleType(), True),
    StructField("Active Std", DoubleType(), True),
    StructField("Active Max", DoubleType(), True),
    StructField("Active Min", DoubleType(), True),

    StructField("Idle Mean", DoubleType(), True),
    StructField("Idle Std", DoubleType(), True),
    StructField("Idle Max", DoubleType(), True),
    StructField("Idle Min", DoubleType(), True)
])
# ------------------------------------------------------------
# READ FROM KAFKA
# ------------------------------------------------------------

kafka_stream = (
    spark.readStream
    .format("kafka")
    .option("kafka.bootstrap.servers", "localhost:9092")
    .option("subscribe", "network-flows")
    .option("startingOffsets", "earliest")
    .load()
)

# Kafka stores message values as binary.
# Convert the value to a string, then parse the JSON.

flows = (
    kafka_stream
    .selectExpr("CAST(value AS STRING) AS json_value")
    .select(from_json(col("json_value"), schema).alias("flow"))
    .select("flow.*")
)

# ------------------------------------------------------------
# PROCESS FLOW RECORDS + ML INFERENCE
# ------------------------------------------------------------

processed_flows = flows.filter(
    col("Flow Duration") >= 0
)


def process_batch(batch_df, batch_id):

    print(f"\n===== Spark Batch {batch_id} =====")

    if batch_df.count() == 0:
        return

    # Select the exact 69 features used during model training
    feature_df = batch_df.select(*feature_columns)

    # Convert Spark DataFrame to NumPy
    X = np.array(feature_df.collect(), dtype=float)

    # Apply the same scaler used during training
    X_scaled = scaler.transform(X)

    # ML prediction
    predictions = model.predict(X_scaled)

    # Convert numeric predictions to attack labels
    labels = label_encoder.inverse_transform(predictions)

    # Add predictions back to the Spark DataFrame
    result_rows = batch_df.collect()

    results = []

    for row, label in zip(result_rows, labels):
        results.append(
            (
                row["Destination Port"],
                row["Flow Duration"],
                row["Total Fwd Packets"],
                row["Total Backward Packets"],
                label
            )
        )

    result_schema = StructType([
        StructField("Destination Port", IntegerType(), True),
        StructField("Flow Duration", DoubleType(), True),
        StructField("Total Fwd Packets", IntegerType(), True),
        StructField("Total Backward Packets", IntegerType(), True),
        StructField("Prediction", StringType(), True)
    ])

    result_df = spark.createDataFrame(
        results,
        result_schema
    )

    result_df.show(truncate=False)

    print("Flows processed:", len(results))

# ------------------------------------------------------------
# START STREAM
# ------------------------------------------------------------

query = (
    processed_flows.writeStream
    .foreachBatch(process_batch)
    .outputMode("append")
    .option("checkpointLocation", "checkpoint/kafka_ids")
    .start()
)

print("Spark Kafka stream is running. Press Ctrl+C to stop.")
query.awaitTermination()