"""Bounded CSV-to-Parquet export for already verified experiment artifacts."""

from __future__ import annotations

import csv
from pathlib import Path

from .audit import TIME_FIELDS


SPLIT_FIELDS = ["variant", "record_id", "source_file_index", "source_record", "event_start", "event_end", "source_label", "attempted_category", "binary_label", "family", "partition", "disposition", "reason", "duplicate_group_id"]
PREDICTION_FIELDS = ["variant", "model_id", "model", "record_id", "partition", "source_label", "family", "binary_label", "attack_score", "threshold", "prediction", "class_prediction", "event_start"]


def export_parquet(source_dir: str | Path, target_dir: str | Path) -> list[str]:
    """Write into an unpublished report stage; preserve IDs, nulls and floats.

    Timestamps stay as recorded ISO strings. Categories, labels and empty reasons
    stay strings rather than being inferred as integers/nulls. Inputs must have
    already passed report integrity validation; no serialized model is loaded.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    source_dir, target_dir = Path(source_dir), Path(target_dir)
    written = []
    specifications = [("audit/splits.csv", "splits.parquet", SPLIT_FIELDS), ("predictions.csv", "predictions.parquet", PREDICTION_FIELDS)]
    for source_name, output_name, fields in specifications:
        output = target_dir / output_name
        if output.exists():
            raise ValueError(f"Parquet export already exists: {output}")
        integer_fields = {"source_file_index", "source_record", "binary_label", "prediction"}
        float_fields = {"attack_score", "threshold"}
        try:
            with (source_dir / source_name).open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                headers = reader.fieldnames or []
                if len(headers) != len(set(headers)) or headers[:len(fields)] != fields or any(name not in TIME_FIELDS for name in headers[len(fields):]):
                    raise ValueError(f"Unexpected Parquet source schema: {source_name}")
                schema = pa.schema([(name, pa.int64() if name in integer_fields else pa.float64() if name in float_fields else pa.string()) for name in headers],
                                   metadata={b"schema_version": b"1", b"timestamp_representation": b"ISO strings; empty UTC fields mean unavailable; local bounds have no timezone", b"source_artifact": source_name.encode()})
                with pq.ParquetWriter(output, schema, compression="snappy") as writer:
                    batch = []
                    for row in reader:
                        if None in row or any(value is None for value in row.values()):
                            raise ValueError(f"Malformed Parquet source row in {source_name}")
                        batch.append({name: int(row[name]) if name in integer_fields else float(row[name]) if name in float_fields else row[name] for name in headers})
                        if len(batch) == 2048:
                            writer.write_table(pa.Table.from_pylist(batch, schema=schema))
                            batch.clear()
                    if batch:
                        writer.write_table(pa.Table.from_pylist(batch, schema=schema))
            written.append(output_name)
        except Exception:
            output.unlink(missing_ok=True)
            raise
    return written
