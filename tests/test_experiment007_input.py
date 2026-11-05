import csv
import io
import zipfile

import pytest

from attack_traffic.experiment007_input import ALIASES, iter_csv_rows, sha256
from attack_traffic.prepare import FEATURES


def make_zip(path, rows, duplicate_header=False):
    headers = [ALIASES.get(name, name) for name in FEATURES] + ["Label", "Timestamp"]
    headers += [f"extra_{i}" for i in range(88 - len(headers))]
    if duplicate_header:
        headers[-1] = headers[0]
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow([" " + name + " " for name in headers])
    for label, date, first in rows:
        writer.writerow([first] + ["1"] * 26 + [label, date] + ["0"] * 59)
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("day/data.csv", stream.getvalue())


def test_stream_maps_labels_features_and_invalid_rows(tmp_path):
    path = tmp_path / "input.zip"
    make_zip(path, [("BENIGN", "2018-12-01 10:00:00", "1"),
                    ("DrDoS_UDP", "2018-12-01 10:00:01", "2"),
                    ("Syn", "2018-12-01 10:00:02", "nan")])
    rows = list(iter_csv_rows(path, "2018-12-01"))
    assert len(sha256(path)) == 64
    assert (rows[0]["label"], rows[0]["family"], len(rows[0]["features"])) == (0, "BENIGN", 27)
    assert (rows[1]["label"], rows[1]["family"], rows[1]["features"][0]) == (1, "UDP", 2)
    assert rows[2]["error"] == "nonfinite_feature"


@pytest.mark.parametrize("label,date,duplicate", [
    ("surprise", "2018-12-01 10:00:00", False),
    ("BENIGN", "2018-11-03 10:00:00", False),
    ("BENIGN", "2018-12-01 10:00:00", True),
])
def test_stream_rejects_unexpected_input(tmp_path, label, date, duplicate):
    path = tmp_path / "input.zip"
    make_zip(path, [(label, date, "1")], duplicate)
    with pytest.raises(ValueError):
        list(iter_csv_rows(path, "2018-12-01"))
