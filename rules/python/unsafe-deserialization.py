import json
import pickle

import joblib
import numpy as np
import pandas as pd
import torch
import yaml


class PlanLoader(yaml.SafeLoader):
    pass


def load_all(blob: bytes, text: str, path: str) -> None:
    # ruleid: python-pickle-deserialization
    pickle.loads(blob)
    with open(path, "rb") as fh:
        # ruleid: python-pickle-deserialization
        pickle.load(fh)
    # ruleid: python-pickle-deserialization
    joblib.load(path)
    # ok: python-pickle-deserialization
    pickle.dumps({"a": 1})
    # ok: python-pickle-deserialization
    json.loads(text)

    # ruleid: python-yaml-unsafe-load
    yaml.load(text)
    # ruleid: python-yaml-unsafe-load
    yaml.load(text, Loader=yaml.Loader)
    # ruleid: python-yaml-unsafe-load
    yaml.load(text, Loader=yaml.FullLoader)
    # ruleid: python-yaml-unsafe-load
    yaml.unsafe_load(text)
    # ok: python-yaml-unsafe-load
    yaml.safe_load(text)
    # ok: python-yaml-unsafe-load
    yaml.load(text, Loader=yaml.SafeLoader)
    # ok: python-yaml-unsafe-load
    yaml.load(text, Loader=PlanLoader)

    # ruleid: python-torch-load-unsafe
    torch.load(path, weights_only=False)
    # ruleid: python-torch-load-unsafe
    np.load(path, allow_pickle=True)
    # ruleid: python-torch-load-unsafe
    pd.read_pickle(path)
    # ok: python-torch-load-unsafe
    torch.load(path, map_location="cpu", weights_only=True)
    # ok: python-torch-load-unsafe
    np.load(path)
