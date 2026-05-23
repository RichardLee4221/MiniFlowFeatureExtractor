import numpy as np


def mean(data):
    if not data:
        return 0
    return np.mean(data)


def std(data):
    if not data:
        return 0
    return np.std(data)


def variance(data):
    if not data:
        return 0
    return np.var(data)


def median(data):
    if not data:
        return 0
    return np.median(data)


def percentile(data, p):
    if not data:
        return 0
    return np.percentile(data, p)