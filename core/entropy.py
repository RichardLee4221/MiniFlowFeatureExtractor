import math
from collections import Counter


def calculate_entropy(data):

    if not data:
        return 0

    counter = Counter(data)

    total = len(data)

    entropy = 0

    for value in counter.values():

        probability = value / total

        entropy -= probability * math.log2(probability)

    return entropy
