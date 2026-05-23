import json


def export_json(data):

    with open("flows.json", "w") as f:

        json.dump(data, f, indent=4)

    print("JSON Export Finished")