import utils
import json
import os

_CONFIG = {
  "_URI": "mongodb://127.0.0.1:27017",
  "_DATABASE": 'excavator_data',
}

client = utils.connect_to_database(_CONFIG)
database = client[_CONFIG["_DATABASE"]]
for i in range(16, 26):
  api_level = i
  filename = "permissions_{}.json".format(api_level)
  filepath = os.path.join("aosp_permissions",
                          filename)
  if os.path.exists(filepath):
    collection = database["permission_{}".format(api_level)]
    with open(filepath) as file:
      data = json.load(file)
      for key in data.keys():
        collection.insert_one({
          '_id': key,
          "permissionGroup": data[key]["permissionGroup"],
          "description": data[key]["description"],
          "protectionLevel": data[key]["protectionLevel"],
          "label": data[key]["label"]})

for i in range(16, 26):
  api_level = i
  filename = "permissions_{}.json".format(api_level)
  filepath = os.path.join("api_permission_mappings",
                          filename)
  if os.path.exists(filepath):
    collection = database["mappings_{}".format(api_level)]
    with open(filepath) as file:
      data = json.load(file)
      for key in data.keys():
        collection.insert_one({
          '_id': key,
          "permissions": data[key]})
