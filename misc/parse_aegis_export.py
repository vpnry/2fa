import json

output_dict = {}

with open('a.json', 'r') as f_in:
    data = json.load(f_in)
    entries = data['db']['entries']
    for entry in entries:
        name = entry['name']
        issuer = entry['issuer']
        secret = entry['info']['secret']
        output_dict[f"{name}@{issuer}"] = secret

with open('raw_decrypted_accounts.json', 'w') as f_out:
    json.dump(output_dict, f_out, indent=2)
    print("Done!")