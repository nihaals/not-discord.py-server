from pathlib import Path

import yaml


# See https://stackoverflow.com/a/39681672/7621784
class Dumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


whitelist_path = Path(__file__).parent.joinpath('whitelist.yml')

with open(whitelist_path) as fp:
    f = yaml.safe_load(fp)

sorted_users = sorted(f['users'], key=lambda u: u['name'].lower())

# Check for duplicate IDs
user_ids = [u['id'] for u in f['users']]
seen = set()
repeated = set()
for user_id in user_ids:
    if isinstance(user_id, str) is True:
        print(f'User ID is string: {user_id}')
    if user_id in seen:
        repeated.add(user_id)
    else:
        seen.add(user_id)
for user_id in repeated:
    print(f'{user_id} is repeated')

with open(whitelist_path, 'w') as fp:
    f = yaml.dump({'users': sorted_users}, fp, Dumper=Dumper, default_flow_style=False)

print('Sorted')
print(f'{len(seen)} unique IDs whitelisted')
