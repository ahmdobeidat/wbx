import yaml
# maintenance importer, not wired to any route or imported anywhere
def load_cfg(path):
    return yaml.load(open(path).read())   # juicy Tier-1 decoy, unreachable
