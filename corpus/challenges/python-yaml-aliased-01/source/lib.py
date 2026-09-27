import yaml
_Loader = yaml.Loader
def parse(text):
    return yaml.load(text, Loader=_Loader)
