import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE_PATH = PROJECT_ROOT.joinpath("packaging", "templates")
DST_PATH = PROJECT_ROOT.joinpath(".github", "actions")

def main():
  images = [
    {
        "name": "bionic",
        "image_name": "ubuntu:bionic"
    },
    {
        "name": "eoan",
        "image_name": "ubuntu:eoan"
    },
    {
        "name": "stretch",
        "image_name": "debian:stretch"
    },
    {
        "name": "buster",
        "image_name": "debian:buster"
    },
  ]
  with open(TEMPLATE_PATH.joinpath("template.dockerfile"), 'r') as f:
    docker_template = f.read()
  with open(TEMPLATE_PATH.joinpath("template.yml"), 'r') as f:
    action_template = f.read()
  for image in images:
    with open(DST_PATH.joinpath(image["name"], "Dockerfile"), "w") as f:
      f.write(docker_template.format(base_image=image["image_name"]))
    with open(DST_PATH.joinpath(image["name"], "action.yml"), "w") as f:
      f.write(action_template.format(target=image["name"]))

if __name__ == "__main__":
  main()
