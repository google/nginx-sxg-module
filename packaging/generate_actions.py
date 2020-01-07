import jinja2
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE_PATH = PROJECT_ROOT.joinpath("packaging", "templates")
DST_PATH = PROJECT_ROOT.joinpath(".github", "actions")

def main():
  images = [
    {
        "name": "bionic",
        "base_name": "ubuntu:bionic"
    },
    {
        "name": "eoan",
        "base_name": "ubuntu:eoan"
    },
    {
        "name": "stretch",
        "base_name": "debian:stretch"
    },
    {
        "name": "buster",
        "base_name": "debian:buster"
    },
  ]
  env = jinja2.Environment(
      loader=jinja2.FileSystemLoader(TEMPLATE_PATH.as_posix()))
  docker_template = env.get_template("Dockerfile.jinja")
  action_template = env.get_template("action.jinja.yml")
  for image in images:
    with open(DST_PATH.joinpath(image["name"], "Dockerfile"), "w") as f:
      f.write(docker_template.render(base_image=image["base_name"]))
    with open(DST_PATH.joinpath(image["name"], "action.yml"), "w") as f:
      f.write(action_template.render(name=image["name"]))

if __name__ == "__main__":
  main()
