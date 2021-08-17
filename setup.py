from lib.utils.constants import CONFIG_SCHEMAS_HOME
from setuptools import setup, find_packages

setup(
    version="2.3.0",
    name="asadm",
    packages=find_packages(exclude=["doc", "test*"]),
    include_package_data=True,
    package_data={"": ["{}/*.json".format(CONFIG_SCHEMAS_HOME)]},
    scripts=["asadm.py"],
)
