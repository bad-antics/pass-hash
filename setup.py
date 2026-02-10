from setuptools import setup,find_packages
setup(name="pass-hash",version="2.0.0",author="bad-antics",description="Pass-the-hash attack simulation and detection",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.8")
