import importlib.metadata

required = {
    'Flask==3.1.0',
    'joblib==1.4.2',
    'scikit-learn==1.6.1',
    'pandas==2.2.3',
    'numpy==2.2.3',
    'requests==2.32.3',
    'flask-cors==5.0.1',
    'python-whois==0.7.3'
}

installed = {pkg.metadata['Name'].lower(): pkg.version for pkg in importlib.metadata.distributions()}
missing = []

for req in required:
    pkg, ver = req.split('==')
    if pkg.lower() not in installed or installed[pkg.lower()] != ver:
        missing.append(req)

if missing:
    print("Missing or incorrect versions of packages:")
    for pkg in missing:
        print(f" - {pkg}")
else:
    print("All required packages are installed with correct versions.")
