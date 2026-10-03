import urllib.request

r = urllib.request.urlopen('http://localhost/assets/js/pqcSizes.js')
body = r.read().decode('utf-8')
print('pqcSizes.js live checks:')
print('  [{}] null fallback present'.format('OK' if 'return null;' in body else 'FAIL'))
print('  [{}] AES-ECB in ALGO_DATABASE'.format('OK' if 'AES-ECB' in body else 'FAIL'))
print('  [{}] old ECDSA fallback GONE'.format('OK' if "return 'ECDSA P-256'" not in body[:4000] else 'FAIL'))

r2 = urllib.request.urlopen('http://localhost/assets/js/pqcSimulator.js')
body2 = r2.read().decode('utf-8')
print('pqcSimulator.js live checks:')
print('  [{}] console.table debug'.format('OK' if 'console.table' in body2 else 'FAIL'))
print('  [{}] family matching (fFamily)'.format('OK' if 'fFamily' in body2 else 'FAIL'))
print('  [{}] no-match returns false'.format('OK' if 'return false' in body2 else 'FAIL'))
