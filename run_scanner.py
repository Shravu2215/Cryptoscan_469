import subprocess, json

result = subprocess.run(
    ['python', 'scanner/pipeline.py', r'C:\tmp\pqc-test-fixture\pqc-test-fixture'],
    capture_output=True, text=True
)
if result.returncode != 0:
    print('Scanner error:', result.stderr[:500])
else:
    data = json.loads(result.stdout)
    findings = data.get('findings', [])
    print('Total findings:', len(findings))

    key_findings = [f for f in findings if str(f.get('file', '')).endswith('.key')]
    print('Key file findings ({}):'.format(len(key_findings)))
    for f in key_findings:
        print('  {} -> algorithm={}'.format(f['file'], f['algorithm']))

    with open('scan_new_output.json', 'w') as out:
        json.dump({'findings': findings}, out)
    print('Saved to scan_new_output.json')
