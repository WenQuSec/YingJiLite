"""Package trusted source modules as an embedded GZip/JSON resource."""
from pathlib import Path
import argparse
import gzip
import json

MODULES = ('engine', 'triage', 'report', 'packages', 'memory', 'history',
           'journal', 'general', 'investigate', 'runtime', 'network')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.output.exists():
        raise SystemExit('Output already exists; use a fresh build directory.')
    source = {}
    for name in MODULES:
        text = (root / 'src' / 'scripts' / (name + '.ps1')).read_text(encoding='utf-8-sig')
        if 'PSScriptRoot' in text or 'Add-Type -TypeDefinition' in text:
            raise SystemExit('Disk/compiler dependency in module: ' + name)
        source[name + '.ps1'] = text
    data = json.dumps(source, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    args.output.write_bytes(gzip.compress(data, mtime=0))
    print('Embedded modules:', len(source))

if __name__ == '__main__':
    main()
