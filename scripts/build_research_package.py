"""Build a local, source-only review package with an integrity manifest."""
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT/'artifacts/research-package-20261105-v4'
ARCHIVE = ROOT/'artifacts/research-package-20261105-v4.zip'
TOP = ('LICENSE','README.md','PRD-01-attack-traffic-classifier.md','TRD-01-attack-traffic-classifier.md',
       'main.py','pyproject.toml','requirements-training.txt','requirements-report.txt','.gitignore')
DIRS = {'attack_traffic':{'.py'}, 'scripts':{'.py'}, 'tests':{'.py'}, 'docs':{'.md'},
        'configs':{'.json','.yaml','.yml'}, 'examples':{'.csv'}}


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024), b''):
            result.update(block)
    return result.hexdigest()


def main():
    if STAGE.exists() or ARCHIVE.exists():
        raise FileExistsError('Choose new package paths; existing evidence is immutable')
    sources = [ROOT/name for name in TOP]
    for directory, suffixes in DIRS.items():
        sources.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and p.suffix.lower() in suffixes and '__pycache__' not in p.parts)
    if any(p.is_symlink() for p in sources):
        raise ValueError('Symlinked source files require separate review')
    STAGE.mkdir(parents=True)
    entries = []
    for source in sorted(sources):
        rel = source.relative_to(ROOT)
        target = STAGE/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
        entries.append({'path':rel.as_posix(),'bytes':target.stat().st_size,'sha256':digest(target)})
    manifest = {'version':1,'scope':'source, documentation, tests, configuration and synthetic fixtures only',
                'excluded':'datasets, captures, model binaries, generated artifacts and row-level outputs',
                'files':entries}
    (STAGE/'PACKAGE-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    with zipfile.ZipFile(ARCHIVE,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for path in sorted(STAGE.rglob('*')):
            if path.is_file(): z.write(path,path.relative_to(STAGE).as_posix())
    with zipfile.ZipFile(ARCHIVE) as z:
        if z.testzip() is not None or set(z.namelist()) != {x['path'] for x in entries}|{'PACKAGE-MANIFEST.json'}:
            raise ValueError('Archive content or CRC validation failed')
        for entry in entries:
            if hashlib.sha256(z.read(entry['path'])).hexdigest()!=entry['sha256']:
                raise ValueError(f"Archive member mismatch: {entry['path']}")
    print(json.dumps({'files':len(entries)+1,'bytes':ARCHIVE.stat().st_size,'sha256':digest(ARCHIVE)}))


if __name__ == '__main__':
    main()
