"""Run with idat -A -S on a COPY of the candidate SO; never use the reference IDB."""
import hashlib
import json
from pathlib import Path
import ida_auto
import ida_funcs
import ida_hexrays
import ida_loader
import ida_nalt
import ida_pro
import idautils

ida_auto.auto_wait()
path = Path(ida_nalt.get_input_file_path())
symbols = json.loads((path.parent / 'symbols.json').read_text())
result = {'input': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
          'functions': len(list(idautils.Functions())), 'scope': 'selected native entry, JNI registration, verifier and interpreter only',
          'selected': []}
has_decompiler = ida_hexrays.init_hexrays_plugin()
for name, address in symbols.items():
    function = ida_funcs.get_func(address)
    item = {'buildSymbol': name, 'address': hex(address), 'recognizedFunction': bool(function)}
    if function:
        item['start'] = hex(function.start_ea)
        item['bytes'] = function.end_ea - function.start_ea
        if has_decompiler:
            try:
                item['pseudocode'] = str(ida_hexrays.decompile(address))
            except Exception as error:
                item['decompileError'] = str(error)
    result['selected'].append(item)
(path.parent / 'analysis.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
ida_loader.save_database(str(path.with_suffix('.i64')), 0)
ida_pro.qexit(0)
