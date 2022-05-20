# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all



datas = []
binaries = [('/usr/bin/less','.')]
hiddenimports = ['pipes', 'json', 'distro', 'dateutil.parser', 'toml', 'jsonschema', 'fcntl', 'bcrypt', "ply.yacc", "ply.lex", "pexpect.pxssh"]
tmp_ret = collect_all('lib')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

added_files = [
]

block_cipher = None

asadm_a = Analysis(['asadm.py'],
             pathex=[],
             binaries=binaries,
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

asinfo_a = Analysis(['asinfo.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

MERGE((asadm_a, "asadm", "asadm"),(asinfo_a, "asinfo", "asinfo"))

asadm_pyz = PYZ(asadm_a.pure)

# HACK to remove 2 warnings. example:
# WARNING: file already exists but should not: /tmp/_MEIU3XEO3/lib-dynload/_struct.cpython-39-x86_64-linux-gnu.so
for tup in asinfo_a.dependencies:
    if "zlib.cpython" in tup[0] or "_struct.cpython" in tup[0]:
        asinfo_a.dependencies.remove(tup)

asadm_exe = EXE(asadm_pyz,
        asadm_a.scripts,
        asadm_a.binaries,
        asadm_a.zipfiles,
        asadm_a.datas,  
        asadm_a.dependencies,
        name='asadm',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,
        disable_windowed_traceback=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None )

asinfo_pyz = PYZ(asinfo_a.pure)

asinfo_exe = EXE(asinfo_pyz,
        asinfo_a.scripts,
        asinfo_a.binaries,
        asinfo_a.zipfiles,
        asinfo_a.datas,  
        asinfo_a.dependencies,
        name='asinfo',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,
        disable_windowed_traceback=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None )
