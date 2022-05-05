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

asadm_a = Analysis(['asadm.py'],
             pathex=[],
             binaries=binaries,
             datas=datas,
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

MERGE((asadm_a, "asadm", "asadm"), (asinfo_a, "asinfo", "asinfo"))

asadm_pyz = PYZ(asadm_a.pure, asadm_a.zipped_data,
             cipher=block_cipher)

asadm_exe = EXE(asadm_pyz,
          asadm_a.scripts, 
          [],
          exclude_binaries=True,
          name='asadm',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )

asinfo_pyz = PYZ(asinfo_a.pure, asinfo_a.zipped_data,
             cipher=block_cipher)

asinfo_exe = EXE(asinfo_pyz,
          asinfo_a.scripts, 
          [],
          exclude_binaries=True,
          name='asinfo',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )

asadm_coll = COLLECT(asadm_exe,
               asadm_a.binaries,
               asadm_a.zipfiles,
               asadm_a.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='asadm')

asinfo_coll = COLLECT(asinfo_exe,
               asinfo_a.binaries,
               asinfo_a.zipfiles,
               asinfo_a.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='asinfo')
