# -*- mode: python ; coding: utf-8 -*-


block_cipher = None

a_B = Analysis(['asinfo.py'],
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

a = Analysis(['asadm.py'],
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

MERGE((a, "asadm", "asadm"), (a_B, "asinfo", "asinfo"))

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts, 
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

pyz_B = PYZ(a_B.pure, a_B.zipped_data,
             cipher=block_cipher)

exe_B = EXE(pyz_B,
          a_B.scripts, 
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

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='asadm')

coll_B = COLLECT(exe_B,
               a_B.binaries,
               a_B.zipfiles,
               a_B.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='asinfo')
