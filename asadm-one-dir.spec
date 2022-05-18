
   
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

#
# Creates a bundled directory as apposed to a single executable file. This allows for
# faster startup but is a bit more difficult to distribute. On Linux, the performance at 
# startup is negligible, however on MacOS the benefits are substantial. This is because
# MacOS codesign verification phones home when a new executable is ran.  In onefile mode
# the OS can not determine whether asadm were previously verified so it will
# verify again.
#
# TLDR; Use onedir for MacOS.
#

datas = []
binaries = [('/usr/bin/less','.')]
hiddenimports = []
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

asadm_coll = COLLECT(asadm_exe,
               asadm_a.binaries,
               asadm_a.zipfiles,
               asadm_a.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='asadm')
