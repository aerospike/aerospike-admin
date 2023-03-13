# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
import platform

#
# Creates a bundled directory as apposed to a single executable file. This allows for
# faster startup but is a bit more difficult to distribute. On Linux, the performance at 
# startup is negligible, however on MacOS the benefits are substantial. This is because
# MacOS codesign verification phones home when a new executable is ran.  In onefile mode
# the OS can not determine whether asadm/asinfo were previously verified so it will
# verify again.
#
# TLDR; Use onedir for MacOS.
#

datas = [('lib/live_cluster/client/config-schemas', './lib/live_cluster/client/config-schemas')]
binaries = [('/usr/bin/less','.')]
hiddenimports = []

'''
RHEL9 removed libcrypt (different from libcrypto) from its default distribution.
It is possible to build Python without libcrypt but we would need to move away from
using pyenv on our build machine since pyenv relies on libcrypt to run `pyenv install`.
'''

if "darwin" not in platform.system().lower():
    binaries.append(('/usr/lib64/libcrypt.so.1', '.'))

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
             hiddenimports=hiddenimports,
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
