# Copyright 2022-2023 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

a = Analysis(['asadm.py'],
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

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
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
