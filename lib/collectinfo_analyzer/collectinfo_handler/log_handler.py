# Copyright 2013-2025 Aerospike, Inc.
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
import json
import logging
import ntpath
import os
import re
import shutil
import tarfile
import zipfile

from lib.utils import common, log_util, util, constants
from lib.utils.constants import NodeSelection, NodeSelectionType
from lib.utils.exit_code import set_exit_code
from lib.view import terminal
from .collectinfo_diagnostics import (
    BundleWarning,
    CollectinfoDiagnostics,
    DiagSeverity,
    FATAL_DIAGNOSTIC_CATEGORIES,
    print_banner,
    render_banner,
)
from .collectinfo_log import CollectinfoLog

logger = logging.getLogger(__name__)

###### Constants ######
DATE_SEG = 0
YEAR = 0
MONTH = 1
DATE = 2

TIME_SEG = 1
HH = 0
MM = 1
SS = 2

# for zipped files
COLLECTINFO_DIR = constants.ADMIN_HOME + "collectinfo/"
COLLECTINFO_INTERNAL_DIR = "collectinfo_analyzer_extracted_files"

ASADM_VERSION_SCAN_FILES = ("ascollectinfo.log", "summary.log")
ASADM_VERSION_SCAN_BYTES = 65536
ASADM_VERSION_RE = re.compile(r"asadm version\s+(\S+)")

######################


class LogHandlerException(Exception):
    pass


def _describes_snapshot(meta: dict, timestamp: str) -> bool:
    snapshots = meta.get("snapshots")

    if not timestamp or not isinstance(snapshots, list):
        return False

    return any(
        isinstance(entry, dict) and entry.get("timestamp") == timestamp
        for entry in snapshots
    )


class CollectinfoLogHandler(object):
    """
    Handles interaction with the ascinfo.json file to make it act more like live_cluster/cluster.
    """

    all_cinfo_logs = {}
    selected_cinfo_logs = {}

    def __init__(self, cinfo_path, asadm_version=""):
        self.cinfo_path = cinfo_path
        self.asadm_version = asadm_version
        self.collectinfo_dir = COLLECTINFO_DIR + str(os.getpid())
        self._validate_and_extract_compressed_files(
            cinfo_path, dest_dir=self.collectinfo_dir
        )
        self.cinfo_timestamp = None
        self.bundle_snapshot_count = 0
        self._bundle_diagnostics: list[BundleWarning] | None = None
        self._collector_asadm_version: str | None = None
        self.bundle_meta_seen = False
        self.bundle_meta_format_version = 0

        try:
            self._add_cinfo_log_files(cinfo_path)
        except Exception as e:
            self.close()
            raise e

        self.collectinfo_meta = self._load_collectinfo_meta()

    def __str__(self):
        status_str = ""
        if not self.all_cinfo_logs:
            return status_str

        i = 1
        for timestamp in sorted(self.all_cinfo_logs.keys()):
            nodes = list(self.all_cinfo_logs[timestamp].get_node_names().keys())
            if len(nodes) == 0:
                continue

            status_str += "\n " + str(i) + ": "
            status_str += ntpath.basename(self.all_cinfo_logs[timestamp].cinfo_file)
            status_str += " ("
            status_str += str(timestamp)
            status_str += ")"
            status_str += "\n\tFound %s nodes" % (len(nodes))
            status_str += "\n\tOnline:  %s" % (", ".join(nodes))
            status_str += "\n\tCollected by:  %s" % (self._collected_by_str(),)
            status_str += "\n"
            i = i + 1

        status_str += self.diagnostics_banner()

        return status_str

    def bundle_files(self, suffixes: tuple[str, ...]) -> list[str]:
        """Every bundle file whose name ends with one of the given suffixes.

        Public because the bundle diagnostics use it to check which files the
        bundle physically contains. Walks the bundle path and the extraction
        directory directly rather than going through _get_valid_files, which
        keeps only .json and .conf files and so cannot see the .log files the
        version scan needs.
        """
        matches = []

        for root in (self.cinfo_path, self.collectinfo_dir):
            if not root or not os.path.exists(root):
                continue

            try:
                files = log_util.get_all_files(root)
            except Exception:
                continue

            for file in files:
                if file.endswith(suffixes) and file not in matches:
                    matches.append(file)

        return matches

    def _analyzed_timestamp(self) -> str:
        """The snapshot every command reads: the newest one in the bundle."""
        if not self.all_cinfo_logs:
            return ""

        return sorted(self.all_cinfo_logs.keys())[-1]

    def _load_collectinfo_meta(self) -> dict:
        """Read the collectinfo_meta.json describing the analyzed snapshot.

        Absent for every bundle collected before asadm wrote collectinfo_meta.json
        (meta_format_version 1), and absent whenever a bundle is analyzed from
        ascinfo.json alone, so a missing file is normal and must stay silent.

        A meta written by a newer asadm (a larger meta_format_version) is still
        returned: unknown fields are ignored and absent fields mean "not
        recorded", so reading the parts this asadm understands beats discarding
        the file. The diagnostics report the version mismatch separately.

        A path holding more than one bundle is a supported input: every archive under
        it is extracted and every ascinfo.json merged, while only the newest snapshot
        is analyzed. Taking the first meta found would then report another bundle's
        node reconciliation and collector version against this snapshot, so only a
        meta that carries the analyzed timestamp is used.

        Every readable meta still leaves a trace in bundle_meta_seen and
        bundle_meta_format_version, whatever snapshot it describes. Those two are
        how the diagnostics tell "no meta was ever written" from "a meta exists
        and this asadm could not read its shape": a v2 meta that renames
        `snapshots` or `timestamp` joins to nothing here, and without the trace it
        would be reported as an old bundle - the exact false claim the version
        gate exists to prevent.
        """
        timestamp = self._analyzed_timestamp()
        joined = {}

        for file in self.bundle_files((constants.COLLECTINFO_META_FILENAME,)):
            try:
                with open(file) as meta_file:
                    meta = json.load(meta_file)
            except Exception as e:
                logger.debug("Could not read %s: %s", file, e)
                continue

            if not isinstance(meta, dict):
                continue

            self.bundle_meta_seen = True
            format_version = meta.get("meta_format_version")

            if isinstance(format_version, int):
                self.bundle_meta_format_version = max(
                    self.bundle_meta_format_version, format_version
                )

            if not joined and _describes_snapshot(meta, timestamp):
                joined = meta

        return joined

    def _scan_bundle_for_asadm_version(self) -> str:
        """Best-effort collector version for bundles with no collectinfo_meta.json.

        asadm has always echoed 'asadm version <v>' into ascollectinfo.log and
        summary.log. Reads a capped prefix because the line is written first.

        A path holding two bundles is a supported input and the scan cannot tell
        which log belongs to the snapshot being analyzed, so a version is returned
        only when every log found agrees. Returning the first match would
        attribute one bundle's collector to another's data, which is worse than
        reporting the version as unrecorded.
        """
        versions = set()

        for file in self.bundle_files(ASADM_VERSION_SCAN_FILES):
            try:
                with open(file, errors="ignore") as log_file:
                    head = log_file.read(ASADM_VERSION_SCAN_BYTES)
            except Exception as e:
                logger.debug("Could not scan %s for asadm version: %s", file, e)
                continue

            match = ASADM_VERSION_RE.search(head)

            if match:
                versions.add(match.group(1))

        if len(versions) == 1:
            return versions.pop()

        if versions:
            logger.debug(
                "Bundle logs record more than one asadm version (%s); "
                "not attributing one to this snapshot.",
                ", ".join(sorted(versions)),
            )

        return ""

    def _collected_by_str(self) -> str:
        """The 'Collected by' intro line.

        A bundle with no recorded version is itself a finding, not a neutral fact, so
        it is flagged in place rather than printed as a bland 'unknown'.
        """
        collector = self.collector_asadm_version()

        if collector:
            return "asadm %s" % (collector,)

        return (
            terminal.fg_yellow()
            + "unrecorded asadm version - see warnings below"
            + terminal.fg_clear()
        )

    def collector_asadm_version(self) -> str:
        """The asadm that produced this bundle, from the metadata file or the logs.

        Every asadm since 2017 echoes 'asadm version <v>' into ascollectinfo.log, so
        bundles collected long before the metadata file existed still report a
        version.
        """
        if self._collector_asadm_version is not None:
            return self._collector_asadm_version

        self._collector_asadm_version = ""

        try:
            meta_version = str(
                (self.collectinfo_meta.get("bundle") or {}).get("asadm_version") or ""
            ).strip()
            self._collector_asadm_version = (
                meta_version or self._scan_bundle_for_asadm_version()
            )
        except Exception as e:
            logger.debug("Could not determine collector asadm version: %s", e)

        return self._collector_asadm_version

    def get_bundle_diagnostics(self) -> list[BundleWarning]:
        if self._bundle_diagnostics is not None:
            return self._bundle_diagnostics

        self._bundle_diagnostics = []

        try:
            if not self.all_cinfo_logs:
                return self._bundle_diagnostics

            timestamp = self._analyzed_timestamp()
            diagnostics = CollectinfoDiagnostics(
                log_handler=self,
                snapshot=self.all_cinfo_logs[timestamp],
                timestamp=timestamp,
                running_version=self.asadm_version,
                meta=self.collectinfo_meta,
            )
            self._bundle_diagnostics = diagnostics.analyze()
        except Exception as e:
            logger.debug("Failed to compute bundle diagnostics: %s", e, exc_info=True)
            self._bundle_diagnostics = [
                BundleWarning(
                    category="diagnostics-unavailable",
                    severity=DiagSeverity.WARNING,
                    title="Diagnostics could not be computed for this bundle",
                    lines=[
                        "Nothing below has been checked. An empty finding list would "
                        "read as a healthy bundle, which is not what happened. Run "
                        "with --debug for the failure.",
                    ],
                )
            ]

        return self._bundle_diagnostics

    def diagnostics_banner(self) -> str:
        return render_banner(self.get_bundle_diagnostics())

    def print_diagnostics_banner(self, stream=None) -> None:
        """Print the banner for --execute mode, failing only on an unusable bundle.

        A finding about the collected cluster's health must not fail the command
        the user ran, so the banner itself stays logger-free. A bundle with no
        readable node data is different in kind: every command over it prints an
        empty table, and `asadm -e ... || handle_error` would call that success.
        Only FATAL_DIAGNOSTIC_CATEGORIES fail the command.

        The exit code is set here rather than left to BaseLogger.error: importing
        it would pull the live-cluster client and OpenSSL into the analyzer, and
        which logger class is installed depends on import order.

        The interactive path prints the same banner through __str__ and keeps
        going: the shell continues and the banner is on screen.
        """
        warnings = self.get_bundle_diagnostics()
        print_banner(warnings, stream)

        unusable = [
            warning
            for warning in warnings
            if warning.category in FATAL_DIAGNOSTIC_CATEGORIES
        ]

        if unusable:
            logger.error(
                "%s. No command can report anything from this bundle.",
                unusable[0].title,
            )
            set_exit_code(2)

    def close(self):
        if self.all_cinfo_logs:
            for timestamp in self.all_cinfo_logs:
                try:
                    self.all_cinfo_logs[timestamp].destroy()
                except Exception:
                    pass
            self.all_cinfo_logs.clear()
            self.selected_cinfo_logs.clear()

        if os.path.exists(self.collectinfo_dir):
            shutil.rmtree(self.collectinfo_dir)

    def get_cinfo_log_at(self, timestamp=""):
        if not timestamp or timestamp not in self.all_cinfo_logs:
            return None

        return self.all_cinfo_logs[timestamp]

    def get_principal(self, timestamp):
        service_data = self.info_statistics(stanza="service")
        principal = None

        if timestamp not in service_data:
            return principal

        for node_ip in service_data[timestamp]:
            temp_principal = service_data[timestamp][node_ip].get("cluster_principal")

            if principal and temp_principal and temp_principal != principal:
                return principal
            elif not principal:
                principal = temp_principal

        return principal

    def get_node_id_to_ip_mapping(self, timestamp):
        meta_data = self.info_meta_data()
        node_to_ip = {}

        if timestamp not in meta_data:
            return {}

        for node_ip in meta_data[timestamp]:
            # A node collected without an id (its info calls failed, TOOLS-3596) must
            # not break the mapping for the healthy nodes.
            node_id = meta_data[timestamp][node_ip].get("node_id")
            if not node_id:
                continue
            node_to_ip[node_id] = node_ip

        return node_to_ip

    def get_ip_to_node_id_mapping(self, timestamp):
        meta_data = self.info_meta_data()
        ip_to_node = {}

        if timestamp not in meta_data:
            return {}

        for node_ip in meta_data[timestamp]:
            node_id = meta_data[timestamp][node_ip].get("node_id")
            if not node_id:
                continue
            ip_to_node[node_ip] = node_id

        return ip_to_node

    def info_getconfig(
        self,
        stanza="",
        flip=False,
        nodes: NodeSelectionType = NodeSelection.ALL,
    ):
        return self._fetch_from_cinfo_log(
            type="config", stanza=stanza, flip=flip, nodes=nodes
        )

    def info_get_originalconfig(self, stanza="", flip=False):
        return self._fetch_from_cinfo_log(
            type="original_config", stanza=stanza, flip=flip
        )

    def info_statistics(self, stanza="", flip=False):
        return self._fetch_from_cinfo_log(type="statistics", stanza=stanza, flip=flip)

    def info_histogram(self, stanza="", byte_distribution=False, flip=False):
        if byte_distribution and stanza == "objsz":
            stanza = "object-size"

        hist_dict = self._fetch_from_cinfo_log(
            type="histogram", stanza=stanza, flip=flip
        )
        res_dict = {}

        version = self.info_meta_data(stanza="asd_build")

        for timestamp, hist_snapshot in hist_dict.items():
            res_dict[timestamp] = {}
            if not hist_snapshot:
                continue

            for node, node_snapshot in hist_snapshot.items():
                res_dict[timestamp][node] = {}
                if not node_snapshot:
                    continue

                for namespace, namespace_snapshot in node_snapshot.items():
                    if not namespace_snapshot:
                        continue

                    try:
                        as_version = version[timestamp][node]
                        d = common.parse_raw_histogram(
                            stanza,
                            namespace_snapshot,
                            logarithmic=byte_distribution,
                            new_histogram_version=common.is_new_histogram_version(
                                as_version
                            ),
                        )
                        if d and not isinstance(d, Exception):
                            res_dict[timestamp][node][namespace] = d

                    except Exception:
                        pass
        return res_dict

    def info_latency(self):
        return self._fetch_from_cinfo_log(type="latency")

    def info_meta_data(self, stanza=""):
        return self._fetch_from_cinfo_log(type="meta_data", stanza=stanza)

    def info_pmap(self):
        return self._fetch_from_cinfo_log(type="pmap")

    def info_user_agents(self):
        return self._fetch_from_cinfo_log(type="user_agents")

    def info_masking_rules(self):
        return self._fetch_from_cinfo_log(type="masking")

    def info_namespaces(self):
        return self._fetch_from_cinfo_log(type="config", stanza="namespace_list")

    def info_release(self):
        return self._fetch_from_cinfo_log(type="meta_data", stanza="release")

    def admin_acl(
        self,
        stanza,
        nodes: NodeSelectionType = NodeSelection.ALL,
    ):
        data = self._fetch_from_cinfo_log(type="acl", stanza=stanza, nodes=nodes)

        """
        Asadm 2.1 stored user data as {user: [role1, role2, . . .]} which had to be
        changed to {user: {roles: [role1, role2], connections: int, . . .}} in 
        Asadm 2.2.  This snippet can be removed when 2.1 is considered old enough :)
        """
        if stanza == "users":
            for nodes_data in data.values():
                for users_data in nodes_data.values():
                    for user, user_data in users_data.items():
                        if isinstance(user_data, list):
                            users_data[user] = {"roles": user_data}

        return data

    def get_sys_data(self, stanza=""):
        res_dict = {}
        if not stanza:
            return res_dict

        for timestamp in sorted(self.selected_cinfo_logs.keys()):
            try:
                out = self.selected_cinfo_logs[timestamp].get_sys_data(stanza=stanza)
                res_dict[timestamp] = util.restructure_sys_data(out, stanza)
            except Exception:
                continue

        return res_dict

    def _get_valid_files(self, cinfo_path=""):
        try:
            if not cinfo_path:
                cinfo_path = self.cinfo_path

            log_files = log_util.get_all_files(cinfo_path)
            valid_files = []
            for log_file in log_files:
                try:
                    # ToDo: It should be some proper check for asadm
                    # collectinfo json file.
                    if os.path.splitext(log_file)[1] == ".json":
                        valid_files.append(log_file)
                        continue
                except Exception:
                    pass

                try:
                    # ToDo: It should be some proper check for asadm
                    # conf file.
                    if os.path.splitext(log_file)[1] == ".conf":
                        valid_files.append(log_file)
                except Exception:
                    pass

            return valid_files

        except Exception:
            return []

    def _get_all_file_paths(self, cinfo_path):
        files = []

        if os.path.isfile(cinfo_path):
            if not self._is_compressed_file(cinfo_path):
                files.append(cinfo_path)
            else:
                files += log_util.get_all_files(self.collectinfo_dir)

        elif os.path.isdir(cinfo_path):
            files += log_util.get_all_files(cinfo_path)
            if os.path.exists(self.collectinfo_dir):
                # ToDo: Before adding file from collectinfo_dir, we need to check file already exists in input file list or not,
                # ToDo: collectinfo_parser fails if same file exists twice in input file list. This is possible if input has zip file and
                # ToDo: user unzipped it but did not remove zipped file, in that case collectinfo-analyzer creates new unzipped file,
                # ToDo: which results in two copies of same file (one unzipped by user and one unzipped by collectinfo-analyzer).

                files += self._get_valid_files(self.collectinfo_dir)

        return files

    def _add_cinfo_log_files(self, cinfo_path=""):
        if not cinfo_path:
            raise LogHandlerException("Collectinfo path not specified.")

        if not os.path.exists(cinfo_path):
            raise LogHandlerException("Wrong Collectinfo path.")

        files = self._get_all_file_paths(cinfo_path)
        if not files:
            raise LogHandlerException("No valid Aerospike collectinfo log available.")

        cinfo_log = CollectinfoLog(cinfo_path, files)
        self.selected_cinfo_logs = cinfo_log.snapshots
        self.all_cinfo_logs = cinfo_log.snapshots
        self.bundle_snapshot_count = len(cinfo_log.data or {})
        snapshots_added = len(self.all_cinfo_logs)
        if not snapshots_added:
            raise LogHandlerException("Multiple snapshots available without JSON dump.")

    def _fetch_from_cinfo_log(
        self,
        type="",
        stanza="",
        flip=False,
        nodes: NodeSelectionType = NodeSelection.ALL,
    ):
        res_dict = {}

        if not type:
            return res_dict

        for timestamp in sorted(self.selected_cinfo_logs.keys()):
            try:
                out = self.selected_cinfo_logs[timestamp].get_data(
                    type=type, stanza=stanza, nodes=nodes
                )
                if flip:
                    out = util.flip_keys(out)

                res_dict[timestamp] = out

            except Exception:
                continue

        return res_dict

    def _is_compressed_file(self, file):
        if not file or not os.path.exists(file):
            return False

        if zipfile.is_zipfile(file) or tarfile.is_tarfile(file):
            return True

        return False

    def _extract_to(self, file, dest_dir):
        """Extract one bundle archive under dest_dir, refusing to write outside it.

        Opening a bundle is opening a third party's archive: a tar member named
        ../../../.ssh/authorized_keys writes outside dest_dir on Python 3.12,
        whose default extraction filter is still fully_trusted. filter="data"
        rejects absolute and traversing paths, and with them symlinks, device
        nodes and non-portable modes. Genuine asadm bundles contain only regular
        files and directories, so nothing legitimate is lost; a non-asadm archive
        carrying symlinks is now rejected, which is the intended trade.

        A refusal is reported rather than swallowed: silently extracting nothing
        surfaces later as "no valid Aerospike collectinfo log available", which
        sends the reader after the wrong problem.
        """
        if not file or not os.path.exists(file):
            return False

        try:
            if tarfile.is_tarfile(file):
                compressed_file = tarfile.open(file)
                is_tar = True

            elif zipfile.is_zipfile(file):
                compressed_file = zipfile.ZipFile(file, "r")
                is_tar = False

            else:
                return False

        except Exception:
            return False

        file_extracted = False
        try:
            if is_tar:
                compressed_file.extractall(path=dest_dir, filter="data")
            else:
                compressed_file.extractall(path=dest_dir)

            file_extracted = True
        except Exception as e:
            logger.warning("Could not extract %s: %s", file, e)
            logger.debug("Extraction of %s failed", file, exc_info=True)
            file_extracted = False
        finally:
            compressed_file.close()

        return file_extracted

    def _validate_and_extract_compressed_files(self, cinfo_path, dest_dir=None):
        if not cinfo_path or not os.path.exists(cinfo_path):
            return

        if not dest_dir:
            dest_dir = self.collectinfo_dir

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        if os.path.isfile(cinfo_path):
            if not self._is_compressed_file(cinfo_path):
                return

            if self._extract_to(cinfo_path, dest_dir):
                self._validate_and_extract_compressed_files(
                    dest_dir, dest_dir=os.path.join(dest_dir, COLLECTINFO_INTERNAL_DIR)
                )
                return

        files = log_util.get_all_files(cinfo_path)
        if not files:
            return

        file_extracted = False
        for file in files:
            if not self._is_compressed_file(file):
                continue

            if self._extract_to(file, dest_dir):
                file_extracted = True

        if file_extracted:
            self._validate_and_extract_compressed_files(
                dest_dir, dest_dir=os.path.join(dest_dir, COLLECTINFO_INTERNAL_DIR)
            )
