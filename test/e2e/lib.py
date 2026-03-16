# Copyright 2025 Aerospike, Inc.
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

import codecs
import datetime
import ipaddress
import os
import shutil
import string
import sys
import aerospike
import docker
import atexit
import signal
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from test.e2e import util

# the port to use for one of the cluster nodes
PORT = 10000
TLS_PORT_OFFSET = 5
TLS_PORT = PORT + TLS_PORT_OFFSET
# the namespace to be used for the tests
NAMESPACE = "test"
# the set to be used for the tests
SET = "test"
DC = "DC1"
CLIENT_ATTEMPTS = 20

# the number of server nodes to use
NODE_CAPACITY = 3
DEFAULT_N_NODES = 2

WORK_DIRECTORY = "work"
LUA_DIRECTORY = "work/lua"
STATE_DIRECTORIES = ["state-%d" % i for i in range(1, NODE_CAPACITY + 1)]
UDF_DIRECTORIES = ["udf-%d" % i for i in range(1, NODE_CAPACITY + 1)]
LOG_PATH = "/var/log/aerospike/aerospike.log"

if sys.platform == "linux":
    USE_VALGRIND = False
else:
    USE_VALGRIND = False

# Fixes issue where call fails during vscode pytest discovery causing not tests to be found
try:
    DOCKER_CLIENT = docker.from_env()
except:
    pass

# a list of docker instances running server nodes
NODES = [None for i in range(NODE_CAPACITY)]
# the aerospike client
CLIENT = None

FILE_COUNT = 0

SETS = []
INDEXES = []
UDFS = []
SERVER_IP = None

# used for testing, disable to connect to a locally running aerospike server
USE_DOCKER_SERVERS = True

# set when the cluser is up and running
RUNNING = False

# where to mount work directory in the docker container
CONTAINER_DIR = "/opt/work"
CONTAINER_CERTS_DIR = CONTAINER_DIR + "/certs"

# directory where TLS certs are generated for e2e tests
CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")

# Enable docker log dumping via environment variable
DUMP_DOCKER_LOGS = os.environ.get("DUMP_DOCKER_LOGS", "false").lower() in (
    "true",
    "1",
    "yes",
)


def graceful_exit(handler):
    def graceful_exit(sig, frame):
        signal.signal(signal.SIGINT, g_orig_int_handler)
        stop()
        os.kill(os.getpid(), signal.SIGINT)

    return graceful_exit


def safe_sleep(secs):
    """
    Sleeps, even in the presence of signals.
    """
    start = time.time()
    end = start + secs

    while start < end:
        time.sleep(end - start)
        start = time.time()


def absolute_path(*path):
    """
    Turns the given path into an absolute path.
    """
    if len(path) == 1 and os.path.isabs(path[0]):
        return path[0]

    return os.path.abspath(os.path.join(os.path.dirname(__file__), *path))


def remove_dir(path):
    """
    Removes a directory.
    """
    print("Removing directory", path)

    for root, dirs, files in os.walk(path, False):
        for name in dirs:
            os.rmdir(os.path.join(root, name))

        for name in files:
            os.remove(os.path.join(root, name))

    os.rmdir(path)


def remove_work_dir():
    """
    Removes the work directory.
    """
    print("Removing work directory")
    work = absolute_path(WORK_DIRECTORY)
    lua = absolute_path(LUA_DIRECTORY)

    if os.path.exists(lua):
        remove_dir(lua)

    if os.path.exists(work):
        remove_dir(work)


def remove_state_dirs():
    """
    Removes the runtime state directories.
    """
    print("Removing state directories")

    for walker in STATE_DIRECTORIES:
        state = absolute_path(WORK_DIRECTORY, walker)

        if os.path.exists(state):
            remove_dir(state)

    for walker in UDF_DIRECTORIES:
        udf = absolute_path(WORK_DIRECTORY, walker)

        if os.path.exists(udf):
            remove_dir(udf)


def init_work_dir():
    """
    Creates an empty work directory.
    """
    remove_work_dir()
    print("Creating work directory")
    work = absolute_path(WORK_DIRECTORY)
    lua = absolute_path(LUA_DIRECTORY)
    os.mkdir(work, 0o755)
    os.mkdir(lua, 0o755)


def init_state_dirs():
    """
    Creates empty state directories.
    """
    remove_state_dirs()
    print("Creating state directories")

    for walker in STATE_DIRECTORIES:
        state = absolute_path(os.path.join(WORK_DIRECTORY, walker))
        os.mkdir(state, 0o755)
        smd = absolute_path(os.path.join(WORK_DIRECTORY, walker, "smd"))
        os.mkdir(smd, 0o755)

    for walker in UDF_DIRECTORIES:
        udf = absolute_path(os.path.join(WORK_DIRECTORY, walker))
        os.mkdir(udf, 0o755)


def generate_tls_certs():
    """
    Generates all TLS certificates needed for e2e tests into test/e2e/certs/,
    then copies them into work/certs/ so the container sees them at /opt/work/certs/.
    """
    dest = CERTS_DIR
    for entry in os.listdir(dest):
        entry_path = os.path.join(dest, entry)
        if entry == ".do_not_delete":
            continue
        if os.path.isdir(entry_path):
            shutil.rmtree(entry_path)
        else:
            os.remove(entry_path)
    os.makedirs(os.path.join(dest, "crl_dir"), exist_ok=True)

    def _gen_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _write_key(key, path, password=None):
        enc = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        with open(path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    enc,
                )
            )

    def _write_cert(cert, path):
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    now = datetime.datetime.now(datetime.timezone.utc)

    # CA
    ca_key = _gen_key()
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "TestCA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(ca_key, os.path.join(dest, "ca.key"))
    _write_cert(ca_cert, os.path.join(dest, "ca.pem"))

    # Server cert (CN=localhost, SAN=DNS:localhost,IP:127.0.0.1)
    server_key = _gen_key()
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(server_key, os.path.join(dest, "server.key"))
    _write_cert(server_cert, os.path.join(dest, "server.pem"))

    # Client cert (for mutual TLS)
    client_key = _gen_key()
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "asadm-client"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(client_key, os.path.join(dest, "client.key"))
    _write_cert(client_cert, os.path.join(dest, "client.pem"))

    # Password-protected client key (password: testpass)
    _write_key(client_key, os.path.join(dest, "client_enc.key"), password=b"testpass")

    # Wrong CA (not in the trust chain, for negative tests)
    wrong_ca_key = _gen_key()
    wrong_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WrongCA")])
    wrong_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(wrong_ca_name)
        .issuer_name(wrong_ca_name)
        .public_key(wrong_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(wrong_ca_key, hashes.SHA256())
    )
    _write_key(wrong_ca_key, os.path.join(dest, "wrong_ca.key"))
    _write_cert(wrong_ca_cert, os.path.join(dest, "wrong_ca.pem"))

    # CRL with server cert revoked
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(server_cert.serial_number)
        .revocation_date(now)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=30))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    with open(os.path.join(dest, "crl_dir", "crl.pem"), "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    # Keyfile password file (for file: prefix test)
    with open(os.path.join(dest, "keypass.txt"), "w") as f:
        f.write("testpass")

    print("Generated TLS certs in", dest)

    work_certs = absolute_path(WORK_DIRECTORY, "certs")
    if os.path.exists(work_certs):
        shutil.rmtree(work_certs)
    shutil.copytree(dest, work_certs)
    print("Copied TLS certs to", work_certs)


def cleanup_tls_certs():
    """
    Removes generated cert files from test/e2e/certs/, preserving .do_not_delete.
    """
    for entry in os.listdir(CERTS_DIR):
        if entry == ".do_not_delete":
            continue
        entry_path = os.path.join(CERTS_DIR, entry)
        if os.path.isdir(entry_path):
            shutil.rmtree(entry_path)
        else:
            os.remove(entry_path)
    print("Cleaned up generated TLS certs from", CERTS_DIR)


def temporary_path(extension):
    global FILE_COUNT
    """
	Generates a path to a temporary file in the work directory using the
	given extension.
	"""
    FILE_COUNT += 1
    file_name = "tmp-" + ("%05d" % FILE_COUNT) + "." + extension
    return absolute_path(os.path.join(WORK_DIRECTORY, file_name))


def create_conf_file_from_template(
    template_content,
    port_base,
    peer_addr,
    enable_security: bool,
    index,
    access_address="127.0.0.1",
):
    """
    Create an Aerospike configuration file from the given template.
    """

    params = {
        "security_stanza": (
            "" if not enable_security else "security {\n enable-quotas true\n}"
        ),
        "feature_path": "env-b64:FEATURES",
        "state_directory": CONTAINER_DIR + "/state-" + str(index),
        "udf_directory": CONTAINER_DIR + "/udf-" + str(index),
        "log_path": LOG_PATH,
        "service_port": str(port_base),
        "fabric_port": str(port_base + 1),
        "heartbeat_port": str(port_base + 2),
        "info_port": str(port_base + 3),
        "admin_port": str(port_base + 4),
        "tls_service_port": str(port_base + TLS_PORT_OFFSET),
        "certs_directory": CONTAINER_CERTS_DIR,
        "access_address": access_address,
        "peer_connection": (
            "# no peer connection"
            if not peer_addr
            else "mesh-seed-address-port " + peer_addr[0] + " " + str(peer_addr[1] + 2)
        ),
        "namespace": NAMESPACE,
    }

    temp = string.Template(template_content)
    conf_content = temp.substitute(params)

    return create_config_file_from_config(conf_content)


def create_config_file_from_config(config_content):
    conf_file = temporary_path("conf")

    with codecs.open(conf_file, "w", "UTF-8") as file_obj:
        file_obj.write(config_content)

    return conf_file


def get_file(path, base=None):
    if base is None:
        return os.path.basename(os.path.realpath(path))
    elif path.startswith(base):
        if path[len(base)] == "/":
            return path[len(base) + 1 :]
        else:
            return path[len(base) :]
    else:
        raise Exception("path %s is not in the directory %s" % (path, base))


def connect_client():
    global CLIENT
    config = {
        "hosts": [(SERVER_IP, PORT)],
        "user": "admin",
        "password": "admin",
    }

    for attempt in range(CLIENT_ATTEMPTS):
        try:
            CLIENT = aerospike.client(config).connect()
            break
        except Exception:
            if attempt < CLIENT_ATTEMPTS - 1:
                safe_sleep(1)
            else:
                raise


def start_server(
    first_base,
    index,
    access_address="127.0.0.1",
    docker_tag="latest",
    template_file="aerospike_latest.conf",
    template_content=None,
    config_content=None,
):
    global CLIENT
    global NODES
    global RUNNING
    global SERVER_IP

    mount_dir = absolute_path(WORK_DIRECTORY)

    try:
        feat_key = os.environ["FEATKEY"]
    except:
        raise Exception(
            "Env var FEATKEY must be set with a base64 encoded feature key file."
        )

    base = first_base + 1000 * (index - 1)

    if template_content is None and not config_content:
        template_file = absolute_path(template_file)
        with codecs.open(template_file, "r", "UTF-8") as file_obj:
            template_content = file_obj.read()

    if template_content:
        conf_file = create_conf_file_from_template(
            template_content,
            base,
            None if index == 1 else (SERVER_IP, first_base),
            True,
            index,
            access_address=access_address,
        )
    elif config_content:
        conf_file = create_config_file_from_config(config_content)
    else:
        raise Exception("Must provide either template_content or config_content")

    cmd = "/usr/bin/asd --foreground --config-file %s --instance %s" % (
        CONTAINER_DIR + "/" + get_file(conf_file, base=mount_dir),
        str(index - 1),
    )
    print("running in docker: %s" % cmd)
    try:
        container = DOCKER_CLIENT.containers.get("aerospike-%d" % (index))
        container.remove(force=True)
    except:
        pass

    image_name = f"aerospike/aerospike-server-enterprise:{docker_tag}"

    try:
        print(f"Pulling latest image: {image_name}")
        DOCKER_CLIENT.images.pull(image_name)
        print(f"Pulled latest image: {image_name}")
    except:
        pass

    container = DOCKER_CLIENT.containers.run(
        image_name,
        command=cmd,
        ports={
            str(base) + "/tcp": str(base),
            str(base + 1) + "/tcp": str(base + 1),
            str(base + 2) + "/tcp": str(base + 2),
            str(base + 3) + "/tcp": str(base + 3),
            str(base + 4) + "/tcp": str(base + 4),
            str(base + TLS_PORT_OFFSET) + "/tcp": str(base + TLS_PORT_OFFSET),
        },
        volumes={mount_dir: {"bind": CONTAINER_DIR, "mode": "rw"}},
        tty=True,
        detach=True,
        environment={
            "FEATURES": "{}".format(feat_key),
        },
        name="aerospike-%d" % (index),
        privileged=True,
    )

    NODES[index - 1] = container
    container.reload()

    # For local development, use localhost since ports are mapped to host
    # For CI/CD environments, you might want to use the container IP
    # Check if we should use localhost or container IP
    use_localhost = os.environ.get("E2E_TEST_USE_LOCALHOST", "true").lower() == "true"

    if use_localhost:
        return "127.0.0.1"
    else:
        return container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]


def start(
    do_reset=True,
    num_nodes=DEFAULT_N_NODES,
    docker_tag="8.1",  # Change this to the desired latest Docker tag
    template_file="aerospike_latest.conf",
    template_content=None,
    config_content=None,
):
    global CLIENT
    global NODES
    global RUNNING
    global SERVER_IP

    if not RUNNING:
        RUNNING = True

        if USE_DOCKER_SERVERS:
            print("Starting asd")

            init_work_dir()
            init_state_dirs()

            if template_file == "aerospike_tls.conf":
                generate_tls_certs()

            first_base = PORT
            for index in range(1, num_nodes + 1):
                ip = start_server(
                    first_base,
                    index,
                    docker_tag=docker_tag,
                    template_file=template_file,
                    template_content=template_content,
                    config_content=config_content,
                )
                if index == 1:
                    SERVER_IP = ip
        else:
            SERVER_IP = "127.0.0.1"

        print("Connecting client")

        connect_client()

        print("Client connected")
        CLIENT.admin_grant_roles(
            "admin",
            [
                "sys-admin",
                "user-admin",
                "data-admin",
                "read-write-udf",
                "sindex-admin",
                "read",
                "write",
                "read-write",
            ],
        )

        CLIENT.close()
        connect_client()

        # Add roster management for strong consistency namespace if using latest config
        if template_file == "aerospike_latest.conf":
            print("Setting up roster for strong consistency namespace")
            roster_cmd = "manage roster stage observed ns test_sc; manage recluster;"

            util.run_asadm(
                f"-h {SERVER_IP}:{PORT} --enable -e '{roster_cmd}' -Uadmin -Padmin"
            )

            print("Roster setup completed")

            # Reconnect to ensure proper connectivity
            CLIENT.close()
            connect_client()

    else:
        if do_reset:
            # if the cluster is already up and running, reset it
            reset()


def dump_docker_logs():
    """
    Dumps logs from all running docker containers to files.
    """
    if not DUMP_DOCKER_LOGS:
        return

    for i in range(0, NODE_CAPACITY):
        if NODES[i] is not None:
            try:
                container = NODES[i]
                # Use actual container name and ID for unique identification
                container_name = (
                    container.name if hasattr(container, "name") else f"container-{i+1}"
                )
                container_id = (
                    container.short_id
                    if hasattr(container, "short_id")
                    else container.id[:12]
                )

                logs = container.logs(timestamps=True, tail=1000)

                # Create docker_logs directory if it doesn't exist
                log_dir = "docker_logs"
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir)

                # Use container name and ID for unique filename
                log_file = os.path.join(
                    log_dir, f"{container_name}_{container_id}_logs.txt"
                )
                with open(log_file, "wb") as f:
                    f.write(logs)

            except Exception as e:
                # Silent failure - don't spam output during tests
                pass


def dump_logs_now():
    """
    Manually dump docker logs during test execution.
    Call this function from your test to capture logs at any point.
    """
    dump_docker_logs()


def dump_logs_on_failure():
    """
    Dump docker logs when a test fails.
    Call this from your test's tearDown method or exception handler.
    """
    dump_docker_logs()


def stop():
    global CLIENT
    global RUNNING
    global NODES

    """
	Disconnects the client and stops the running asd process.
	"""
    if RUNNING:
        print("Disconnecting client")

        if CLIENT is None:
            print("No connected client")
        else:
            CLIENT.close()
            CLIENT = None

        # Dump docker logs before stopping containers
        dump_docker_logs()

        print("Stopping asd")
        for i in range(0, NODE_CAPACITY):
            if NODES[i] is not None:
                NODES[i].stop()
                NODES[i].remove()
                NODES[i] = None

        remove_state_dirs()
        remove_work_dir()

        RUNNING = False


def reset():
    global UDFS
    global INDEXES
    """
	Nukes the server, removing all records, indexes, udfs, etc.
	"""
    print("resetting the database")

    # truncate the set
    for set_name in [
        SET,
    ]:
        if set_name is not None:
            set_name = set_name.strip()
        CLIENT.truncate(NAMESPACE, None if not set_name else set_name, 0)

    # delete all udfs
    for udf in UDFS:
        CLIENT.udf_remove(udf)
    UDFS = []

    # delete all indexes
    for index in INDEXES:
        try:
            CLIENT.index_remove(NAMESPACE, index)
        except aerospike.exception.IndexNotFound:
            # the index may not actually be there if we are only backing up certain
            # sets, but this is ok, so fail silently
            pass
    INDEXES = []


def stop_silent():
    # silence stderr and stdout
    stdout_tmp = sys.stdout
    stderr_tmp = sys.stderr
    null = open(os.devnull, "w")
    sys.stdout = null
    sys.stderr = null
    try:
        stop()
        sys.stdout = stdout_tmp
        sys.stderr = stderr_tmp
    except:
        sys.stdout = stdout_tmp
        sys.stderr = stderr_tmp
        raise


def populate_db(set_name: str, namespace: str = "test"):
    global CLIENT
    write_policy = {"key": aerospike.POLICY_KEY_SEND}
    keys = []

    try:
        for idx in range(100):
            key = (namespace, set_name, "key" + str(idx))
            bins = {
                "str": str(idx),
                "a-str": str(idx % 10),
                "b-str": str(idx % 5),
                "int": idx % 5,
                "a-int": idx % 5,
                "b-int": idx % 10,
                "float": idx * 3.14,
                "int-str-mix": str(idx % 5) if idx >= 80 else idx % 10,
            }
            keys.append(key)
            CLIENT.put(key, bins, {"ttl": 3600 * (idx + 1)}, policy=write_policy)
    except:
        print("Failed to fully populate the DB")
        raise

    print("Successfully populated DB")


def create_sindex(name, type_, ns, bin, set_: str | None = None):
    global CLIENT
    req = "sindex-create:namespace={};indexname={};bin={};type={}".format(
        ns, name, bin, type_
    )

    if set_:
        req += ";set=" + set_

    CLIENT.info_all(req)

    time.sleep(1)  # TODO: Instead of sleep wait for sindex to exist
    print("Successfully created secondary index", name)


def create_xdr_filter(ns, dc, exp):
    global CLIENT
    req = f"xdr-set-filter:namespace={ns};dc={dc};exp={exp}".format(ns, dc, exp)

    CLIENT.info_all(req)

    time.sleep(1)  # TODO: Instead of sleep wait for sindex to exist
    print("Successfully created an xdr filter for ", dc, ns, exp)


def upload_udf(file_name, file_contents):
    assert file_name[-4:] == ".lua"
    file_path = write_file(file_name, file_contents)
    CLIENT.udf_put(file_path, 0)
    UDFS.append(file_name[:-4])


def write_file(file_name, file_contents):
    file_path = absolute_path(os.path.join(WORK_DIRECTORY, file_name))
    with open(file_path, "w") as file:
        file.write(file_contents)
    return file_path


g_orig_int_handler = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, graceful_exit(g_orig_int_handler))

# shut down the aerospike cluster when the tests are over
atexit.register(stop_silent)
