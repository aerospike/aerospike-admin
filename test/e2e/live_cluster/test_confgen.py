import re
import time

import asynctest
from test.e2e import lib, util

aerospike_conf = """
${security_stanza}

service {
    feature-key-file ${feature_path}
	run-as-daemon false
	pidfile ${state_directory}/asd.pid
	proto-fd-max 1024
	transaction-retry-ms 10000
	transaction-max-ms 10000
}

logging {
	console {
		context any info
        context security info
	}
	file ${log_path} {
		context any info
	}
}

mod-lua {
	user-path ${udf_directory}
}

network {
	service {
		port ${service_port}
		address any
		access-address ${access_address}
	}

	heartbeat {
		mode mesh
		address any
		port ${heartbeat_port}
		interval 100
		timeout 3
		connect-timeout-ms 100
		${peer_connection}
	}

	fabric {
		port ${fabric_port}
		address any
	}

	info {
		port ${info_port}
		address any
	}
}

namespace ${namespace} {
	replication-factor 2
	memory-size 512M
	default-ttl 0
	storage-engine device {
		file /opt/aerospike/data/test.dat
		filesize 1G
		data-in-memory false # Store data in memory in addition to file.
	}
	nsup-period 60
}

xdr {
        dc DC1 {
                namespace ${namespace} {
                }
        }
}
"""


class TestConfGen(asynctest.TestCase):
    maxDiff = None
    """
    This test has the following steps:
    1. Start a cluster with a template aerospike.conf file
    2. Run "generate config" with the cluster IP and port and save the generated aerospike.conf to
    run on a new server.
    3. Store all `show config *` command output
    4. Stop the cluster
    5. Start a new cluster with the generated aerospike.conf file
    6. Run "generate config" with the cluster IP and port and save the generated aerospike.conf to
    compare with the first generated aerospike.conf
    7. Store all `show config *` command output
    8. Compare the two aerospike.conf files
    9. Compare the two `show config *` command outputs
    """

    @classmethod
    def rm_timestamp_from_output(cls, output):
        lines = output.split("\n")
        for i, l in enumerate(lines):
            l = re.sub(r"([0-9]{2}:){2}[0-9]{2}", "", l)
            lines[i] = l
        return "\n".join(lines)

    def tearDown(self):
        lib.stop()

    async def test_genconf(self):
        lib.start(num_nodes=1, template_content=aerospike_conf)
        time.sleep(1)
        conf_gen_cmd = f"generate config with 127.0.0.1:{lib.PORT}"
        show_config_cmd = "show config; show config security; show config xdr"
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{conf_gen_cmd}' -Uadmin -Padmin"
        )

        if cp.returncode != 0:
            print(cp.stdout)
            print(cp.stderr)
            self.fail()

        first_conf = cp.stdout

        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{show_config_cmd}' -Uadmin -Padmin"
        )

        if cp.returncode != 0:
            print(cp.stdout)
            print(cp.stderr)
            self.fail()

        first_show_config = cp.stdout

        lib.stop()

        lib.start(num_nodes=1, config_content=first_conf)

        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{conf_gen_cmd}' -Uadmin -Padmin"
        )

        if cp.returncode != 0:
            print(cp.stdout)
            print(cp.stderr)
            self.fail()

        second_conf = cp.stdout

        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{show_config_cmd}' -Uadmin -Padmin"
        )

        if cp.returncode != 0:
            print(cp.stdout)
            print(cp.stderr)
            self.fail()

        second_show_config = cp.stdout

        self.assertEqual(first_conf, second_conf)
        self.assertEqual(
            TestConfGen.rm_timestamp_from_output(first_show_config),
            TestConfGen.rm_timestamp_from_output(second_show_config),
        )

    async def test_genconf_save_to_file(self):
        lib.start(num_nodes=1, template_content=aerospike_conf)
        time.sleep(1)
        conf_gen_cmd = f"generate config with all"
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{conf_gen_cmd}' -Uadmin -Padmin"
        )

        if cp.returncode != 0:
            print(cp.stdout)
            print(cp.stderr)
            self.fail()

        first_conf = cp.stdout
        tmp_file = "/tmp/test_genconf_save_to_file.conf"

        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{conf_gen_cmd} -o {tmp_file}' -Uadmin -Padmin"
        )

        with open(tmp_file, "r") as f:
            second_conf = f.read()

        # Remove empty line of stdout
        self.assertListEqual(first_conf.split("\n"), second_conf.split("\n")[1:])
