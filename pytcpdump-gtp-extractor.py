from scapy.all import sniff, PcapWriter
from scapy.interfaces import get_if_list
from scapy.contrib.gtp import GTPPDUSessionContainer
from clize import run
from log import logger
from clize import parameters
import paramiko
from scp import SCPClient
import shutil

ERROR_MOVE_BOTH_PATHS = 10
SCP_NOT_CONFIGURED_ERROR = 11


def create_ssh_client(server, port, user, password):
    """Creates a Paramiko SSH client connection."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port=port, username=user, password=password)
    return client


def capture(*,
            iface: ('i', parameters.multi(min=0)),  # noqa: F821
            filter: 'f' = '',  # noqa: F821
            output: 'w' = None,  # noqa: F821
            duration: 'd' = 0,  # noqa: F821
            logging: 'l' = False,  # noqa: F821
            move_to_nfs_path: 'm' = None,  # noqa: F821
            move_to_scp_path: 'p' = None,  # noqa: F821
            move_to_scp_server: 's' = None,  # noqa: F821
            move_to_scp_port: 'o' = None,  # noqa: F821
            move_tp_scp_username: 'u' = None,  # noqa: F821
            move_to_scp_password: 'a' = None):  # noqa: F821
    """
    Captures network traffic on specified interfaces with an optional
    filter and save to the file if provided.

    :param iface: interfaces to sniff the traffic.
    :param filter: tcpdump / bpf filter.
    :param output: output pcap file to save captured packets.
    :param duration: duration of the capture in seconds (0 = infinite).
    :param logging: enable logging of captured packets.
    :param move_to_scp_path: SCP path to move the output pcap after capture.
    :param move_to_nfs: move the output pcap to NFS path after capture.
    """
    if len(iface) == 0:
        iface = get_if_list()
    if output:
        writer = PcapWriter(output, append=False)

    if move_to_scp_path and move_to_nfs_path:
        logger.error("Cannot move pcap to both SCP and NFS paths. Choose one.")
        return ERROR_MOVE_BOTH_PATHS

    if move_to_scp_path and output:
        if not move_to_scp_server or not move_to_scp_port or not move_tp_scp_username or not move_to_scp_password:
            logger.error("SCP server, port, username, and password must be provided to move the pcap via SCP.")
            return SCP_NOT_CONFIGURED_ERROR
        ssh_client = create_ssh_client(move_to_scp_server,
                                       move_to_scp_port,
                                       move_tp_scp_username,
                                       move_to_scp_password)
        scp_client = SCPClient(ssh_client.get_transport())

    num_pkts_captured = 0

    def analyze_packet(packet):
        nonlocal num_pkts_captured
        if GTPPDUSessionContainer in packet:
            packet = packet.getlayer(GTPPDUSessionContainer).payload
        num_pkts_captured += 1
        if output:
            writer.write(packet)
        if logging:
            logger.info(packet)

    try:
        if duration > 0:
            sniff(iface=iface, filter=filter, prn=analyze_packet, store=0, timeout=duration)
        else:
            sniff(iface=iface, filter=filter, prn=analyze_packet, store=0)
    except Exception as e:
        logger.error(e)
    finally:
        if output:
            writer.close()
            logger.info(f"Packet capture saved to {output}")
        logger.info(f"Total packets captured: {num_pkts_captured}")
        if move_to_scp_path and output:
            scp_client.put(output, move_to_scp_path)
            logger.info(f"Moved pcap to SCP path: {move_to_scp_path}")
        if move_to_nfs_path and output:
            shutil.move(output, move_to_nfs_path)
            logger.info(f"Moved pcap to NFS path: {move_to_nfs_path}")


if __name__ == "__main__":
    run(capture)
