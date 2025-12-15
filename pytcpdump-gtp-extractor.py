from scapy.all import sniff, PcapWriter
from scapy.interfaces import get_if_list
from scapy.contrib.gtp import GTPPDUSessionContainer
from clize import run
from log import logger
from clize import parameters
import shutil


def capture(*,
            iface: ('i', parameters.multi(min=0)),  # noqa: F821
            filter: 'f' = '',  # noqa: F821
            output: 'w' = None,  # noqa: F821
            duration: 'd' = 0,  # noqa: F821
            logging: 'l' = False):  # noqa: F821
    """
    Captures network traffic on specified interfaces with an optional
    filter and save to the file if provided.

    :param iface: interfaces to sniff the traffic.
    :param filter: tcpdump / bpf filter (default no filter).
    :param output: output pcap file to save captured packets.
    :param duration: duration of the capture in seconds (0 = infinite).
    :param logging: enable logging of captured packets.
    """
    if len(iface) == 0:
        iface = get_if_list()
    if output:
        writer = PcapWriter(output, append=False)

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
