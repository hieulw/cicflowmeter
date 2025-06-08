import argparse

from scapy.sendrecv import AsyncSniffer

from cicflowmeter.flow_session import FlowSession


def create_sniffer(
    input_file, input_interface, output_mode, output, fields=None, verbose=False
):
    assert (input_file is None) ^ (input_interface is None), (
        "Either provide interface input or file input not both"
    )
    if fields is not None:
        fields = fields.split(",")

    # Pass config to FlowSession constructor
    session = FlowSession(
        output_mode=output_mode,
        output=output,
        fields=fields,
        verbose=verbose,
    )

    if input_file:
        sniffer = AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
    else:
        sniffer = AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
    return sniffer, session


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )
    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        "-c",
        "--csv",
        action="store_const",
        const="csv",
        dest="output_mode",
        help="output flows as csv",
    )
    output_group.add_argument(
        "-u",
        "--url",
        action="store_const",
        const="url",
        dest="output_mode",
        help="output flows as request to url",
    )

    parser.add_argument(
        "output",
        help="output file name (in csv mode) or url (in url mode)",
    )

    parser.add_argument(
        "--fields",
        action="store",
        dest="fields",
        help="comma separated fields to include in output (default: all)",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="more verbose")

    args = parser.parse_args()

    sniffer, session = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.fields,
        args.verbose,
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()
        # Flush all flows at the end
        session.flush_flows()


if __name__ == "__main__":
    main()
