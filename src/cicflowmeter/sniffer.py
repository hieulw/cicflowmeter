import argparse

from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class


def create_sniffer(
    input_file, input_interface, output_mode, output_file, verbose=False
):
    assert (input_file is None) ^ (
        input_interface is None
    ), "Either provide interface input or file input not both"

    NewFlowSession = generate_session_class(output_mode, output_file, verbose)

    if input_file:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )


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

    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-c",
        "--csv",
        action="store_const",
        const="csv",
        dest="output_mode",
        help="output flows as csv",
    )

    parser.add_argument(
        "output",
        help="output file name (in flow mode) or directory (in sequence mode)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="more verbosity")

    args = parser.parse_args()

    sniffer = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.verbose,
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    main()
