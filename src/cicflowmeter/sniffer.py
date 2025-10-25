import argparse
import time

from scapy.sendrecv import AsyncSniffer

from cicflowmeter.flow_session import FlowSession
import threading

import os
from pathlib import Path

GC_INTERVAL = 1.0  # seconds (tune as needed)


def _start_periodic_gc(session, interval=GC_INTERVAL):
    stop_event = threading.Event()

    def _gc_loop():
        while not stop_event.wait(interval):
            try:
                session.garbage_collect(time.time())
            except Exception:
                # Don't let GC threading failures kill the process
                session.logger.exception("Periodic GC error")

    t = threading.Thread(target=_gc_loop, name="flow-gc", daemon=True)
    t.start()
    # attach to session so we can stop it later
    session._gc_thread = t
    session._gc_stop = stop_event


def create_sniffer(
    input_file, input_interface, output_mode, output, input_directory=None, fields=None, verbose=False
):
    assert sum([input_file is None, input_interface is None, input_directory is None]) == 2, (
        "Provide exactly one: interface, file, or directory input"
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

    _start_periodic_gc(session, interval=GC_INTERVAL)

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

def process_directory_merged(input_dir, output_dir, fields=None, verbose=False):
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Validate input and output directory
    if not input_path.exists():
        print(f"Error: Input directory '{input_dir}' does not exist")
        return
    
    if not input_path.is_dir():
        print(f"Error: Input path '{input_dir}' is not a directory")
        return
    
    if output_path.exists() and output_path.is_file():
        print(f"Error: Output path '{output_dir}' already exists as a file.")
        print(f"Please provide a directory path for batch processing.")
        return
    
    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error: Could not create output directory '{output_dir}': {e}")
        return
    
    # Find all pcap files
    pcap_files = list(input_path.glob("*.pcap")) + list(input_path.glob("*.pcapng"))
    
    if not pcap_files:
        print(f"Error: No pcap files found in {input_dir}")
        return
    
    output_file = output_path / "merged_output.csv"
    print(f"Found {len(pcap_files)} pcap file(s) to process")
    print(f"Merging all flows into: {output_file.name}")
    
    # Create a single sniffer session for all files
    session = FlowSession(
        output_mode="csv",
        output=str(output_file),
        fields=fields,
        verbose=verbose,
    )
    
    _start_periodic_gc(session, interval=GC_INTERVAL)
    
    for idx, pcap_file in enumerate(pcap_files, 1):
        print(f"[{idx}/{len(pcap_files)}] Processing {pcap_file.name}...")
        
        try:
            sniffer = AsyncSniffer(
                offline=str(pcap_file),
                filter="ip and (tcp or udp)",
                prn=session.process,
                store=False,
            )
            
            sniffer.start()
            sniffer.join()
            
            print(f"[{idx}/{len(pcap_files)}] Completed {pcap_file.name}")
        except Exception as e:
            print(f"Error processing {pcap_file.name}: {e}")
            continue
    
    # Stop periodic GC
    if hasattr(session, "_gc_stop"):
        session._gc_stop.set()
        session._gc_thread.join(timeout=2.0)
    
    # Flush all remaining flows
    session.flush_flows()
    
    print(f"\nAll done! Merged output saved to: {output_file}")

def process_directory(input_dir, output_dir, fields=None, verbose=False):
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Validate input and output directory

    if not input_path.exists():
        print(f"Error: Input directory '{input_dir}' does not exist")
        return
    
    if not input_path.is_dir():
        print(f"Error: Input path '{input_dir}' is not a directory")
        return
    
    if output_path.exists() and output_path.is_file():
        print(f"Error: Output path '{output_dir}' already exists as a file.")
        print(f"Please provide a directory path for batch processing.")
        print(f"Example: cicflowmeter -d ./pcaps/ -c ./output_directory/")
        return
    
    # Create output directory if it doesn't exist
    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error: Could not create output directory '{output_dir}': {e}")
        return
    
    # Find all pcap files
    pcap_files = list(input_path.glob("*.pcap")) + list(input_path.glob("*.pcapng"))
    
    if not pcap_files:
        print(f"Error: No pcap files found in {input_dir}")
        return
    
    print(f"Found {len(pcap_files)} pcap file(s) to process")
    
    for pcap_file in pcap_files:
        output_file = output_path / f"{pcap_file.stem}.csv"
        print(f"Processing {pcap_file.name} -> {output_file.name}")
        
        try:
            sniffer, session = create_sniffer(
                input_file=str(pcap_file),
                input_interface=None,
                output_mode="csv",
                output=str(output_file),
                fields=fields,
                verbose=verbose,
            )
            
            sniffer.start()
            sniffer.join()
            
            # Stop periodic GC
            if hasattr(session, "_gc_stop"):
                session._gc_stop.set()
                session._gc_thread.join(timeout=2.0)
            
            # Flush all flows
            session.flush_flows()
            
            print(f"Completed {pcap_file.name}")
        except Exception as e:
            print(f"Error processing {pcap_file.name}: {e}")
            continue
    
    print(f"\nAll done! Output files saved to: {output_dir}")

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
    input_group.add_argument(
        "-d",
        "--directory",
        action="store",
        dest="input_directory",
        help="process all pcap files from INPUT_DIRECTORY",
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
        help="output file name (in csv mode), url (in url mode), or output directory (in directory mode)",
    )

    parser.add_argument(
        "--fields",
        action="store",
        dest="fields",
        help="comma separated fields to include in output (default: all)",
    )

    parser.add_argument(
        "--merge",
        action="store_true",
        help="merge all pcap files into a single CSV (only works with -d/--directory mode)",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="more verbose")

    args = parser.parse_args()
    if args.merge and not args.input_directory:
        parser.error("--merge can only be used with -d/--directory mode")
    if args.input_directory:
        if args.merge:
            process_directory_merged(
                args.input_directory,
                args.output,
                args.fields,
                args.verbose,
            )
        else:
            process_directory(
                args.input_directory,
                args.output,
                args.fields,
                args.verbose,
            )
        return

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
        # Stop periodic GC if present
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        sniffer.join()
        # Flush all flows at the end
        session.flush_flows()


if __name__ == "__main__":
    main()
