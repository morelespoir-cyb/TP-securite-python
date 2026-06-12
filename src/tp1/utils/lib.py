from scapy.all import get_if_list

from tp1.utils.config import logger


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    List available network interfaces with Scapy and prompt the user
    to pick one. Validates input until a valid choice is made.

    :return: name of the chosen network interface (e.g. 'eth0')
             or "" if no interface is available
    """
    interfaces = get_if_list()

    if not interfaces:
        logger.error("No network interface available")
        return ""

    # Display numbered list (1-indexed, more natural for end-users)
    print("\nAvailable network interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  {idx}. {iface}")

    # Robust input loop: keep asking until we get a valid integer in range
    while True:
        choice = input("\nChoose an interface (number): ").strip()
        if not choice.isdigit():
            print("Invalid input — please enter a number.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(interfaces):
            selected = interfaces[idx - 1]
            logger.info(f"Selected interface: {selected}")
            return selected
        print(f"Out of range — choose between 1 and {len(interfaces)}.")