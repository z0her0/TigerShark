"""  # pylint: disable=line-too-long
This module provides functionality to retrieve detailed information about specific methods within
Distributed Computing Environment / Remote Procedure Calls (DCE/RPC) services. It utilizes a
dictionary of known DCE/RPC services and their methods, each identified by an operation number (opnum).

The main functionality is encapsulated in the `get_dcerpc_info` function. This function accepts a service
name and an operation number as input, and returns detailed information about the corresponding method
within the specified DCE/RPC service. This information includes the method's name, a note describing
the method, any associated attack techniques, tactics, and procedures (TTPs), the type of attack
associated with the method, and indicators of compromise (IOCs).

This module is particularly useful in the context of network security and forensic analysis, where
understanding the details of DCE/RPC methods can be crucial for identifying potential malicious activities.

Functions:
    - `get_dcerpc_info`: Retrieves information about a specific opnum for a given DCE/RPC service.
"""

from typing import Tuple, Union

from make_colorful import Color
from dcerpc_data import dcerpc_services


# pylint: disable=line-too-long
def get_dcerpc_info(service_name: str, opnum: int) -> Union[Tuple[None, str, None, None, None], Tuple[int, int, int, int, int]]:
    """
    Retrieves information about a specific operation number (opnum) for a given DCERPC service.

    Args:
        service_name (str): The name of the DCERPC service.
        opnum (int): The operation number for which information is requested.

    Returns:
        Union[Tuple[None, str, None, None, None], Tuple[str, str, str, str, str]]:
        A tuple containing information about the DCERPC method, or an error message if the service or method is not
        found.
        The tuple format is (Method, Note, Attack_TTP, Attack_Type, IOC) for valid cases,
        or (None, error message, None, None, None) for invalid cases.

    Notes:
        This function first checks if the provided service name exists in the `dcerpc_services` dictionary.
        If the service is found and valid, it then looks for the method associated with the given opnum.
        If the method is found, its details are returned; otherwise, an error message is provided.
    """
    service = dcerpc_services.get(service_name.lower())

    if service is None or isinstance(service, str) or not isinstance(service, dict) or "Methods" not in service:
        return None, f"{Color.LIGHTRED}Service {service_name} not found or invalid.{Color.END}", None, None, None

    method_info = service["Methods"].get(opnum)
    if method_info and isinstance(method_info, dict):
        return (
            method_info["Method"],
            method_info["Note"],
            method_info["Attack_TTP"],
            method_info['Attack_Type'],
            method_info['IOC']
        )
    else:
        return None, f"Method with opnum {opnum} not found in service {service_name}.", None, None, None


if __name__ == '__main__':
    pass
