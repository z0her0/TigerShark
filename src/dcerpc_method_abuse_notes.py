from typing import Tuple, Optional, Dict, Any, Union

from make_colorful import Color
from dcerpc_data import dcerpc_services


def get_dcerpc_info(service_name: str, opnum: int) -> Union[tuple[None, str, None, None], tuple[int, int, int, int, int]]:
    """
    Retrieves MITRE ATT&CK TTP information for the DCERPC protocol method.
    """
    service: Optional[Dict[str, Any]] = dcerpc_services.get(service_name.lower())
    if not service:
        return None, f"{Color.LIGHTRED}Service {service_name} not found.{Color.END}", None, None

    method_info: Optional[Dict[str, int]] = service["Methods"].get(int(opnum))
    if method_info:
        return (
            method_info["Method"],
            method_info["Note"],
            method_info["ATT&CK TTP"],
            method_info['Attack Type'],
            method_info['IOC']
        )
    else:
        return None, f"Method with opnum {opnum} not found in service {service_name}.", None, None


if __name__ == '__main__':
    service_name_input: str = 'lsarpc'
    opnum_input: int = 76
    results: Tuple[Optional[str], Optional[str], Optional[str], Optional[str]] = get_dcerpc_info(service_name_input,
                                                                                                 opnum_input)

    print(results[0])  # Method
    print(results[1])  # Note
    print(results[2])  # ATT&CK TTP
    print(results[3])  # Attack Type
    print(results[4])  # IOC
