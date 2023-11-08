from make_colorful import Color
# Import custom Color class to enable colored text output

from dcerpc_data import dcerpc_services
# Import custom function to fetch and detail DCERPC services, highlighting possible and known abuse

from make_helpers import get_input_opnum
# Import custom function that validates user input and returns int, in order to map to the corresponding
# method and notes


def get_dcerpc_info(service_name, opnum):
    """
    Retrieves information about the operation number (opnum) and associated method
    name for a given DCERPC service.

    Args:
        service_name (str): The name of the service to query (e.g., "SAMR").
        opnum (int): The operation number for which to retrieve the method info.

    Returns:
        tuple: A tuple containing the method name and note associated with the opnum,
               or (None, None) if not found.
    """
    service = dcerpc_services.get(service_name.lower())
    if not service:
        return None, f"Service {service_name} not found."

    method_info = service["Methods"].get(opnum)
    if method_info:
        return method_info["Method"], method_info["Note"]
    else:
        return None, f"Method with opnum {opnum} not found in service {service_name}."
