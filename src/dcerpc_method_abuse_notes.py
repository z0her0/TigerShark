"""
Purpose: Retrieves specific information about DCERPC services based on user input (service name and operation number).

Functionality:
  The get_dcerpc_info function fetches detailed information for a given service and its operation number.
  It also has the capability to list all available services if list_services is set to True.

Integration: Imports dcerpc_services from dcerpc_data.py to access the data dictionary.
"""

from typing import Tuple, Union, List, Dict, Any

from make_colorful import Color
from dcerpc_data import dcerpc_services


def display_summary_detail(data: Dict[str, Any], key: str) -> None:
    """
    Displays a detailed view of a specific summary key from the DCERPC data.

    This function checks if the given key is present in the 'summary' section of the data.
    If found, it prints the detailed information for that key, otherwise it prints an error message.
    """
    if "summary" in data and key in data["summary"]:
        summary_detail = data["summary"][key]
        print(f"\n{Color.BOLD + Color.AQUA}{key.capitalize()} Detail{Color.END}:\n{Color.GREY}{summary_detail}{Color.END}\n")
    else:
        print(f"No detailed data available for '{key}'.")


def format_method_details(method_details):
    """
    Formats the method details for display.

    This function iterates over the key-value pairs in the method details, applying color formatting
    and adjusting the indentation for better readability.
    """
    formatted_details = []
    for key, value in method_details.items():
        formatted_value = value.replace("\n", "\n         ")
        key_color = Color.BOLD + Color.SKY_BLUE
        value_color = Color.GREY
        formatted_details.append(f"  {key_color}{key}{Color.END}:  {value_color}{formatted_value}{Color.END}")

    return "\n".join(formatted_details)


def list_methods(service_name: str, data: Dict[str, Any]) -> None:
    """
    Lists all the methods available for a specified DCERPC service.

    This function checks if the specified service exists and has methods defined in the provided data.
    If so, it prints the list of methods with their details, else prints an error message.
    """
    
    # Check if the specified service exists in the data and is a dictionary
    if service_name in data and isinstance(data[service_name], dict):
        service_data = data[service_name]

        # Check if the service has methods defined
        if "Methods" in service_data and isinstance(service_data["Methods"], dict):
            
            # Apply color formatting for the service name
            service_name_color = Color.BOLD + Color.GOLD
            print(f"\n{service_name_color}Methods in {service_name}{Color.END}:\n")

            # Iterate through each method and display its details
            for method_id, method_details in service_data["Methods"].items():
                
                # Apply color formatting for the method ID
                method_id_color = Color.BOLD + Color.CYAN
                print(f"{method_id_color}- Opnum {method_id}{Color.END}:\n{format_method_details(method_details)}\n")
        else:
            
            # If no methods are found for the service, display a message in red
            no_methods_color = Color.BOLD + Color.LIGHTRED
            print(f"{no_methods_color}No methods found for {service_name}.{Color.END}")
    else:
        
        # If the service is not found in the data, display a message in red
        service_not_found_color = Color.BOLD + Color.LIGHTRED
        print(f"{service_not_found_color}Service {service_name} not found.{Color.END}")


def enhanced_search(keyword: str, data: Dict[str, Any]) -> List[str]:
    """
    Enhanced search in the dcerpc_services dictionary.
    """
    keyword_lower = keyword.lower()
    results = []

    # Define colors for different parts of the search results
    service_color = Color.BOLD + Color.AQUA
    method_color = Color.BOLD + Color.YELLOW
    detail_color = Color.GREEN
    text_color = Color.GREY

    for service_name, service_data in data.items():
        
        # Check if the service data is a dictionary and contains the 'Methods' key
        if isinstance(service_data, dict) and "Methods" in service_data:
            for method_id, method_details in service_data["Methods"].items():
                
                # Check if any part of the method details contains the keyword (case-insensitive)
                if any(keyword_lower in str(value).lower() for value in method_details.values()):
                    
                    # Format the service name and method ID with color
                    result = f"{service_color}Service: {service_name}, {method_color}Method {method_id}:{Color.END}"
                    
                    # Iterate through each detail key-value pair
                    for key, value in method_details.items():
                        
                        # Format the value with indentation and color
                        formatted_value = value.replace("\n", f"\n{text_color}    ")
                        
                        # Append the formatted detail to the result string
                        result += f"\n  {detail_color}{key}: {text_color}{formatted_value}{Color.END}"
                    
                    # Add the fully formatted result to the results list
                    results.append(result)

    return results


def get_dcerpc_info(service_name: str = "", opnum: int = 0, list_services: bool = False) -> Union[Tuple[None, str, None, None, None], Tuple[int, int, int, int, int], List[str]]:
    """
    Retrieves information about a specific operation number (opnum) for a given DCERPC service.
    """
    if list_services:
        return [service for service in dcerpc_services.keys() if isinstance(dcerpc_services[service], dict)]

    if service_name is None or opnum is None:
        return None, "Service name or opnum not provided.", None, None, None

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
