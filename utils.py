import importlib
import pkgutil
import re
import base64
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def is_prime(n):
    """
    Checks if a given number is a prime number.
    
    A prime number is an integer greater than 1 that has no divisors
    other than 1 and itself. This function returns False for numbers
    less than or equal to 1.
    
    Parameters:
        n (int): The number to check.
    
    Returns:
        bool: True if the number is prime, False otherwise.
    """
    if n <= 1:
        return False  # Numbers <= 1 are not prime
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False  # If n is divisible by i, then it's not a prime number
    return True  # If no divisors were found, n is prime


def generate_primes(limit):
    """
    Generates a list of prime numbers up to a given limit.
    
    This function iterates through all numbers starting from 2 up to the specified limit
    and uses the is_prime function to determine if each number is prime. The prime numbers
    found are added to a list which is then returned.
    
    Parameters:
        limit (int): The upper limit for generating prime numbers.
    
    Returns:
        list: A list of prime numbers from 2 up to the limit.
    """
    primes = []  # List to store prime numbers
    for num in range(2, limit + 1):
        if is_prime(num):
            primes.append(num)  # Add the prime number to the list
    return primes  # Return the list of prime numbers

def extract_text_messages(data):
    """
    Extract all messages with 'textMessage' from the input JSON-like object.
    :param data: JSON object containing conversation data
    :return: List of messages with 'textMessage'
    """
    text_messages = []
 
    # Parcours de la liste des messages dans l'objet 'messages'
    if 'messages' in data and 'message' in data['messages']:
        for message in data['messages']['message']:
            # Vérifie si 'content' contient 'textMessage'
            if 'content' in message and 'textMessage' in message['content']:
                text_messages.append(message['content']['textMessage']['textPlain'])
 
    return text_messages

def camel_to_snake(camel_str):
    """
    Converts a camelCase or PascalCase string to snake_case.

    :param camel_str: The camelCase string to convert.
    :return: The snake_case version of the input string.
    """
    # Use regex to insert an underscore before each uppercase letter followed by a lowercase letter
    # and convert the entire string to lowercase.
    snake_str = re.sub(r'(?<!^)(?=[A-Z])', '_', camel_str).lower()
    return snake_str

def dispatcher(package_name, function_name, **kwargs):
    """
    Executes a function from a module within a given package using the function name and package name.

    :param package_name: Name of the package containing the modules (e.g., 'my_package').
    :param function_name: Name of the function to execute (should match the function name within a module).
    :param args: Positional arguments to pass to the function.
    :param kwargs: Keyword arguments to pass to the function.
    :return: The result of the executed function.
    :raises ValueError: If the function is not found within the package.
    """
    function_name = camel_to_snake(function_name)
    # Use pkgutil to iterate over all modules in the specified package directory.
    # pkgutil.iter_modules returns information about modules and sub-packages.
    # The package directory is specified by replacing '.' with '/' in the package_name for proper pathing.
    for _, module_name, _ in pkgutil.iter_modules([package_name.replace(".", "/")]):
        
        # Check if the module name matches the function name (assuming each module has a single function).
        if module_name == function_name:
            
            # Dynamically import the module containing the function using importlib.
            # importlib.import_module loads the specified module, allowing access to its functions.
            module = importlib.import_module(f"{package_name}.{module_name}")
            
            # Retrieve the function from the module by name.
            # getattr tries to get the attribute (function) by name from the module.
            # If it finds a callable function, it will execute it with the provided arguments.
            func = getattr(module, function_name, None)
            if func and callable(func):
                return func(**kwargs)  # Execute the function and return its result
    
    # If the function is not found in the specified package, return None.
    return None

def is_valid_msisdn(msisdn):
    """
    Validate the given MSISDN against specified patterns.
    
    Conditions:
    - Case 1: Format should be 081XXXXXXX, 082XXXXXXX, or 083XXXXXXX
    - Case 2: Format should be 81XXXXXXX, 82XXXXXXX, or 83XXXXXXX
    - Case 3: Format should be 24381XXXXXXX, 24382XXXXXXX, or 24383XXXXXXX
    - Case 4: Format should be +24381XXXXXXX, +24382XXXXXXX, or +24383XXXXXXX
    - Case 5: Format should be 0024381XXXXXXX, 0024382XXXXXXX, or 0024383XXXXXXX
    
    Args:
    msisdn (str): The MSISDN to validate.
    
    Returns:
    bool: True if the MSISDN is valid, False otherwise.
    """
    
    # Define the patterns for each case
    patterns = [
        r'^08[1-3, 6]\d{7}$',         # Case 1
        r'^8[1-3, 6]\d{7}$',          # Case 2
        r'^2438[1-3, 6]\d{7}$',       # Case 3
        r'^\+2438[1-3, 6]\d{7}$',     # Case 4
        r'^002438[1-3, 6]\d{7}$'      # Case 5
    ]
    
    # Check if msisdn matches any of the patterns
    return any(re.match(pattern, msisdn) for pattern in patterns)

def normalize_phone_number(phone_number):
    """
    Normalize a Congolese phone number to the format 0XXYYYYYYY.

    This function accepts phone numbers in various formats:
        - 081XXXXXXX, 082XXXXXXX, or 083XXXXXXX
        - 81XXXXXXX, 82XXXXXXX, or 83XXXXXXX
        - 24381XXXXXXX, 24382XXXXXXX, or 24383XXXXXXX
        - +24381XXXXXXX, +24382XXXXXXX, or +24383XXXXXXX
        - 0024381XXXXXXX, 0024382XXXXXXX, or 0024383XXXXXXX

    It strips non-digit characters and converts the number to the standard local format:
    0XXYYYYYYY (e.g., 0811234567).

    Parameters:
        phone_number (str): The phone number string in any of the accepted formats.

    Returns:
        str or None: The normalized phone number in the 0XXYYYYYYY format, or None if invalid.
    """
    # Remove all non-digit characters
    phone_number = re.sub(r'\D', '', phone_number)

    # Handle different formats
    if phone_number.startswith('00243'):
        phone_number = phone_number[5:]
    elif phone_number.startswith('243'):
        phone_number = phone_number[3:]
    elif phone_number.startswith('8') and len(phone_number) == 9:
        phone_number = '0' + phone_number

    if not phone_number.startswith('0'):
        phone_number = '0' + phone_number
    # Validate the final format
    if re.match(r'^0(81|82|83)\d{7}$', phone_number):
        return phone_number
    else:
        return None  # Invalid number

def parse_string_to_dict(data_str):
    """
    Parses a formatted string into a dictionary.

    Handles edge cases like:
    - Empty values
    - Values with colons or commas inside (e.g., code snippets or formats)
    - Irregular spacing
    - Trailing or malformed key-value pairs

    Parameters:
        data_str (str): The raw input string to parse.

    Returns:
        dict: A dictionary containing the parsed key-value pairs.
    """
    # Regular expression to match key-value pairs with optional whitespace
    pattern = re.compile(r'([^:,]+?):\s*(.*?)(?=, [^:,]+?:|$)')
    
    # Dictionary to hold the parsed data
    data_dict = {}

    # Find all key-value pairs using the regex
    for match in pattern.findall(data_str):
        key = match[0].strip()
        value = match[1].strip().strip('"')  # Strip quotes and whitespace
        data_dict[key] = value

    return data_dict

def extract_whatsapp_text(payload: dict):
    """
    Extract text message information from a WhatsApp Cloud API webhook payload.

    This function safely parses the incoming webhook JSON and extracts:
    - Sender phone number (from)
    - Sender profile name
    - Text message body

    The function ONLY processes messages of type "text".
    If the payload does not contain a valid text message, it returns None.

    Args:
        payload (dict): Raw webhook payload received from WhatsApp Cloud API

    Returns:
        dict | None: A dictionary containing extracted message data:
            {
                "from": str,           # WhatsApp sender phone number
                "profile_name": str,   # Sender display name
                "text": str            # Message text body
            }
        or None if the message is not a text message or payload is invalid.
    """

    try:
        # Navigate to the main payload structure
        entry = payload.get("entry", [])[0]
        change = entry.get("changes", [])[0]
        value = change.get("value", {})

        # Extract messages and contacts arrays
        messages = value.get("messages", [])
        contacts = value.get("contacts", [])

        # If no messages are present, stop processing
        if not messages:
            return None

        message = messages[0]

        # Ensure the message type is "text"
        if message.get("type") != "text":
            return None

        # Extract text body and sender phone number
        text_body = message.get("text", {}).get("body")
        from_number = message.get("from")

        # Extract sender profile name if available
        profile_name = None
        if contacts:
            profile_name = contacts[0].get("profile", {}).get("name")

        return {
            "from": from_number,
            "profile_name": profile_name,
            "text": text_body
        }

    except (IndexError, AttributeError):
        # Return None if payload structure is unexpected
        return None
    
def extract_message_id(payload: dict) -> str | None:
    """
    Extract WhatsApp message ID safely from webhook payload.
    """
    try:
        return payload["entry"][0]["changes"][0]["value"]["messages"][0]["id"]
    except (KeyError, IndexError, TypeError):
        return None

def load_private_key(path="private_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,   # b"password" si la clé est protégée
            backend=default_backend()
        )

def decrypt_aes_key(private_key, encrypted_aes_key_b64: str) -> bytes:
    encrypted_key = base64.b64decode(encrypted_aes_key_b64)

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_flow_payload(aes_key, encrypted_payload_b64, iv_b64):
    encrypted_payload = base64.b64decode(encrypted_payload_b64)
    iv = base64.b64decode(iv_b64)

    aesgcm = AESGCM(aes_key)
    decrypted_bytes = aesgcm.decrypt(iv, encrypted_payload, None)

    return json.loads(decrypted_bytes.decode("utf-8"))