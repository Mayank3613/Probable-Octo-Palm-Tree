import ssl
import socket
from typing import List, Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def extract_certificate_sans(hostname: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """
    Connects to the target hostname, pulls the raw TLS certificate,
    and extracts Subject Alternative Names (SANs) and Issuer info.
    This helps correlate domains that share the same multi-domain certificate.
    """
    result = {
        "hostname": hostname,
        "success": False,
        "issuer": None,
        "subject": None,
        "sans": [],
        "error": None
    }
    
    try:
        # Create a raw socket and wrap it to grab the unverified certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                
                # Parse the DER certificate using cryptography
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                # Extract Issuer and Subject
                result["issuer"] = cert.issuer.rfc4514_string()
                result["subject"] = cert.subject.rfc4514_string()
                
                # Extract SANs (Subject Alternative Names)
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    sans = ext.value.get_values_for_type(x509.DNSName)
                    result["sans"] = list(sans)
                except x509.ExtensionNotFound:
                    pass
                
                result["success"] = True
                
    except Exception as e:
        result["error"] = str(e)
        
    return result

if __name__ == "__main__":
    # Test execution
    res = extract_certificate_sans("example.com")
    print(res)
