import socket
import ssl
import sys
from io import StringIO
import argparse
from datetime import datetime
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
import requests

domain = argparse.ArgumentParser(description='SSL Scout')
domain.add_argument('-d','--domain', dest='Domain',
                    action='store', required=True, help='Domain name is required ( e.g. google.com )' )
domain.add_argument('-o','--output', help='Save results to file')
args = domain.parse_args()

port = 443


def show_banner():
    print(r"""
         
    ███████╗███████╗██╗         ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
    ██╔════╝██╔════╝██║         ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
    ███████╗███████╗██║         ███████╗██║     ██║   ██║██║   ██║   ██║   
    ╚════██║╚════██║██║         ╚════██║██║     ██║   ██║██║   ██║   ██║   
    ███████║███████║███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
    ╚══════╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

    SSL/TLS Certificate Analyzer v1.0
    """)


def main():
    show_banner()


    port = 443
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ssl_safety = ssl.create_default_context()
    secure = ssl_safety.wrap_socket(sock, server_hostname=args.Domain)

    secure.connect((args.Domain, port))

    certificate = secure.getpeercert()

    output_capture = StringIO()
    original_stdout = sys.stdout
    sys.stdout = output_capture


    print(f"certificate obtained for: {args.Domain}")

    def expiry():
        month_map = {
            'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
            'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
            'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
        }

        if certificate:
            ssl_date = certificate.get('notAfter', 'Unknown')
            parts_date = ssl_date.split()
            month = parts_date[0]
            day = parts_date[1]
            year = parts_date[3]
            month_update = month_map[month]
            formatted_cert_date = year + month_update + day
            date_today = datetime.today().strftime('%Y%m%d')
            if formatted_cert_date > date_today:
                print("Certificate is still valid")
                cert_number = datetime(int(year), int(month_update), int(day))
                date_number = datetime.today()
                gap = (cert_number - date_number).days
                return {"days": gap, "expiry_date": ssl_date}

            else:
                print("Certificate is expired")

        else:
            print("No certificate found")


    def issuer():
        if certificate:
            issuing = certificate.get('issuer', 'Unknown')
            invalid = "Unknown"
            for field in issuing:
                if field[0][0] == 'organizationName':
                    organization = field[0][1]
                    break
            print(f"The certificate issued by \n" "=== " f"{organization}" " ===")


    def encryption():
        if certificate:
            binary = secure.getpeercert(binary_form=True)
            certificate_binary = x509.load_der_x509_certificate(binary, default_backend())
            public_key = certificate_binary.public_key()

            print(f"Public Key Type: {type(public_key).__name__}")
            if hasattr(public_key, 'key_size'):
                print(f"Key Teeth: {public_key.key_size}")
            else:
                print("This lock measures strength differently")
        else:
            print("No encryption can be retrieved")
            pass

    def ocsp_check():
        if certificate:
            ocsp_urls = certificate.get('OCSP', [])

            if ocsp_urls:
                print("REVOCATION CHECKING: ENABLED")
                print(f"Servers: {len(ocsp_urls)} OCSP endpoint(s)")


                for url in ocsp_urls:
                    try:
                        response = requests.head(url, timeout=5, allow_redirects=True)
                        if response.status_code == 200:
                            print(f"{url}: ACTIVE")
                        else:
                            print(f"{url}: HTTP {response.status_code}")
                    except:
                        print(f"{url}: OFFLINE")

                print("SECURITY STATUS: Protected against revocation attacks")
                print("Full validation requires issuer certificate chain")

            else:
                print("REVOCATION CHECKING: DISABLED")
                print("Certificate cannot be revoked if compromised!")

    def sub_domain():
        if certificate:
            san_list = certificate.get('subjectAltName', [])

            if san_list:
                print("\nIP Addresses for Certificate Domains:")

                for domain_type, domain_name in san_list:
                    if domain_type == 'DNS' and "*" not in domain_name:
                        try:
                            ip_address = socket.gethostbyname(domain_name)
                            print(f"{domain_name}: {ip_address}")
                        except:
                            print(f"{domain_name}: Could not resolve IP")
            else:
                print("No domain information in certificate")

    print("\n=======================================")
    issuer()
    print("\n=======================================")
    expiry()
    print("\n=======================================")
    encryption()
    print("\n=======================================")
    ocsp_check()
    print("\n=======================================")
    sub_domain()


    all_output = output_capture.getvalue()
    sys.stdout = original_stdout


    print(all_output)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(all_output)
            print(f"\nResults saved to: {args.output}")
        except Exception as e:
            print(f"Error saving file: {e}")

    secure.close()

if __name__ == '__main__':
    main()
