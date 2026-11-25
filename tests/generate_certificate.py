from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


CERT_DIR = Path(__file__).parent / "certs"
CERT_DIR.mkdir(exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Certificate identity
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
])

# Build certificate
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=7))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))
        ]),
        critical=False
    )
    .sign(private_key, hashes.SHA256())
)

# Save private key
(CERT_DIR / "server.key").write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
)

# Save certificate
(CERT_DIR / "server.crt").write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)

print("Test certificate generated successfully.")