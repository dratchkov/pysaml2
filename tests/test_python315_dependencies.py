"""Dependency compatibility must not remove the pinned certificate-verification fix."""
from datetime import datetime, timedelta, timezone
from importlib.metadata import requires

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from packaging.requirements import Requirement
import pytest

from saml2.cert import OpenSSLWrapper


def selected_requirements(python_version):
    environment = {"python_version": python_version}
    return {
        requirement.name.lower(): requirement
        for entry in requires("pysaml2")
        for requirement in [Requirement(entry)]
        if requirement.marker is None or requirement.marker.evaluate(environment)
    }


def test_python315_selects_new_xml_stack_and_preserves_security_floors():
    selected = selected_requirements("3.15")
    assert "4.3.2" in selected["xmlschema"].specifier
    assert "2.5.1" not in selected["xmlschema"].specifier
    assert "46.0.5" in selected["cryptography"].specifier
    assert "46.0.4" not in selected["cryptography"].specifier
    assert "25.3.0" in selected["pyopenssl"].specifier
    assert "24.2.1" not in selected["pyopenssl"].specifier


@pytest.mark.parametrize("python_version", ["3.9", "3.10", "3.14"])
def test_older_python_keeps_existing_xml_stack(python_version):
    selected = selected_requirements(python_version)
    assert "2.5.1" in selected["xmlschema"].specifier
    assert "4.3.2" not in selected["xmlschema"].specifier


@pytest.mark.parametrize("algorithm", ["rsa", "ec"])
def test_patched_verifier_accepts_correct_issuer_and_rejects_wrong_issuer(algorithm):
    def key():
        return (rsa.generate_private_key(public_exponent=65537, key_size=2048)
                if algorithm == "rsa" else ec.generate_private_key(ec.SECP256R1()))

    now = datetime.now(timezone.utc)
    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA")])
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test leaf")])
    issuer_key, wrong_key, leaf_key = key(), key(), key()

    def certificate(subject, public_key, signing_key):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1)).sign(signing_key, hashes.SHA256())
                .public_bytes(serialization.Encoding.PEM).decode("ascii"))

    issuer = certificate(issuer_name, issuer_key.public_key(), issuer_key)
    wrong_issuer = certificate(issuer_name, wrong_key.public_key(), wrong_key)
    leaf = certificate(leaf_name, leaf_key.public_key(), issuer_key)
    verifier = OpenSSLWrapper()
    assert verifier.verify(issuer, leaf)[0] is True
    assert verifier.verify(wrong_issuer, leaf)[0] is False
