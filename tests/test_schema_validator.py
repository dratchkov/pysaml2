from pathutils import full_path as expand_full_path

from pytest import mark
from pytest import raises
from unittest.mock import patch
from urllib.request import OpenerDirector

from saml2 import create_class_from_xml_string
from saml2.saml import AttributeStatement
from saml2.sigver import validate_doc_with_schema
from saml2.xml.schema import XMLSchemaError
from saml2.xml.schema import validate as validate_doc_with_schema


@mark.parametrize("doc", ["invalid_metadata_file.xml", "empty_metadata_file.xml"])
def test_invalid_saml_metadata_doc(doc):
    with raises(XMLSchemaError):
        validate_doc_with_schema(expand_full_path(doc))


@mark.parametrize(
    "doc",
    [
        "InCommon-metadata.xml",
        "idp.xml",
        "idp_2.xml",
        "idp_aa.xml",
        "idp_all.xml",
        "idp_example.xml",
        "idp_soap.xml",
        "entity_cat_re.xml",
        "entity_cat_re_nren.xml",
        "entity_cat_rs.xml",
        "entity_cat_sfs_hei.xml",
        "entity_esi_and_coco_sp.xml",
        "entity_no_friendly_name_sp.xml",
        "extended.xml",
        "idp_slo_redirect.xml",
        "idp_uiinfo.xml",
        "metadata.aaitest.xml",
        "metadata.xml",
        "metadata_cert.xml",
        "metadata_example.xml",
        "metadata_sp_1.xml",
        "metadata_sp_1_no_encryption.xml",
        "metadata_sp_2.xml",
        "metasp.xml",
        "pdp_meta.xml",
        "servera.xml",
        "sp.xml",
        "sp_slo_redirect.xml",
        # XXX "swamid-1.0.xml",
        # XXX "swamid-2.0.xml",
        # TODO include the fed namespace
        # TODO see https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
        "urn-mace-swami.se-swamid-test-1.0-metadata.xml",
        "uu.xml",
        "vo_metadata.xml",
    ],
)
def test_valid_saml_metadata_doc(doc):
    result = validate_doc_with_schema(expand_full_path(doc))
    assert result == None


@mark.parametrize(
    "doc",
    [
        "attribute_response.xml",
        "okta_response.xml",
        "simplesamlphp_authnresponse.xml",
        "saml2_response.xml",
        "saml_false_signed.xml",
        "saml_hok.xml",
        "saml_hok_invalid.xml",
        "saml_signed.xml",
        "saml_unsigned.xml",
    ],
)
def test_valid_saml_response_doc(doc):
    result = validate_doc_with_schema(expand_full_path(doc))
    assert result == None


@mark.parametrize("doc", ["encrypted_attribute_statement.xml"])
def test_valid_saml_partial_doc(doc):
    result = validate_doc_with_schema(expand_full_path(doc))
    assert result == None


@mark.parametrize("doc", ["eidas_response.xml"])
def test_valid_eidas_saml_response_doc(doc):
    result = validate_doc_with_schema(expand_full_path(doc))
    assert result == None


def test_namespace_processing():
    elem = create_class_from_xml_string(
        AttributeStatement,
        """
        <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">
            <saml:Attribute Name="urn:mace:dir:attribute-def:uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue xsi:type="xs:string">alum11</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:mace:terena.org:attribute-def:schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue xsi:type="xs:string"/>
            </saml:Attribute>
        </saml:AttributeStatement>
        """,
    )
    validate_doc_with_schema(str(elem))


@mark.parametrize("prefix", ["xs", "xsd"])
def test_nil_attribute_value_retains_its_type_namespace(prefix):
    elem = create_class_from_xml_string(
        AttributeStatement,
        f'''<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:{prefix}="http://www.w3.org/2001/XMLSchema">
            <saml:Attribute Name="first"><saml:AttributeValue xsi:type="{prefix}:string">value</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="second"><saml:AttributeValue xsi:nil="true" xsi:type="{prefix}:string"/></saml:Attribute>
        </saml:AttributeStatement>''',
    )
    xml = str(elem)
    # Every sibling must carry the QName binding; a declaration on the first
    # value is not in scope for the second value.
    assert xml.count(f'xmlns:{prefix}="http://www.w3.org/2001/XMLSchema"') == 2
    validate_doc_with_schema(xml)
    assert elem.attribute[1].attribute_value[0].get_type() == f"{prefix}:string"


def test_document_schema_hints_cannot_trigger_network_access():
    doc = '''<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:assertion https://example.invalid/untrusted.xsd">
        <saml:Attribute Name="test"><saml:AttributeValue>value</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>'''
    with patch.object(OpenerDirector, "open", side_effect=AssertionError("Unexpected resource access")):
        validate_doc_with_schema(doc)


@mark.parametrize("location", ["file:///should-not-be-opened", "https://example.invalid/entity"])
def test_external_entities_are_rejected_without_resource_access(location):
    doc = f'''<!DOCTYPE test [<!ENTITY external SYSTEM "{location}">]>
        <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Attribute Name="test"><saml:AttributeValue>&external;</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>'''
    with patch.object(OpenerDirector, "open", side_effect=AssertionError("Unexpected resource access")) as access:
        with raises(XMLSchemaError):
            validate_doc_with_schema(doc)
        access.assert_not_called()


def test_remote_document_url_is_rejected_without_network_access():
    with patch.object(OpenerDirector, "open", side_effect=AssertionError("Unexpected resource access")) as access:
        with raises(XMLSchemaError):
            validate_doc_with_schema("https://example.invalid/metadata.xml")
        access.assert_not_called()
