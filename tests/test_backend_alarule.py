import pytest
from sigma.collection import SigmaCollection
from sigma.backends.alarule import alaruleBackend


@pytest.fixture
def alarule_backend():
    return alaruleBackend()


# TODO: implement tests for some basic queries and their expected results.
def test_alarule_and_expression(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: taskscheduler
                source: taskscheduler
            detection:
                sel:
                    EventID: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['Test_Product\n| where fieldA=="valueA" and fieldB=="valueB"']
    )


def test_alarule_or_expression(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ['Test_Product\n| where fieldA=="valueA" or fieldB=="valueB"']
    )


def test_alarule_and_or_expression(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            'Test_Product\n| where ((fieldA in ("valueA1", "valueA2")) and (fieldB in ("valueB1", "valueB2")))'
        ]
    )


def test_alarule_or_and_expression(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            'Test_Product\n| where (fieldA=="valueA1" and fieldB=="valueB1") or (fieldA=="valueA2" and fieldB=="valueB2")'
        ]
    )


def test_alarule_in_expression(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == [
            'Test_Product\n| where fieldA=="valueA" or fieldA=="valueB" or fieldA startswith "valueC"'
        ]
    )


def test_alarule_regex_query(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == ['Test_Product\n| where (fieldA matches regex "foo.*bar" and fieldB=="foo")']
    )


def test_alarule_cidr_query(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ['Test_Product\n| where ipv4_is_in_range(field, "192.168.0.0/16")']
    )


def test_alarule_field_name_with_whitespace(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value fajweio
                condition: sel
        """
            )
        )
        == ['Test_Product\n| where ["field name"]=="value"']
    )


def test_alarule_field_name_dynamic(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1.value1: value fajweio
                condition: sel
            tags:
                - attack.defense_evasion
                - attack.t1548
        """
            ),
            output_format='KQL',
        )
        == ['Test_Product\n| where ["field name"]=="value"']
    )


def test_alarule_field_name_dynamic(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1.value1: value fajweio
                condition: sel
            tags:
                - attack.defense_evasion
                - attack.t1548
        """
            ),
            output_format='ala_rule',
        )
        == [
            '{"displayName": "Test", "description": "None Technique: .", "severity": "medium", "enabled": true, "query": "Test_Product\\n| where parse_json(Field1)[\\"value1\\"]==\\"value fajweio\\"", "queryFrequency": "PT30M", "queryPeriod": "PT30M", "triggerOperator": "GreaterThan", "triggerThreshold": 0, "suppressionDuration": "PT2H30M", "suppressionEnabled": true, "tactics": [], "techniques": []}'
        ]
    )


# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.


def test_alarule_format1_output(alarule_backend: alaruleBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format
    pass


def test_alarule_format2_output(alarule_backend: alaruleBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format
    pass


ala_rule_backend = alaruleBackend()
test_alarule_field_name_dynamic(ala_rule_backend)
test_alarule_or_expression(ala_rule_backend)
