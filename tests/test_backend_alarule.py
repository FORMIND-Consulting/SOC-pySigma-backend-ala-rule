import pytest
from sigma.collection import SigmaCollection
from sigma.backends.alarule import alaruleBackend


@pytest.fixture
def alarule_backend():
    return alaruleBackend()


# TODO: implement tests for some basic queries and their expected results.
def test_KQL_and_expression(alarule_backend: alaruleBackend):
    assert (
        alarule_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: Test_Product
                source: Test_Product
            detection:
                sel:
                    EventID: valueA
                    fieldB: valueB
                condition: sel
        """
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where (event_id=="valueA" and fieldB=="valueB")'
    )


def test_KQL_or_expression(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where fieldA=="valueA" or fieldB=="valueB"'
    )


def test_KQL_and_or_expression(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where ((fieldA in ("valueA1", "valueA2")) and (fieldB in ("valueB1", "valueB2")))'
    )


def test_KQL_or_and_expression(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where (fieldA=="valueA1" and fieldB=="valueB1") or (fieldA=="valueA2" and fieldB=="valueB2")'
    )


def test_KQL_in_expression(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where fieldA=="valueA" or fieldA=="valueB" or fieldA startswith "valueC"'
    )


def test_KQL_regex_query(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where (fieldA matches regex "foo.*bar" and fieldB=="foo")'
    )


def test_KQL_cidr_query(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where ipv4_is_in_range(field, "192.168.0.0/16")'
    )


def test_KQL_field_name_with_whitespace(alarule_backend: alaruleBackend):
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
            ),
            output_format='KQL',
        )
        == 'Test_Product\n| where ["field name"]=="value fajweio"'
    )


def test_KQL_field_name_dynamic(alarule_backend: alaruleBackend):
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
        == 'Test_Product\n| where parse_json(Field1)["value1"]=="value fajweio"'
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
        == '{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "contentVersion": "1.0.0.0", "parameters": {"workspace": {"type": "String"}}, "resources": [{"id": "[concat(resourceId(\'Microsoft.OperationalInsights/workspaces/providers\', parameters(\'workspace\'), \'Microsoft.SecurityInsights\'),\'/alertRules/None\')]", "name": "[concat(parameters(\'workspace\'),\'/Microsoft.SecurityInsights/None\')]", "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "kind": "Scheduled", "apiVersion": "2022-09-01-preview", "properties": {"displayName": "Test", "description": "None Technique: .", "severity": "Medium", "enabled": true, "query": "Test_Product\\n| where parse_json(Field1)[\\"value1\\"]==\\"value fajweio\\"", "queryFrequency": "PT30M", "queryPeriod": "PT30M", "triggerOperator": "GreaterThan", "triggerThreshold": 0, "suppressionDuration": "PT2H30M", "suppressionEnabled": true, "tactics": [], "techniques": [], "incidentConfiguration": {"createIncident": true, "groupingConfiguration": {"enabled": false, "reopenClosedIncident": false, "lookbackDuration": "PT2H30M", "matchingMethod": "AllEntities", "groupByEntities": [], "groupByAlertDetails": [], "groupByCustomDetails": []}}, "eventGroupingSettings": {"aggregationKind": "SingleAlert"}, "alertDetailsOverride": null, "customDetails": null, "sentinelEntitiesMappings": null}}]}'
    )
