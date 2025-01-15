from datetime import timedelta
import json
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
from sigma.collection import SigmaCollection
from sigma.conversion.deferred import DeferredQueryExpression

from sigma.pipelines.alarule import alarule_pipeline

import re
from typing import ClassVar, Dict, Optional, Tuple, Pattern, List, Any, Union


class alaruleBackend(TextQueryBackend):
    """ala-rule backend."""

    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[
        str
    ] = "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[
        str
    ] = "=="  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[
        str
    ] = "'"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\\w+$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[
        bool
    ] = True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape: ClassVar[
        str
    ] = "\\"  # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote: ClassVar[
        bool
    ] = True  # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = re.compile(
        "\\s|\\."
    )  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[
        str
    ] = '"'  # string quoting character (added as escaping character)
    escape_char: ClassVar[
        str
    ] = "\\"  # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[
        str
    ] = "\\"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[
        Dict[bool, str]
    ] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    endswith_expression: ClassVar[str] = "{field} endswith {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[
        str
    ] = "match"  # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    re_expression: ClassVar[
        str
    ] = '{field} matches regex "{regex}"'  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char: ClassVar[
        str
    ] = "\\"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard
    cidr_expression: ClassVar[
        str
    ] = 'ipv4_is_in_range({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression: ClassVar[
        str
    ] = "{field} in ({value})"  # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression: ClassVar[
        str
    ] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[
        str
    ] = "isnull({field})"  # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = True  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[
        bool
    ] = False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression: ClassVar[
        str
    ] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator: ClassVar[
        str
    ] = "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator: ClassVar[
        str
    ] = "contains-all"  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[
        str
    ] = '"{value}"'  # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[
        str
    ] = '{value}'  # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[
        str
    ] = '_=~{value}'  # Expression for regular expression not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[
        str
    ] = "\n| "  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[
        str
    ] = "\n| "  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[
        str
    ] = "*"  # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def __init__(self, *args, **kwargs):
        """Initialize field mappings."""
        super().__init__(*args, **kwargs)
        self.processing_pipeline = alarule_pipeline()

    def getTable(self, category, product, service):
        if category == "process_creation":
            table = "SecurityEvent"
            self.eventid = "1"
        elif service and service.lower() == "security":
            table = "SecurityEvent"
        elif service and service.lower() == "sysmon":
            table = "Sysmon"
        elif service and service.lower() == "powershell":
            table = "Event"
        elif service and service.lower() == "office365":
            table = "OfficeActivity"
        elif service and service.lower() in ["azuread", "auditlogs"]:
            table = "AuditLogs"
        elif service and service.lower() in ["azureactivity", "activitylogs"]:
            table = "AzureActivity"
        elif service and service.lower() in ["signinlogs"]:
            table = "SigninLogs"
        elif service:
            if "-" in service:
                table = "-".join([item.capitalize() for item in service.split("-")])
            elif "_" in service:
                table = "_".join([item.capitalize() for item in service.split("_")])
            else:
                table = (
                    service.capitalize()
                    if service.islower() or service.isupper()
                    else service
                )

        elif product:
            if "-" in product:
                table = "-".join([item.capitalize() for item in product.split("-")])
            elif "_" in product:
                table = "_".join([item.capitalize() for item in product.split("_")])
            elif product.islower() or product.isupper():
                table = product.capitalize()
            else:
                table = product
        elif category:
            if "-" in category:
                table = "-".join([item.capitalize() for item in category.split("-")])
            elif "_" in category:
                table = "_".join([item.capitalize() for item in category.split("_")])
            elif category.islower() or category.isupper():
                table = category.capitalize()
            else:
                table = category
        return table

    def convert(
        self, rule_collection: SigmaCollection, output_format: Optional[str] = None
    ) -> Any:
        """
        Convert a Sigma ruleset into the target data structure. Usually the result are one or
        multiple queries, but might also be some arbitrary data structure required for further
        processing.
        """
        queries = []
        for rule in rule_collection.rules:
            for query in self.convert_rule(rule, output_format or self.default_format):
                category = rule.logsource.category
                product = rule.logsource.product
                service = rule.logsource.service
                table = self.getTable(category, product, service)
                if output_format in ['KQL', 'default']:
                    queries.append(f'{table}\n| where {query}')
                elif output_format == 'ala_rule':
                    query['query'] = f'{table}\n| where {query["query"]}'
                    queries.append({'id': str(rule.id), 'query': query})

        return self.finalize(queries, output_format or self.default_format)

    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            if (
                self.token_separator == self.and_token
            ):  # don't repeat the same thing triple times if separator equals and token
                joiner = self.and_token
            else:
                joiner = self.token_separator + self.and_token + self.token_separator

            return '({})'.format(
                joiner.join(
                    (
                        converted
                        for converted in (
                            self.convert_condition(arg, state)
                            if self.compare_precedence(cond, arg)
                            else self.convert_condition_group(arg, state)
                            for arg in cond.args
                        )
                        if converted is not None
                        and not isinstance(converted, DeferredQueryExpression)
                    )
                )
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def escape_and_quote_field(self, field_name: str) -> str:
        """
        Escape field name by prepending pattern matches of field_escape_pattern with field_escape
        string. If field_escape_quote is set to True (default) and field escaping string is defined
        in field_escape, all instances of the field quoting character are escaped before quoting.

        Quote field name with field_quote if field_quote_pattern (doesn't) matches the original
        (unescaped) field name. If field_quote_pattern_negation is set to True (default) the pattern matching
        result is negated, which is the default behavior. In this case the field name is quoted if
        the pattern doesn't matches.
        """
        if self.field_escape is not None:  # field name escaping
            if (
                self.field_escape_pattern is not None
            ):  # Match all occurrences of field_escape_pattern if defined and initialize match position set with result.
                match_positions = {
                    match.start()
                    for match in self.field_escape_pattern.finditer(field_name)
                }
            else:
                match_positions = set()

            if (
                self.field_escape_quote and self.field_quote is not None
            ):  # Add positions of quote string to match position set
                re_quote = re.compile(re.escape(self.field_quote))
                match_positions.update(
                    (match.start() for match in re_quote.finditer(field_name))
                )

            if match_positions:  # found matches, escape them
                r = [0] + list(sorted(match_positions)) + [len(field_name)]
                escaped_field_name = "".join(
                    field_name[r[i] : r[i + 1]]
                    if (i == 0)
                    else (self.field_escape + field_name[r[i] : r[i + 1]])
                    for i in range(len(r) - 1)
                )

            else:  # no matches, just pass original field name without escaping
                escaped_field_name = field_name
        else:
            escaped_field_name = field_name

        if '\\.' in escaped_field_name:
            fields = escaped_field_name.replace('\\.', '.').split('.')
            escaped_field_name_temp = ''
            for i, field in enumerate(fields):
                if i == 0:
                    escaped_field_name_temp = f'parse_json({field.title()})'
                elif i == len(fields) - 1:
                    escaped_field_name_temp = f'{escaped_field_name_temp}["{field}"]'
                else:
                    escaped_field_name_temp = (
                        f'parse_json({escaped_field_name_temp}["{field}"])'
                    )
            return escaped_field_name_temp

        if '\\ ' in escaped_field_name:
            return '["{}"]'.format(escaped_field_name.replace('\\ ', ' '))

        if self.field_quote is not None:  # Field quoting
            if self.field_quote_pattern is not None:  # Match field quote pattern...
                quote = bool(self.field_quote_pattern.match(escaped_field_name))
                if (
                    self.field_quote_pattern_negation
                ):  # ...negate result of matching, if requested...
                    quote = not quote
            else:
                quote = True

            if quote:  #  ...and quote if pattern (doesn't) matches
                return self.field_quote + escaped_field_name + self.field_quote

        return escaped_field_name

    def parse_severity(self, old_severity):
        if not old_severity:
            return "Medium"
        old_severity = old_severity.name.title()
        return "High" if old_severity == "Critical" else old_severity

    def timeframeToDelta(self, timeframe):
        time_unit = timeframe[-1:]
        duration = int(timeframe[:-1])
        return (
            time_unit == "s"
            and timedelta(seconds=duration)
            or time_unit == "m"
            and timedelta(minutes=duration)
            or time_unit == "h"
            and timedelta(hours=duration)
            or time_unit == "d"
            and timedelta(days=duration)
            or None
        )

    def iso8601_duration(self, delta):
        if not delta:
            return "PT0S"
        if not delta.seconds:
            return "P%dD" % (delta.days)
        days = delta.days and "%dD" % (delta.days) or ""
        hours = (
            delta.seconds // 3600 % 24 and "%dH" % (delta.seconds // 3600 % 24) or ""
        )
        minutes = delta.seconds // 60 % 60 and "%dM" % (delta.seconds // 60 % 60) or ""
        seconds = delta.seconds % 60 and "%dS" % (delta.seconds % 60) or ""
        return f"P{days}T{hours}{minutes}{seconds}"

    def finalize_query_KQL(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        # TODO: implement the per-query output for the output format KQL here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        print(query)
        return query

    def finalize_output_KQL(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format KQL here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return "\n".join(queries)

    def finalize_query_ala_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        # TODO: implement the per-query output for the output format ala_rule here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        techniques = []
        tactics = []

        timeframe = self.timeframeToDelta("30m")
        queryDuration = self.iso8601_duration(timeframe)
        suppressionDuration = self.iso8601_duration(timeframe * 5)

        rule = {
            "displayName": f"""{rule.title}""",
            "description": f'{getattr(rule, "description", "")} Technique: {",".join(techniques)}.',
            "severity": self.parse_severity(getattr(rule, 'level', 'medium')),
            "enabled": True,
            "query": query,
            "queryFrequency": queryDuration,
            "queryPeriod": queryDuration,
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": suppressionDuration,
            "suppressionEnabled": True,
            "tactics": tactics,
            "techniques": techniques,
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": False,
                    "reopenClosedIncident": False,
                    "lookbackDuration": suppressionDuration,
                    "matchingMethod": "AllEntities",
                    "groupByEntities": [],
                    "groupByAlertDetails": [],
                    "groupByCustomDetails": [],
                },
            },
            "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
            "alertDetailsOverride": None,
            "customDetails": None,
            "sentinelEntitiesMappings": None,
        }

        return rule

    def finalize_output_ala_rule(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format ala_rule here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        output = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {"workspace": {"type": "String"}},
            "resources": [],
        }

        for query in queries:
            output['resources'].append(
                {
                    "id": f"[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/{query['id']}')]",
                    "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/{query['id']}')]",
                    "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                    "kind": "Scheduled",
                    "apiVersion": "2022-09-01-preview",
                    "properties": query['query'],
                }
            )
        return json.dumps(output)
