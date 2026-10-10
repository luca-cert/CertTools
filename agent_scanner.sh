#!/usr/bin/env bash

set -u

NMAP_OUT="/tmp/general_nmap_scan.txt"
OUTPUT_FILE="/tmp/agent_scan_results.txt"

#
# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------
#

CONNECT_TIMEOUT=3
HEALTH_TIMEOUT=10
CHAT_TIMEOUT=30
FUZZ_TIMEOUT=5
OPENAPI_TIMEOUT=10
DOCS_TIMEOUT=10

#
# --------------------------------------------------------------------
# Arguments
# --------------------------------------------------------------------
#

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <wordlist>" >&2
    exit 1
fi

WORDLIST="$1"

if [[ ! -f "$NMAP_OUT" ]]; then
    echo "Error: Nmap output file not found: $NMAP_OUT" >&2
    exit 1
fi

if [[ ! -r "$WORDLIST" ]]; then
    echo "Error: Wordlist not found or not readable: $WORDLIST" >&2
    exit 1
fi

#
# --------------------------------------------------------------------
# Temporary directory
# --------------------------------------------------------------------
#

TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

#
# --------------------------------------------------------------------
# Start output
# --------------------------------------------------------------------
#

: > "$OUTPUT_FILE"

echo "Agent scan started."
echo "Nmap input : $NMAP_OUT"
echo "Wordlist   : $WORDLIST"
echo "Output     : $OUTPUT_FILE"
echo

current_ip=""

#
# --------------------------------------------------------------------
# Function: discover_openapi
#
# Attempts to retrieve /openapi.json.
#
# If that doesn't return a valid OpenAPI JSON document, /docs is
# requested as a secondary discovery mechanism.
#
# The function writes the extracted API surface into:
#
#   $OPENAPI_OUTPUT
#
# --------------------------------------------------------------------
#

discover_openapi() {
    local base_url="$1"

    local openapi_url="${base_url}/openapi.json"
    local docs_url="${base_url}/docs"

    local openapi_file
    local docs_file
    local status

    openapi_file="${TMP_DIR}/openapi.json"
    docs_file="${TMP_DIR}/docs.html"

    OPENAPI_FOUND="false"
    DOCS_FOUND="false"

    : > "$openapi_file"
    : > "$docs_file"

    #
    # ------------------------------------------------------------
    # Try /openapi.json
    # ------------------------------------------------------------
    #

    status="$(
        curl -sS \
            -o "$openapi_file" \
            -w "%{http_code}" \
            --connect-timeout "$CONNECT_TIMEOUT" \
            --max-time "$OPENAPI_TIMEOUT" \
            "$openapi_url" \
            2>/dev/null
    )"

    if [[ "$status" =~ ^2[0-9][0-9]$ ]] &&
       python3 - "$openapi_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)

    # Basic OpenAPI detection.
    if not isinstance(data, dict):
        sys.exit(1)

    if "paths" not in data:
        sys.exit(1)

    if not ("openapi" in data or "swagger" in data):
        sys.exit(1)

except Exception:
    sys.exit(1)
PY
    then
        OPENAPI_FOUND="true"

        {
            echo "OPENAPI / API SURFACE"
            echo "------------------------------------------------------------------"
            echo "Source: ${openapi_url}"
            echo "HTTP Status: ${status}"
            echo

            python3 - "$openapi_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

#
# API metadata
#
info = data.get("info", {})

if info.get("title"):
    print(f"Title: {info['title']}")

if info.get("version"):
    print(f"Version: {info['version']}")

if info.get("summary"):
    print(f"Summary: {info['summary']}")

if info.get("description"):
    description = str(info["description"]).strip()
    if description:
        print("Description:")
        print(description)

print()

#
# OpenAPI version
#
if data.get("openapi"):
    print(f"OpenAPI Version: {data['openapi']}")
elif data.get("swagger"):
    print(f"Swagger Version: {data['swagger']}")

print()

#
# Tags
#
tags = data.get("tags", [])

if tags:
    print("Tags:")
    for tag in tags:
        if isinstance(tag, dict):
            name = tag.get("name", "")
            desc = tag.get("description", "")

            if name:
                if desc:
                    print(f"  - {name}: {desc}")
                else:
                    print(f"  - {name}")
        elif isinstance(tag, str):
            print(f"  - {tag}")

    print()

#
# Paths / operations
#
paths = data.get("paths", {})

print(f"Documented Paths: {len(paths)}")
print()

if not paths:
    print("  No paths documented.")
    sys.exit(0)

http_methods = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace"
}

for path, path_item in paths.items():

    if not isinstance(path_item, dict):
        continue

    for method, operation in path_item.items():

        if method.lower() not in http_methods:
            continue

        method_upper = method.upper()

        if not isinstance(operation, dict):
            operation = {}

        print(f"  {method_upper:7} {path}")

        summary = operation.get("summary")
        description = operation.get("description")

        if summary:
            print(f"           Summary: {summary}")

        if description:
            description = str(description).strip().replace("\n", " ")
            if len(description) > 500:
                description = description[:497] + "..."
            print(f"           Description: {description}")

        #
        # Tags attached to operation
        #
        operation_tags = operation.get("tags", [])

        if operation_tags:
            print(
                "           Tags: " +
                ", ".join(str(x) for x in operation_tags)
            )

        #
        # Parameters
        #
        parameters = operation.get("parameters", [])

        if parameters:
            print("           Parameters:")

            for parameter in parameters:

                if not isinstance(parameter, dict):
                    continue

                name = parameter.get("name", "?")
                location = parameter.get("in", "?")
                required = parameter.get("required", False)

                parameter_type = ""

                schema = parameter.get("schema", {})

                if isinstance(schema, dict):
                    if schema.get("type"):
                        parameter_type = schema["type"]
                    elif schema.get("$ref"):
                        parameter_type = schema["$ref"]

                suffix = ""

                if parameter_type:
                    suffix += f", type={parameter_type}"

                if required:
                    suffix += ", required"

                print(
                    f"             - {name} "
                    f"(in={location}{suffix})"
                )

        #
        # Request body
        #
        request_body = operation.get("requestBody")

        if isinstance(request_body, dict):

            content = request_body.get("content", {})

            if content:
                print("           Request Body:")

                for content_type, content_spec in content.items():

                    schema_name = ""

                    if isinstance(content_spec, dict):
                        schema = content_spec.get("schema", {})

                        if isinstance(schema, dict):
                            if schema.get("$ref"):
                                schema_name = schema["$ref"]
                            elif schema.get("type"):
                                schema_name = schema["type"]

                    if schema_name:
                        print(
                            f"             - {content_type} "
                            f"(schema={schema_name})"
                        )
                    else:
                        print(f"             - {content_type}")

        #
        # Security
        #
        security = operation.get("security")

        if security:
            schemes = []

            for security_requirement in security:
                if isinstance(security_requirement, dict):
                    schemes.extend(security_requirement.keys())

            if schemes:
                print(
                    "           Security: " +
                    ", ".join(schemes)
                )

        print()

#
# Security schemes
#
components = data.get("components", {})

if isinstance(components, dict):
    security_schemes = components.get("securitySchemes", {})

    if security_schemes:
        print("Security Schemes:")

        for name, scheme in security_schemes.items():

            if not isinstance(scheme, dict):
                continue

            scheme_type = scheme.get("type", "unknown")
            scheme_name = scheme.get("scheme", "")
            bearer_format = scheme.get("bearerFormat", "")

            details = scheme_type

            if scheme_name:
                details += f", scheme={scheme_name}"

            if bearer_format:
                details += f", format={bearer_format}"

            print(f"  - {name}: {details}")

        print()

PY

            echo
        } >> "$CURRENT_AGENT_OUTPUT"

    fi

    #
    # ------------------------------------------------------------
    # If /openapi.json isn't available, try /docs.
    # ------------------------------------------------------------
    #

    if [[ "$OPENAPI_FOUND" != "true" ]]; then

        status="$(
            curl -sS \
                -o "$docs_file" \
                -w "%{http_code}" \
                --connect-timeout "$CONNECT_TIMEOUT" \
                --max-time "$DOCS_TIMEOUT" \
                "$docs_url" \
                2>/dev/null
        )"

        if [[ "$status" =~ ^2[0-9][0-9]$ ]] &&
           grep -qiE 'swagger|openapi|redoc' "$docs_file"; then

            DOCS_FOUND="true"

            {
                echo "API DOCUMENTATION"
                echo "------------------------------------------------------------------"
                echo "Source: ${docs_url}"
                echo "HTTP Status: ${status}"
                echo "Documentation UI detected."
                echo
            } >> "$CURRENT_AGENT_OUTPUT"

            #
            # Try to discover the OpenAPI URL referenced by Swagger UI.
            #
            discovered_openapi="$(
                python3 - "$docs_file" <<'PY'
import re
import sys

try:
    html = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()

    patterns = [
        r'url:\s*[\'"]([^\'"]+openapi[^\'"]*)[\'"]',
        r'url:\s*[\'"]([^\'"]+swagger[^\'"]*)[\'"]',
        r'url\s*=\s*[\'"]([^\'"]+openapi[^\'"]*)[\'"]',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)

        if match:
            print(match.group(1))
            break

except Exception:
    pass
PY
            )"

            if [[ -n "$discovered_openapi" ]]; then

                {
                    echo "OpenAPI schema reference found in docs:"
                    echo "  ${discovered_openapi}"
                    echo
                } >> "$CURRENT_AGENT_OUTPUT"

                #
                # Resolve relative OpenAPI URLs.
                #
                if [[ "$discovered_openapi" == /* ]]; then
                    discovered_openapi_url="${base_url}${discovered_openapi}"
                else
                    discovered_openapi_url="${base_url}/${discovered_openapi#./}"
                fi

                discovered_file="${TMP_DIR}/discovered_openapi.json"

                discovered_status="$(
                    curl -sS \
                        -o "$discovered_file" \
                        -w "%{http_code}" \
                        --connect-timeout "$CONNECT_TIMEOUT" \
                        --max-time "$OPENAPI_TIMEOUT" \
                        "$discovered_openapi_url" \
                        2>/dev/null
                )"

                if [[ "$discovered_status" =~ ^2[0-9][0-9]$ ]] &&
                   python3 - "$discovered_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)

    if (
        isinstance(data, dict)
        and "paths" in data
        and ("openapi" in data or "swagger" in data)
    ):
        sys.exit(0)

except Exception:
    pass

sys.exit(1)
PY
                then

                    {
                        echo "OpenAPI schema retrieved from:"
                        echo "  ${discovered_openapi_url}"
                        echo
                        echo "API SURFACE"
                        echo "------------------------------------------------------------------"
                    } >> "$CURRENT_AGENT_OUTPUT"

                    python3 - "$discovered_file" <<'PY' >> "$CURRENT_AGENT_OUTPUT"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

info = data.get("info", {})

if info.get("title"):
    print(f"Title: {info['title']}")

if info.get("version"):
    print(f"Version: {info['version']}")

if info.get("summary"):
    print(f"Summary: {info['summary']}")

if data.get("openapi"):
    print(f"OpenAPI Version: {data['openapi']}")
elif data.get("swagger"):
    print(f"Swagger Version: {data['swagger']}")

print()

paths = data.get("paths", {})

print(f"Documented Paths: {len(paths)}")
print()

methods = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace"
}

for path, path_item in paths.items():

    if not isinstance(path_item, dict):
        continue

    for method, operation in path_item.items():

        if method.lower() not in methods:
            continue

        if not isinstance(operation, dict):
            operation = {}

        print(f"  {method.upper():7} {path}")

        if operation.get("summary"):
            print(f"           Summary: {operation['summary']}")

        if operation.get("description"):
            description = str(operation["description"]).strip()
            description = description.replace("\n", " ")

            if len(description) > 500:
                description = description[:497] + "..."

            print(f"           Description: {description}")

        tags = operation.get("tags", [])

        if tags:
            print(
                "           Tags: " +
                ", ".join(str(x) for x in tags)
            )

        parameters = operation.get("parameters", [])

        if parameters:
            print("           Parameters:")

            for parameter in parameters:

                if not isinstance(parameter, dict):
                    continue

                name = parameter.get("name", "?")
                location = parameter.get("in", "?")
                required = parameter.get("required", False)

                schema = parameter.get("schema", {})

                parameter_type = ""

                if isinstance(schema, dict):
                    parameter_type = (
                        schema.get("type")
                        or schema.get("$ref")
                        or ""
                    )

                extra = ""

                if parameter_type:
                    extra += f", type={parameter_type}"

                if required:
                    extra += ", required"

                print(
                    f"             - {name} "
                    f"(in={location}{extra})"
                )

        request_body = operation.get("requestBody")

        if isinstance(request_body, dict):

            content = request_body.get("content", {})

            if content:
                print("           Request Body:")

                for content_type, content_spec in content.items():

                    schema_name = ""

                    if isinstance(content_spec, dict):

                        schema = content_spec.get("schema", {})

                        if isinstance(schema, dict):
                            schema_name = (
                                schema.get("$ref")
                                or schema.get("type")
                                or ""
                            )

                    if schema_name:
                        print(
                            f"             - {content_type} "
                            f"(schema={schema_name})"
                        )
                    else:
                        print(f"             - {content_type}")

        security = operation.get("security")

        if security:

            schemes = []

            for requirement in security:

                if isinstance(requirement, dict):
                    schemes.extend(requirement.keys())

            if schemes:
                print(
                    "           Security: " +
                    ", ".join(schemes)
                )

        print()

components = data.get("components", {})

if isinstance(components, dict):

    schemes = components.get("securitySchemes", {})

    if schemes:
        print("Security Schemes:")

        for name, scheme in schemes.items():

            if not isinstance(scheme, dict):
                continue

            details = scheme.get("type", "unknown")

            if scheme.get("scheme"):
                details += f", scheme={scheme['scheme']}"

            if scheme.get("bearerFormat"):
                details += f", format={scheme['bearerFormat']}"

            print(f"  - {name}: {details}")

        print()
PY

                    echo >> "$CURRENT_AGENT_OUTPUT"

                    OPENAPI_FOUND="true"
                fi
            fi
        fi
    fi

    #
    # If neither endpoint exposed an OpenAPI schema, still document
    # whether /docs was found.
    #

    if [[ "$OPENAPI_FOUND" != "true" && "$DOCS_FOUND" != "true" ]]; then
        {
            echo "API DOCUMENTATION"
            echo "------------------------------------------------------------------"
            echo "No accessible /openapi.json or /docs endpoint found."
            echo
        } >> "$CURRENT_AGENT_OUTPUT"
    fi
}

#
# --------------------------------------------------------------------
# Function: fuzz_agent
# --------------------------------------------------------------------
#

fuzz_agent() {
    local ip="$1"
    local port="$2"

    local base_url="http://${ip}:${port}"
    local word
    local path
    local url
    local status
    local content_type
    local tmp_headers

    tmp_headers="${TMP_DIR}/headers_${ip//./_}_${port}.tmp"

    while IFS= read -r word || [[ -n "$word" ]]; do

        [[ -z "$word" ]] && continue
        [[ "$word" =~ ^[[:space:]]*# ]] && continue

        word="${word//$'\r'/}"
        word="$(printf '%s' "$word" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        [[ -z "$word" ]] && continue

        path="/${word#/}"

        # Don't accidentally treat a full URL as a path.
        if [[ "$path" =~ ^// ]]; then
            continue
        fi

        url="${base_url}${path}"

        status="$(
            curl -sS \
                -o /dev/null \
                -D "$tmp_headers" \
                -w "%{http_code}" \
                --connect-timeout "$CONNECT_TIMEOUT" \
                --max-time "$FUZZ_TIMEOUT" \
                --max-redirs 0 \
                "$url" \
                2>/dev/null
        )"

        [[ -z "$status" ]] && status="000"

        case "$status" in

            2[0-9][0-9])

                content_type="$(
                    awk -F': ' '
                        BEGIN { IGNORECASE=1 }
                        /^Content-Type:/ {
                            gsub("\r", "", $2)
                            print $2
                            exit
                        }
                    ' "$tmp_headers"
                )"

                {
                    echo "  [+] ${path}"
                    echo "      Status: ${status}"

                    [[ -n "$content_type" ]] &&
                        echo "      Content-Type: ${content_type}"

                    echo "      URL: ${url}"
                } >> "${CURRENT_AGENT_OUTPUT}"

                ;;

            401|403)

                {
                    echo "  [+] ${path}"
                    echo "      Status: ${status}"
                    echo "      Capability likely exists but requires authorization"
                    echo "      URL: ${url}"
                } >> "${CURRENT_AGENT_OUTPUT}"

                ;;

            3[0-9][0-9])

                {
                    echo "  [?] ${path}"
                    echo "      Status: ${status}"
                    echo "      Redirect returned; endpoint may exist"
                    echo "      URL: ${url}"
                } >> "${CURRENT_AGENT_OUTPUT}"

                ;;

            404)
                ;;

            000)
                ;;

            *)

                {
                    echo "  [?] ${path}"
                    echo "      Status: ${status}"
                    echo "      Unusual response; investigate manually"
                    echo "      URL: ${url}"
                } >> "${CURRENT_AGENT_OUTPUT}"

                ;;
        esac

    done < "$WORDLIST"
}

#
# --------------------------------------------------------------------
# Parse Nmap output
# --------------------------------------------------------------------
#

while IFS= read -r line; do

    #
    # Handle:
    #
    #   Nmap scan report for 192.168.54.21
    #
    # and:
    #
    #   Nmap scan report for hostname (192.168.54.21)
    #
    if [[ "$line" =~ ^Nmap\ scan\ report\ for\ .*\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)$ ]]; then

        current_ip="${BASH_REMATCH[1]}"

    elif [[ "$line" =~ ^Nmap\ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then

        current_ip="${BASH_REMATCH[1]}"
    fi

    #
    # Find open TCP ports.
    #
    if [[ "$line" =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]] ]]; then

        port="${BASH_REMATCH[1]}"

        if [[ -z "$current_ip" ]]; then
            continue
        fi

        base_url="http://${current_ip}:${port}"
        health_url="${base_url}/health"
        chat_url="${base_url}/chat"

        echo "Scanning ${current_ip}:${port}..."

        CURRENT_AGENT_OUTPUT="${TMP_DIR}/agent_${current_ip//./_}_${port}.tmp"
        : > "$CURRENT_AGENT_OUTPUT"

        #
        # ------------------------------------------------------------
        # /health
        # ------------------------------------------------------------
        #

        health_response="$(
            curl -sS \
                --connect-timeout "$CONNECT_TIMEOUT" \
                --max-time "$HEALTH_TIMEOUT" \
                "$health_url" \
                2>/dev/null
        )"

        if health_pretty="$(
            printf '%s' "$health_response" |
                python3 -m json.tool 2>/dev/null
        ); then
            :
        else
            health_pretty="$health_response"
        fi

        #
        # Extract agent name.
        #
        agent_name="$(
            printf '%s' "$health_response" |
                python3 -c '
import json
import sys

try:
    data = json.load(sys.stdin)

    name = None

    if isinstance(data, dict):

        for key in ("name", "agent_name", "agentName"):
            if data.get(key):
                name = data[key]
                break

        if not name and isinstance(data.get("agent"), dict):
            agent = data["agent"]

            for key in ("name", "agent_name", "agentName"):
                if agent.get(key):
                    name = agent[key]
                    break

    print(name if name else "Unknown")

except Exception:
    print("Unknown")
'
        )"

        #
        # ------------------------------------------------------------
        # /chat
        # ------------------------------------------------------------
        #
        chat_response=""
        chat_response="$(
            curl -sS \
                --connect-timeout "$CONNECT_TIMEOUT" \
                --max-time "$CHAT_TIMEOUT" \
                -X POST \
                "$chat_url" \
                -H "Content-Type: application/json" \
                -d '{"message":"Hi, what do you do?"}' \
                2>/dev/null
        )"

        if chat_pretty="$(
            printf '%s' "$chat_response" |
                python3 -m json.tool 2>/dev/null
        ); then
            :
        else
            chat_pretty="$chat_response"
        fi

        #
        # ------------------------------------------------------------
        # Main agent information
        # ------------------------------------------------------------
        #

        {
            echo "======================================================================"
            echo "IP:           ${current_ip}"
            echo "Port:         ${port}"
            echo "Agent Name:   ${agent_name}"
            echo "======================================================================"
            echo

            echo "HEALTH: ${health_url}"
            echo "------------------------------------------------------------------"

            if [[ -n "$health_pretty" ]]; then
                printf '%s\n' "$health_pretty"
            else
                echo "[No response / connection failed]"
            fi

            echo

            echo "CHAT: ${chat_url}"
            echo "Question: Hi, what do you do?"
            echo "------------------------------------------------------------------"

            if [[ -n "$chat_pretty" ]]; then
                printf '%s\n' "$chat_pretty"
            else
                echo "[No response / connection failed]"
            fi

            echo
        } >> "$OUTPUT_FILE"

        #
        # ------------------------------------------------------------
        # OpenAPI / documentation discovery
        # ------------------------------------------------------------
        #

        discover_openapi "$base_url"

        #
        # ------------------------------------------------------------
        # Additional API fuzzing
        # ------------------------------------------------------------
        #

        {
            echo "ADDITIONAL CAPABILITIES"
            echo "------------------------------------------------------------------"
            echo "Fuzzing wordlist: ${WORDLIST}"
            echo
        } >> "$CURRENT_AGENT_OUTPUT"

        fuzz_agent "$current_ip" "$port"

        #
        # Append everything discovered for this agent.
        #
        cat "$CURRENT_AGENT_OUTPUT" >> "$OUTPUT_FILE"

        #
        # If fuzzing didn't find anything, add a clear message.
        #
        if ! grep -qE '^  \[\+\?\]' "$CURRENT_AGENT_OUTPUT" 2>/dev/null; then
            :
        fi

        {
            echo
            echo
        } >> "$OUTPUT_FILE"

    fi

done < "$NMAP_OUT"

echo
echo "Scan complete."
echo "Results written to: $OUTPUT_FILE"
