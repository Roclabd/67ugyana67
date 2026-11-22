#!/usr/bin/env python3
"""Generate deterministic, static SECRET and SCA fixtures."""

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
from textwrap import dedent

from gradle_variants import (
    BUILD, buildsrc_versions, catalog_versions, convention_versions, extra_versions,
    gradle_configurations, named_coordinates, platform_lock, property_versions, val_versions,
)
from secret_variants import (
    catalog_secrets,
    compose_secrets,
    credential_url,
    encoded_secret,
    pem_private_key,
    xml_secret,
    gradle_property_secrets,
    kotlin_companion_secrets,
    kotlin_object_secrets,
    kotlin_value_secrets,
    properties_secrets,
    test_env_secrets,
)


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
TRAINING = FIXTURES / "training"
ADVISORIES = TRAINING / "vulnerability-database" / "vulnerabilities.json"


def numeric_version(version: str) -> tuple[int, ...]:
    components = [int(component) for component in version.split(".")]
    while components and components[-1] == 0:
        components.pop()
    return tuple(components)


def in_range(version: tuple[int, ...], interval: dict) -> bool:
    if interval["lower"] is not None:
        lower = numeric_version(interval["lower"])
        if version < lower or (version == lower and not interval["lowerInclusive"]):
            return False
    upper = numeric_version(interval["upper"])
    return version < upper or (version == upper and interval["upperInclusive"])


@dataclass
class Variant:
    name: str
    advisories: list[dict]
    files: dict[str, str] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    controls: list[dict] = field(default_factory=list)
    coverage_status: str = "COMPLETE"
    attention: list[dict] = field(default_factory=list)

    def add_file(self, path: str, content: str) -> None:
        self.files[path] = dedent(content).strip("\n") + "\n"

    def line_of(self, path: str, anchor: str) -> int:
        lines = [index for index, line in enumerate(self.files[path].splitlines(), 1)
                 if anchor in line]
        if len(lines) != 1:
            raise ValueError(f"{self.name}/{path}: expected one line containing {anchor!r}")
        return lines[0]

    def secret(self, name: str, kind: str, path: str, anchor: str, *,
               end: str | None = None, control: bool = False) -> None:
        line = self.line_of(path, anchor)
        end_line = self.line_of(path, end) if end is not None else line
        rows = self.controls if control else self.findings
        rows.append({"id": name, "category": "SECRET", "class": kind, "path": path,
                     "line": line, "endLine": end_line})

    def dependency(self, name: str, coordinate: str, anchor: str, *,
                   control: bool = False, qualified: bool = False, path: str = BUILD) -> None:
        group, artifact, version = coordinate.split(":")
        line = self.line_of(path, anchor)
        records = [entry for entry in self.advisories
                   if (entry["group"], entry["artifact"]) == (group, artifact)]
        if not records:
            raise ValueError(f"{self.name}: missing advisories for {group}:{artifact}")
        numeric = None if qualified else numeric_version(version)
        affected = [entry for entry in records if numeric is not None and
                    any(in_range(numeric, interval) for interval in entry["ranges"])]
        if control == bool(affected):
            raise ValueError(f"{self.name}: advisory ranges contradict the case for {coordinate}")

        base = {"id": name, "category": "SCA", "class": "known-vulnerable-dependency",
                "path": path, "line": line, "endLine": line,
                "group": group, "artifact": artifact, "version": version}
        if control:
            advisory_ids = sorted({value for entry in records
                                   for value in [entry["id"], *entry["aliases"]]})
            self.controls.append({**base, "advisoryIds": advisory_ids})
        else:
            for entry in sorted(affected, key=lambda item: item["id"]):
                self.findings.append({**base, "id": f"{name}-{entry['id']}",
                                      "advisoryIds": [entry["id"], *entry["aliases"]]})

    def contents(self) -> dict[Path, bytes]:
        files = {Path(self.name, "project", path): source.encode("utf-8")
                 for path, source in self.files.items()}
        truth = {"dataset": self.name, "formatVersion": 1, "coverageStatus": self.coverage_status,
                 "findings": self.findings, "controls": self.controls}
        if self.attention:
            truth["attention"] = self.attention
        files[Path(self.name, "truth.json")] = (
            json.dumps(truth, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        return files


def yaml_extra(variant: Variant) -> Variant:
    config = "src/main/resources/application-meter.yml"
    variant.add_file(config, """
        meter:
          display-name: sample
          distributor:
            api-key: 'fixture-meter-qm57-n8dr'
            password: '${METER_PASSWORD}'
    """)
    variant.secret("meter-api-key", "api-key", config, "api-key:")
    variant.secret("meter-env-reference", "password", config, "password:", control=True)

    source = "src/main/kotlin/lab/meter/ImportDefaults.kt"
    variant.add_file(source, """
        package lab.meter

        internal const val archivePassword = "fixture-meter-pw67-n4ct"
    """)
    variant.secret("archive-password", "password", source, "archivePassword")

    variant.add_file(BUILD, """
        extra["codecRelease"] = "2.8.8"
        val codecRelease = extra["codecRelease"] as String

        dependencies {
            implementation("com.google.code.gson:gson:$codecRelease")
            implementation("org.apache.commons:commons-text:1.10.0")
        }
    """)
    variant.dependency("codec-extra", "com.google.code.gson:gson:2.8.8", "gson:$codecRelease")
    variant.dependency("text-fixed-boundary", "org.apache.commons:commons-text:1.10.0",
                       "commons-text:", control=True)
    return variant


def properties_catalog(variant: Variant) -> Variant:
    config = "src/main/resources/application-index.properties"
    variant.add_file(config, """
        index.channel = sample
        index.archive.password = ${INDEX_PASSWORD:fixture-index-7qk3-9trx}
        index.archive.api-key = <set-at-runtime>
    """)
    variant.secret("index-literal-fallback", "secret-fallback", config, "archive.password")
    variant.secret("index-placeholder", "api-key", config, "archive.api-key", control=True)

    source = "src/main/kotlin/lab/index/LabelDefaults.kt"
    variant.add_file(source, """
        package lab.index

        private const val first = "fixture-"
        private const val second = "index-"
        private const val third = "v63x-j9qs"

        internal const val labelToken =
            first + second + third
    """)
    variant.secret("label-joined-token", "configuration-token", source,
                   "labelToken", end="first + second + third")

    variant.add_file("gradle/libs.versions.toml", """
        [versions]
        index-io = "2.6"
        text-processing = "3.18.0"

        [libraries]
        index-io = { module = "commons-io:commons-io", version.ref = "index-io" }
        text-processing = { module = "org.apache.commons:commons-lang3", version.ref = "text-processing" }
    """)
    variant.add_file(BUILD, """
        dependencies {
            implementation(libs.index.io)
            implementation(libs.text.processing)
        }
    """)
    variant.dependency("io-catalog", "commons-io:commons-io:2.6", "libs.index.io")
    variant.dependency("lang-fixed-boundary", "org.apache.commons:commons-lang3:3.18.0",
                       "libs.text.processing", control=True)
    return variant


def dotenv_gradle_property(variant: Variant) -> Variant:
    variant.coverage_status = "PARTIAL"
    config = "config/.env"
    variant.add_file(config, """
        PANEL_CHANNEL=sample
        PANEL_ACCESS_TOKEN="fixture-panel-jr53-p2k8"
        PANEL_PASSWORD=${PANEL_PASSWORD:-fixture-panel-wz89-v3x7}
        PANEL_API_KEY=${PANEL_API_KEY}
    """)
    variant.secret("panel-access-token", "configuration-token", config, "PANEL_ACCESS_TOKEN=")
    variant.secret("panel-literal-fallback", "secret-fallback", config, "PANEL_PASSWORD=")
    variant.secret("panel-env-reference", "api-key", config, "PANEL_API_KEY=", control=True)

    source = "src/test/kotlin/lab/panel/SampleDefaults.kt"
    variant.add_file(source, """
        package lab.panel

        internal const val samplePassword = "fixture-panel-test-rm64"
    """)
    variant.secret("panel-test-scope", "password", source, "samplePassword")

    variant.add_file("gradle.properties", "yamlRelease = 1.31")
    variant.add_file(BUILD, """
        val format = findProperty("yamlRelease") as String

        dependencies {
            add("implementation", "org.yaml:snakeyaml:$format:tests@jar")
            implementation("com.google.code.gson:gson:2.8.9-RC1")
        }
    """)
    variant.dependency("yaml-property-classifier", "org.yaml:snakeyaml:1.31", "snakeyaml:$format")
    variant.dependency("codec-version-qualifier", "com.google.code.gson:gson:2.8.9-RC1",
                       "gson:2.8.9-RC1", control=True, qualified=True)
    return variant


VARIANTS = {
    "c7-yaml-extra": yaml_extra,
    "c7-properties-catalog": properties_catalog,
    "c7-dotenv-gradle-property": dotenv_gradle_property,
    "c7-secret-properties": properties_secrets,
    "c7-secret-gradle-properties": gradle_property_secrets,
    "c7-secret-compose": compose_secrets,
    "c7-secret-catalog": catalog_secrets,
    "c7-secret-kotlin-object": kotlin_object_secrets,
    "c7-secret-kotlin-companion": kotlin_companion_secrets,
    "c7-secret-kotlin-value": kotlin_value_secrets,
    "c7-secret-test-env": test_env_secrets,
    "c7-sca-gradle-extra": extra_versions,
    "c7-sca-gradle-catalog": catalog_versions,
    "c7-sca-gradle-val": val_versions,
    "c7-sca-gradle-properties": property_versions,
    "c7-secret-credential-url": credential_url,
    "c7-secret-pem": pem_private_key,
    "c7-secret-base64": encoded_secret,
    "c7-secret-xml": xml_secret,
    "c7-sca-named-coordinates": named_coordinates,
    "c7-sca-configurations": gradle_configurations,
    "c7-sca-buildsrc": buildsrc_versions,
    "c7-sca-convention": convention_versions,
    "c7-sca-platform-lock": platform_lock,
}


def write_fixtures(output: Path, variants: list[Variant]) -> None:
    if output.is_relative_to(TRAINING.resolve()):
        raise ValueError("output cannot be inside fixtures/training")
    pending = []
    for variant in variants:
        for relative, data in variant.contents().items():
            target = output / relative
            if target.resolve() != target:
                raise ValueError(f"refusing to follow redirected fixture path: {target}")
            if target.exists():
                if not target.is_file() or target.read_bytes() != data:
                    raise ValueError(f"refusing to overwrite existing path: {target}")
            else:
                pending.append((target, data))

    for target, data in pending:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=FIXTURES / "variants",
                        help="directory for generated variants (default: fixtures/variants)")
    parser.add_argument("--variant", choices=VARIANTS, help="generate only this variant")
    args = parser.parse_args()

    try:
        advisories = json.loads(ADVISORIES.read_text(encoding="utf-8"))["vulnerabilities"]
        names = [args.variant] if args.variant else VARIANTS
        variants = [VARIANTS[name](Variant(name, advisories)) for name in names]
        write_fixtures(args.output.resolve(), variants)
    except (OSError, ValueError) as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 2

    for variant in variants:
        print(variant.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
